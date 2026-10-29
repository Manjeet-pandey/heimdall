"""Review page: live feed, escalations waiting for you, learn-then-lock, proof results, run proof / checks.
Stdlib only (nothing to install on `docker compose up`). Reads the checkpoint's SQLite read-only; writes only
its own decisions file and the live policy. Run on the host to get the Run buttons (they need docker):
  python3 review/app.py  ->  http://127.0.0.1:8000"""

import json
import math
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from checkpoint.rules import check_destination  # noqa: E402

DB = os.environ.get("HEIMDALL_DB", str(ROOT / "data/checkpoint.db"))
DECISIONS = os.path.splitext(DB)[0] + ".decisions.db"  # same naming as the checkpoint: escalation ids are per DB
POLICY = os.environ.get("HEIMDALL_POLICY", str(ROOT / "data/policy.json"))
POLICY_SEED = ROOT / "checkpoint/policy.json"
PROOF = ROOT / "proof/out"
PAGE = Path(__file__).with_name("index.html")
COLS = "id, ts, agent, method, host, path, bytes_out, verdict, reason, reviewer"
ALLOWED_HOSTS = {"127.0.0.1:8000", "localhost:8000"}  # Host header check: DNS rebinding can't reach the API
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "*"}
# Run buttons: fixed commands only, never anything from the request. Need docker -> host only.
RUNNER = shutil.which("docker") is not None and os.environ.get("REVIEW_RUNNER", "1") != "0"
JOBS = {
    "proof": lambda runs: [sys.executable, "proof/run.py", "--runs", str(runs)],
    "checks": lambda runs: ["./demo/demo.sh", "--check"],
}
RUN = {"job": None, "proc": None, "started": None, "log": PROOF / "run.log"}


def today() -> float:
    return time.mktime(time.localtime()[:3] + (0, 0, 0, 0, 0, -1))


def query(sql: str, args=(), path: str = DB) -> list[dict]:
    try:
        c = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2)
    except sqlite3.OperationalError:
        return []  # checkpoint hasn't written anything yet
    c.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in c.execute(sql, args)]
    except sqlite3.OperationalError:
        return []
    finally:
        c.close()


def load_policy() -> dict:
    return json.loads(Path(POLICY if os.path.exists(POLICY) else POLICY_SEED).read_text())


def save_policy(p: dict) -> None:
    tmp = f"{POLICY}.tmp"
    with open(tmp, "w") as f:
        json.dump(p, f, indent=2)
    os.replace(tmp, POLICY)  # atomic: the checkpoint never reads half a file


# --- live feed ---------------------------------------------------------------------------------------------

def moves(after: int) -> list[dict]:
    if after:
        return query(f"select {COLS} from moves where id > ? order by id limit 300", (after,))
    return query(f"select {COLS} from moves order by id desc limit 200")[::-1]


def summary() -> dict:
    t = today()
    policy = load_policy()["agents"]
    used = query("select agent, host, sum(bytes_out) n from moves where ts >= ? and verdict != 'block' "
                 "and reviewer != 'off' group by agent, host", (t,))
    budget = []
    for agent, a in policy.items():
        rows = [u for u in used if u["agent"] == agent]
        for host in sorted(a["allow_hosts"]):
            n = sum(u["n"] for u in rows if u["host"] == host)
            budget.append({"agent": agent, "dest": host, "used": n, "cap": a["budget_day"]})
        n = sum(u["n"] for u in rows if u["host"] not in a["allow_hosts"])
        budget.append({"agent": agent, "dest": None, "used": n, "cap": a.get("unknown_day", 4096)})
    counts = {r["verdict"]: r["n"] for r in query(
        "select verdict, count(*) n from moves where ts >= ? group by verdict", (t,))}
    caught = query("select reviewer who, count(*) n from moves where ts >= ? and verdict = 'block' "
                   "group by reviewer order by n desc", (t,))
    last_muse = query("select reason, ts from moves where reviewer in ('muse-reviewer', 'muse-history') "
                      "order by id desc limit 1")
    muse = {"state": "idle"}
    if last_muse:
        ms = re.search(r"\[muse (\d+)ms", last_muse[0]["reason"])
        # Only a real Muse answer carries the "[muse Nms" marker; anything else means Muse didn't answer.
        muse = {"state": "up" if ms else "down", "latency_ms": int(ms.group(1)) if ms else None}
    last = query("select max(ts) ts from moves")
    strict = query("select agent, min(ts) since from moves where verdict = 'flag' and ts >= ? group by agent", (t,))
    return {"budget": budget, "stopped": counts.get("block", 0),
            "passed": sum(counts.get(v, 0) for v in ("allow", "allow-with-budget", "learn")),
            "caught": caught, "muse": muse, "strict": strict, "last_ts": last[0]["ts"] if last else None,
            "waiting": len(escalations()["waiting"]),
            "modes": {agent: a.get("mode", "locked") for agent, a in policy.items()}}


# --- escalations: Muse (or strict mode) asked for a human ---------------------------------------------------

def decisions() -> dict[int, dict]:
    return {r["esc_id"]: r for r in query("select esc_id, decision, ts from decisions", path=DECISIONS)}


def escalations() -> dict:
    d = decisions()
    rows = query("select id, ts, agent, method, host, path, reason, used from escalations order by id desc limit 200")
    waiting = [r for r in rows if r["id"] not in d and not r["used"]]
    done = [{**r, "decision": d[r["id"]]["decision"], "decided": d[r["id"]]["ts"]} for r in rows if r["id"] in d][:30]
    return {"waiting": waiting, "done": done}


def decide(body: dict) -> dict:
    esc_id, decision = int(body["id"]), body["decision"]
    if decision not in ("allow", "deny"):
        raise ValueError("decision must be allow or deny")
    if not query("select id from escalations where id = ?", (esc_id,)):
        raise ValueError(f"no escalation #{esc_id}")
    c = sqlite3.connect(DECISIONS)
    try:
        c.execute("CREATE TABLE IF NOT EXISTS decisions(esc_id INTEGER PRIMARY KEY, decision TEXT, ts REAL)")
        # First answer wins: a decision the checkpoint may already have acted on is never rewritten.
        c.execute("INSERT OR IGNORE INTO decisions VALUES(?,?,?)", (esc_id, decision, time.time()))
        c.commit()
    finally:
        c.close()
    return {"ok": True}


# --- learn, then lock -----------------------------------------------------------------------------------------

def path_regex(path: str) -> str:
    """/repos/me/proj/issues/12/comments -> /repos/me/proj/issues/\\d+/comments. Ids widen, words stay literal."""
    out = []
    for seg in path.split("/"):
        if re.fullmatch(r"\d+", seg):
            out.append(r"\d+")
        elif re.fullmatch(r"[0-9a-fA-F-]{8,}", seg):
            out.append("[^/]+")
        else:
            out.append(re.escape(seg))
    return "/".join(out)


def learned() -> dict:
    policy = load_policy()["agents"]
    out = {}
    for agent, a in policy.items():
        rows = query("select method, host, path, max(bytes_out) b, count(*) n from moves where agent = ? "
                     "and verdict = 'learn' and ts >= ? group by method, host, path", (agent, a.get("learn_since", 0)))
        groups = {}
        for r in rows:
            k = (r["method"], r["host"], path_regex(r["path"]))
            g = groups.setdefault(k, {"method": k[0], "host": k[1], "path_re": k[2], "count": 0, "max_seen": 0,
                                      "example": r["path"]})
            g["count"] += r["n"]
            g["max_seen"] = max(g["max_seen"], r["b"])
        for g in groups.values():
            # bytes_out counts URL + headers + body, so 2x of it is a generous body cap. Reads get 0.
            g["max_bytes"] = 0 if g["method"] in ("GET", "HEAD") else max(1024, math.ceil(2 * g["max_seen"] / 1024) * 1024)
        out[agent] = {"mode": a.get("mode", "locked"), "learn_since": a.get("learn_since"),
                      "moves": sorted(groups.values(), key=lambda g: (g["host"], g["path_re"])),
                      "rules": [{"method": m, "host_re": h, "path_re": p, "max_bytes": b} for m, h, p, b in a["path_rules"]]}
    return out


def start_learning(body: dict) -> dict:
    p = load_policy()
    a = p["agents"][body["agent"]]
    a["mode"], a["learn_since"] = "learn", time.time()
    save_policy(p)
    return {"ok": True}


def lock(body: dict) -> dict:
    p = load_policy()
    a = p["agents"][body["agent"]]
    for r in body.get("rules", []):
        method, host, path_re, max_bytes = r["method"].upper(), r["host"].lower(), r["path_re"], int(r["max_bytes"])
        if method not in METHODS:
            raise ValueError(f"bad method {method}")
        if why := check_destination(host):
            raise ValueError(f"bad host {host}: {why}")
        re.compile(path_re)
        if not path_re.startswith("/") or not 0 <= max_bytes <= 1048576:
            raise ValueError(f"bad rule {path_re} / {max_bytes}")
        rule = [method, re.escape(host), path_re, max_bytes]
        if rule not in a["path_rules"]:
            a["path_rules"].append(rule)
        if host not in a["allow_hosts"]:
            a["allow_hosts"].append(host)
    a["mode"] = "locked"
    a.pop("learn_since", None)
    save_policy(p)
    return {"ok": True}


# --- proof results + runner -------------------------------------------------------------------------------------

def proof() -> dict:
    f = PROOF / "summary.json"
    return {"summary": json.loads(f.read_text()) if f.exists() else None, "runner": RUNNER}


def run_status() -> dict:
    proc = RUN["proc"]
    log = RUN["log"].read_text(errors="replace").splitlines()[-80:] if RUN["log"].exists() and RUN["job"] else []
    return {"runner": RUNNER, "job": RUN["job"], "started": RUN["started"],
            "running": proc is not None and proc.poll() is None,
            "exit": proc.poll() if proc is not None else None, "log": log}


def run(body: dict) -> dict:
    if not RUNNER:
        raise ValueError("Run buttons need docker: start the review page on your machine with python3 review/app.py")
    if RUN["proc"] is not None and RUN["proc"].poll() is None:
        raise ValueError(f"{RUN['job']} is already running")
    job = body["job"]
    if job not in JOBS:
        raise ValueError(f"unknown job {job}")
    runs = int(body.get("runs", 1))
    if not 1 <= runs <= 10:
        raise ValueError("runs must be 1-10")
    PROOF.mkdir(parents=True, exist_ok=True)
    log = open(RUN["log"], "w")
    RUN.update(job=job, started=time.time(),
               proc=subprocess.Popen(JOBS[job](runs), cwd=ROOT, stdout=log, stderr=subprocess.STDOUT))
    return {"ok": True}


GETS = {"/api/summary": summary, "/api/escalations": escalations, "/api/learn": learned, "/api/proof": proof,
        "/api/run": run_status}
POSTS = {"/api/decide": decide, "/api/learn/start": start_learning, "/api/lock": lock, "/api/run": run}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urlsplit(self.path)
        if u.path == "/":
            return self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
        if u.path == "/api/moves":
            return self._json(200, moves(int(parse_qs(u.query).get("after", ["0"])[0] or 0)))
        if u.path in GETS:
            return self._json(200, GETS[u.path]())
        return self._send(404, b"not found", "text/plain")

    def do_POST(self):
        u = urlsplit(self.path)
        # CSRF / DNS rebinding: only our own page on localhost. A custom header forces a CORS preflight we never
        # answer, so another site in the browser can't POST here; the Host check stops rebinding to 127.0.0.1.
        origin = self.headers.get("Origin")
        if (self.headers.get("Host") not in ALLOWED_HOSTS or self.headers.get("X-Heimdall") != "1"
                or (origin and urlsplit(origin).netloc not in ALLOWED_HOSTS)):
            return self._json(403, {"error": "forbidden"})
        if u.path not in POSTS:
            return self._send(404, b"not found", "text/plain")
        try:
            body = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 65536)) or b"{}")
            return self._json(200, POSTS[u.path](body))
        except (ValueError, KeyError, TypeError, OSError, re.error) as e:
            return self._json(400, {"error": str(e)})

    def _json(self, code, obj):
        return self._send(code, json.dumps(obj).encode(), "application/json")

    def _send(self, code, data, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        # Feed shows attacker-controlled text: page renders it with textContent, and CSP keeps the page same-origin.
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; connect-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    bind = os.environ.get("REVIEW_BIND", "127.0.0.1")
    print(f"review page on http://127.0.0.1:8000 (run buttons {'on' if RUNNER else 'off: no docker here'})", flush=True)
    ThreadingHTTPServer((bind, 8000), Handler).serve_forever()
