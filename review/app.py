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
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from checkpoint.rules import check_destination  # noqa: E402

DB = os.environ.get("HEIMDALL_DB", str(ROOT / "data/checkpoint.db"))
DECISIONS = os.path.splitext(DB)[0] + ".decisions.db"  # same naming as the checkpoint: escalation ids are per DB
# The attack test's log (proof/run.py, attack mode) sits next to the live one; the page can show either.
TEST_DB = os.path.join(os.path.dirname(DB), "attack.db")
POLICY = os.environ.get("HEIMDALL_POLICY", str(ROOT / "data/policy.json"))
POLICY_SEED = ROOT / "checkpoint/policy.json"
PROOF = ROOT / "proof/out"
PAGE = Path(__file__).with_name("index.html")
COLS = "id, ts, agent, method, host, path, query, body, headers, bytes_out, verdict, reason, reviewer"
COLS_OLD = "id, ts, agent, method, host, path, bytes_out, verdict, reason, reviewer"
_SCHEMA: dict = {}  # db path -> (mtime, cols): old logs predate query/body; read them without those


def _cols(db: str) -> str:
    try:
        mt = os.path.getmtime(db)
    except OSError:
        return COLS_OLD
    if _SCHEMA.get(db, (None,))[0] != mt:
        try:
            c = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2)
            names = {r[1] for r in c.execute("PRAGMA table_info(moves)")}
            c.close()
        except sqlite3.OperationalError:
            names = set()
        _SCHEMA[db] = (mt, COLS if {"query", "body", "headers"} <= names else COLS_OLD)
    return _SCHEMA[db][1]
PORT = int(os.environ.get("REVIEW_PORT", "8000"))
ALLOWED_HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}  # Host header check: DNS rebinding can't reach the API
# Extra names you open the page by, e.g. REVIEW_HOSTS=myhost:8000 behind a reverse proxy. Exact host:port only.
ALLOWED_HOSTS |= {h.strip() for h in os.environ.get("REVIEW_HOSTS", "").split(",") if h.strip()}
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "*"}
# Run buttons: fixed commands only, never anything from the request. Need a container engine -> host only.
RUNNER = (shutil.which("docker") or shutil.which("podman")) is not None and os.environ.get("REVIEW_RUNNER", "1") != "0"
JOBS = {
    "attack": lambda runs: [sys.executable, "proof/run.py", "--attack"],
    "proof": lambda runs: [sys.executable, "proof/run.py", "--runs", str(runs)],
    "rogue": lambda runs: [sys.executable, "proof/rogue.py", "--runs", str(runs)],  # needs llama-server running
    "load": lambda runs: [sys.executable, "proof/load.py", "--rate", "100", "--seconds", "60"],
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

# Proof-baseline traffic (supervisor off) is test data, never shown as live activity.
LIVE = "reviewer != 'off'"


def source(src: str | None) -> str:
    return TEST_DB if src == "test" else DB


def decisions_file(db: str) -> str:
    return os.path.splitext(db)[0] + ".decisions.db"


def moves(after: int, db: str = DB) -> list[dict]:
    cols = _cols(db)
    if after and ((query("select max(id) m from moves", path=db) or [{}])[0].get("m") or 0) < after:
        after = 0  # the log was reset under the page (a new test run numbers from 1 again): send it from the start
    if after:
        rows = query(f"select {cols} from moves where id > ? and {LIVE} order by id limit 300", (after,), db)
    else:  # first load: live shows today only (like its summary); the test shows its whole last run
        since = today() if db == DB else 0
        rows = query(f"select {cols} from moves where ts >= ? and {LIVE} order by id desc limit 300", (since,), db)[::-1]
    for r in rows:
        r.setdefault("query", "")
        r.setdefault("body", "")
        r.setdefault("headers", "")
    return rows


def summary(db: str = DB) -> dict:
    # Live: today only. Test: the whole last run (proof/run.py wipes it first), whenever it happened.
    # While a test is starting, the server still holds the last run's log for a few seconds: count from this run's start.
    t = today() if db == DB else (RUN["started"] or 0) if RUN["proc"] is not None and RUN["proc"].poll() is None else 0
    # The test always runs on the repo's seed policy, so show that one with it.
    policy = load_policy()["agents"] if db == DB else json.loads(POLICY_SEED.read_text())["agents"]
    q = lambda sql, args=(): query(sql, args, db)  # noqa: E731
    used = q("select agent, host, sum(bytes_out) n from moves where ts >= ? and verdict != 'block' "
                 "and reviewer != 'off' group by agent, host", (t,))
    budget = []
    for agent, a in policy.items():
        rows = [u for u in used if u["agent"] == agent]
        for host in sorted(a["allow_hosts"]):
            n = sum(u["n"] for u in rows if u["host"] == host)
            budget.append({"agent": agent, "dest": host, "used": n, "cap": a["budget_day"]})
        n = sum(u["n"] for u in rows if u["host"] not in a["allow_hosts"])
        budget.append({"agent": agent, "dest": None, "used": n, "cap": a.get("unknown_day", 4096)})
    counts = {r["verdict"]: r["n"] for r in q(
        f"select verdict, count(*) n from moves where ts >= ? and {LIVE} group by verdict", (t,))}
    # Per deciding layer and outcome, for the diagram's counters.
    by_reviewer = q(f"select reviewer who, verdict, count(*) n from moves where ts >= ? and {LIVE} "
                        "group by reviewer, verdict", (t,))
    caught = q("select reviewer who, count(*) n from moves where ts >= ? and verdict = 'block' "
                   "group by reviewer order by n desc", (t,))
    last_muse = q("select reason, ts from moves where reviewer in ('muse-reviewer', 'muse-history') "
                      "order by id desc limit 1")
    muse = {"state": "idle"}
    if last_muse:
        ms = re.search(r"\[muse (\d+)ms", last_muse[0]["reason"])
        # Only a real Muse answer carries the "[muse Nms" marker; anything else means Muse didn't answer.
        muse = {"state": "up" if ms else "down", "latency_ms": int(ms.group(1)) if ms else None}
    last = q(f"select max(ts) ts from moves where {LIVE}")
    strict = q("select agent, min(ts) since from moves where verdict = 'flag' and ts >= ? group by agent", (t,))
    return {"budget": budget, "stopped": counts.get("block", 0),
            "passed": sum(counts.get(v, 0) for v in ("allow", "allow-with-budget", "learn")),
            "caught": caught, "muse": muse, "strict": strict, "last_ts": last[0]["ts"] if last else None,
            "waiting": len(escalations(db)["waiting"]), "test_exists": os.path.exists(TEST_DB), "by_reviewer": by_reviewer, "flags": counts.get("flag", 0),
            "agents": {agent: {"mode": a.get("mode", "locked"), "allow_hosts": sorted(a["allow_hosts"])}
                       for agent, a in policy.items()}}


# --- escalations: Muse (or strict mode) asked for a human ---------------------------------------------------

def decisions(db: str = DB) -> dict[int, dict]:
    return {r["esc_id"]: r for r in query("select esc_id, decision, ts from decisions", path=decisions_file(db))}


def escalations(db: str = DB) -> dict:
    d = decisions(db)
    rows = query("select id, ts, agent, method, host, path, reason, used from escalations order by id desc limit 200",
                 path=db)
    waiting = [r for r in rows if r["id"] not in d and not r["used"]]
    done = [{**r, "decision": d[r["id"]]["decision"], "decided": d[r["id"]]["ts"]} for r in rows if r["id"] in d][:30]
    return {"waiting": waiting, "done": done}


def decide(body: dict) -> dict:
    esc_id, decision, db = int(body["id"]), body["decision"], source(body.get("src"))
    if decision not in ("allow", "deny"):
        raise ValueError("decision must be allow or deny")
    if not query("select id from escalations where id = ?", (esc_id,), db):
        raise ValueError(f"no escalation #{esc_id}")
    c = sqlite3.connect(decisions_file(db))
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
    extra = {k: json.loads((PROOF / f"{k}.json").read_text()) if (PROOF / f"{k}.json").exists() else None
             for k in ("load", "rogue")}
    return {"summary": json.loads(f.read_text()) if f.exists() else None, "runner": RUNNER, **extra,
            "slow_pieces": slow_pieces()}


SLOW_RE = re.compile(r"Build (\w+) passed on runner (\d+)\.")


def slow_pieces() -> list[dict]:
    """The last complete slow leak from the load test (proof/load.py): the secret's pieces as they left, in order."""
    if not os.path.exists(TEST_DB):
        return []
    group, last = [], []
    for m in query("select id, ts, path, body, reason, reviewer from moves where verdict != 'block' "
                   "and body like '%passed on runner%' order by id", path=TEST_DB):
        hit = SLOW_RE.search(m["body"] or "")
        if not hit:
            continue
        n = int(hit.group(2))
        group = [] if n == 1 else group
        if n == len(group) + 1:
            group.append({**m, "piece": hit.group(1)})
            if n == 4:
                last = group
    return last


def run_status() -> dict:
    proc = RUN["proc"]
    log = RUN["log"].read_text(errors="replace").splitlines()[-80:] if RUN["log"].exists() and RUN["job"] else []
    return {"runner": RUNNER, "job": RUN["job"], "started": RUN["started"],
            "running": proc is not None and proc.poll() is None,
            "exit": proc.poll() if proc is not None else None, "log": log}


LLAMA_HEALTH = os.environ.get("LLAMA_URL", "http://127.0.0.1:8089/v1/chat/completions").rsplit("/v1/", 1)[0] + "/health"


def rogue_live() -> dict:
    """The newest rogue-agent run, step by step (Llama's thought, its request, what came back), for the page."""
    runs = sorted((PROOF / "rogue").glob("*.jsonl"), key=lambda f: f.stat().st_mtime) if (PROOF / "rogue").exists() else []
    if not runs:
        return {"run": None, "steps": [], "result": None}
    running = RUN["job"] == "rogue" and RUN["proc"] is not None and RUN["proc"].poll() is None
    f = runs[-1]
    if running and f.stat().st_mtime < (RUN["started"] or 0):  # new run still starting its sandbox: don't show the last one
        return {"run": None, "steps": [], "result": None, "running": True}
    steps = [json.loads(line) for line in f.read_text().splitlines() if line.strip()]
    done = PROOF / "rogue.json"
    result = None
    if done.exists():
        result = next((r for r in json.loads(done.read_text()).get("results", []) if r["run"] == f.stem), None)
    return {"run": f.stem, "steps": steps, "result": result, "running": running}


def run(body: dict) -> dict:
    if not RUNNER:
        raise ValueError("Run buttons need docker or podman: start the review page on your machine with python3 review/app.py")
    if RUN["proc"] is not None and RUN["proc"].poll() is None:
        raise ValueError(f"{RUN['job']} is already running")
    job = body["job"]
    if job == "redteam":
        # Live stream: paced attack laps until stopped (Stop button -> SIGTERM -> stack put back).
        pace = float(body.get("pace", 20))
        if not 5 <= pace <= 300:
            raise ValueError("pace must be 5-300 seconds")
        cmd = [sys.executable, "proof/run.py", "--stream", "--pace", str(pace)]
    else:
        if job == "rogue":  # fail here with a clear message, not a minute later in the run log
            try:
                urllib.request.urlopen(LLAMA_HEALTH, timeout=2)
            except OSError:
                raise ValueError("The rogue agent needs Llama: run ./start.sh, or start llama-server on port 8089")
        if job not in JOBS:
            raise ValueError(f"unknown job {job}")
        runs = int(body.get("runs", 1))
        if not 1 <= runs <= 10:
            raise ValueError("runs must be 1-10")
        cmd = JOBS[job](runs)
    PROOF.mkdir(parents=True, exist_ok=True)
    log = open(RUN["log"], "w")
    RUN.update(job=job, started=time.time(),
               proc=subprocess.Popen(cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT))
    return {"ok": True}


def stop(body: dict) -> dict:
    proc = RUN["proc"]
    if proc is not None and proc.poll() is None:
        proc.terminate()  # proof/run.py traps SIGTERM and puts the stack back before exiting
    return {"ok": True}


GETS = {"/api/summary": summary, "/api/escalations": escalations, "/api/learn": lambda db: learned(),
        "/api/proof": lambda db: proof(), "/api/run": lambda db: run_status(), "/api/rogue": lambda db: rogue_live()}
POSTS = {"/api/decide": decide, "/api/learn/start": start_learning, "/api/lock": lock, "/api/run": run,
         "/api/stop": stop}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urlsplit(self.path)
        if u.path == "/":
            return self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
        # The data is redacted but still yours: DNS rebinding must not let another site read it either.
        if u.path.startswith("/api/") and self.headers.get("Host") not in ALLOWED_HOSTS:
            return self._json(403, {"error": "forbidden"})
        qs = parse_qs(u.query)
        db = source(qs.get("src", ["live"])[0])
        if u.path == "/api/moves":
            after = qs.get("after", ["0"])[0]
            return self._json(200, moves(int(after) if after.isdigit() else 0, db))
        if u.path in GETS:
            return self._json(200, GETS[u.path](db))
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
        self.send_header("Cache-Control", "no-store")  # the page and the feed must never be served stale
        # Feed shows attacker-controlled text: page renders it with textContent, and CSP keeps the page same-origin.
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; connect-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    bind = os.environ.get("REVIEW_BIND", "127.0.0.1")
    print(f"review page on http://127.0.0.1:{PORT} (run buttons {'on' if RUNNER else 'off: no container engine here'})", flush=True)
    ThreadingHTTPServer((bind, PORT), Handler).serve_forever()
