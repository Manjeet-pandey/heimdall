"""Review page: live feed, stopped moves with reasons, budget per agent, what caught what, Muse status.
Stdlib only (nothing to install on `docker compose up`). Reads the checkpoint's SQLite read-only.
Run: python3 review/app.py  ->  http://127.0.0.1:8000"""

import json
import os
import re
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

DB = os.environ.get("HEIMDALL_DB", "data/checkpoint.db")
POLICY = os.environ.get("HEIMDALL_POLICY", "checkpoint/policy.json")
PAGE = Path(__file__).with_name("index.html")
COLS = "id, ts, agent, method, host, path, bytes_out, verdict, reason, reviewer"


def query(sql: str, args=()) -> list[dict]:
    try:
        c = sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=2)
    except sqlite3.OperationalError:
        return []  # checkpoint hasn't written anything yet
    c.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in c.execute(sql, args)]
    except sqlite3.OperationalError:
        return []
    finally:
        c.close()


def moves(after: int) -> list[dict]:
    if after:
        return query(f"select {COLS} from moves where id > ? order by id limit 300", (after,))
    return query(f"select {COLS} from moves order by id desc limit 200")[::-1]


def summary() -> dict:
    today = time.mktime(time.localtime()[:3] + (0, 0, 0, 0, 0, -1))
    policy = json.loads(Path(POLICY).read_text())["agents"]
    used = query("select agent, host, sum(bytes_out) n from moves where ts >= ? and verdict != 'block' "
                 "and reviewer != 'off' group by agent, host", (today,))
    budget = []
    for agent, a in policy.items():
        rows = [u for u in used if u["agent"] == agent]
        for host in sorted(a["allow_hosts"]):
            n = sum(u["n"] for u in rows if u["host"] == host)
            budget.append({"agent": agent, "dest": host, "used": n, "cap": a["budget_day"]})
        n = sum(u["n"] for u in rows if u["host"] not in a["allow_hosts"])
        budget.append({"agent": agent, "dest": None, "used": n, "cap": a.get("unknown_day", 4096)})
    counts = {r["verdict"]: r["n"] for r in query(
        "select verdict, count(*) n from moves where ts >= ? group by verdict", (today,))}
    caught = query("select reviewer who, count(*) n from moves where ts >= ? and verdict = 'block' "
                   "group by reviewer order by n desc", (today,))
    last_muse = query("select reason, ts from moves where reviewer = 'muse-reviewer' order by id desc limit 1")
    muse = {"state": "idle"}
    if last_muse:
        r = last_muse[0]["reason"]
        ms = re.search(r"\[muse (\d+)ms", r)
        muse = {"state": "down" if "fail-closed" in r else "up", "latency_ms": int(ms.group(1)) if ms else None,
                "ts": last_muse[0]["ts"]}
    last = query("select max(ts) ts from moves")
    return {"budget": budget, "stopped": counts.get("block", 0), "passed": sum(counts.values()) - counts.get("block", 0),
            "caught": caught, "muse": muse, "last_ts": last[0]["ts"] if last else None}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urlsplit(self.path)
        if u.path == "/":
            return self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
        if u.path == "/api/moves":
            after = int(parse_qs(u.query).get("after", ["0"])[0] or 0)
            return self._send(200, json.dumps(moves(after)).encode(), "application/json")
        if u.path == "/api/summary":
            return self._send(200, json.dumps(summary()).encode(), "application/json")
        return self._send(404, b"not found", "text/plain")

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
    print(f"review page on http://{bind}:8000", flush=True)
    ThreadingHTTPServer((bind, 8000), Handler).serve_forever()
