"""Review page server: write guards, decisions, learn -> lock. Stdlib only. Run: python3 proof/test_review.py"""

import http.client
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer

tmp = tempfile.mkdtemp()
os.environ.update(HEIMDALL_DB=f"{tmp}/checkpoint.db", HEIMDALL_POLICY=f"{tmp}/policy.json", REVIEW_RUNNER="0")
sys.path.insert(0, ".")
sys.path.insert(0, "review")
import app  # noqa: E402
from checkpoint.db import connect, escalate, log  # noqa: E402

fails = []
db = connect(app.DB)
esc = escalate(db, "coder", "GET", "docs.example.org", "/q", "sha1", "unclear purpose")
now = time.time()
for path, b in [("/simple/requests/", 300), ("/simple/flask/", 280), ("/upload/12", 900)]:
    log(db, "coder", "GET" if "simple" in path else "POST", "pypi.org", path, "", "", "", b, "learn", "learning run", "learn-mode")

srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
port = srv.server_address[1]
app.ALLOWED_HOSTS = {f"127.0.0.1:{port}"}
threading.Thread(target=srv.serve_forever, daemon=True).start()


def post(path, body, host=None, header=True, origin=None):
    c = http.client.HTTPConnection("127.0.0.1", port)
    h = {"Content-Type": "application/json", "Host": host or f"127.0.0.1:{port}"}
    if header:
        h["X-Heimdall"] = "1"
    if origin:
        h["Origin"] = origin
    c.request("POST", path, json.dumps(body), h)
    r = c.getresponse()
    return r.status, json.loads(r.read() or b"{}")


def check(name, got, want):
    if got != want:
        fails.append(f"{name}: got {got!r}, want {want!r}")


# Live view never shows proof-baseline (supervisor off) traffic.
log(db, "coder", "POST", "ci-diagnostics.test", "/c", "", "", "", 100, "allow", "supervisor off (proof baseline)", "off")
check("live-hides-baseline", [m["reviewer"] for m in app.moves(0) if m["reviewer"] == "off"], [])
check("summary-agents", app.summary()["agents"]["coder"]["allow_hosts"], ["api.github.com", "api.openai.com"])

# Write guards: another site in the browser, or DNS rebinding to 127.0.0.1, can't act.
check("no-header", post("/api/decide", {"id": esc, "decision": "allow"}, header=False)[0], 403)
check("rebinding-host", post("/api/decide", {"id": esc, "decision": "allow"}, host="evil.example:8000")[0], 403)
check("foreign-origin", post("/api/decide", {"id": esc, "decision": "allow"}, origin="https://evil.example")[0], 403)
def get(path, host=None):
    c = http.client.HTTPConnection("127.0.0.1", port)
    c.request("GET", path, headers={"Host": host or f"127.0.0.1:{port}"})
    r = c.getresponse()
    r.read()
    return r.status


check("get-rebinding-host", get("/api/summary", host="evil.example:8000"), 403)
check("get-bad-after", get("/api/moves?after=abc"), 200)
check("bad-decision", post("/api/decide", {"id": esc, "decision": "maybe"})[0], 400)
check("unknown-escalation", post("/api/decide", {"id": 999, "decision": "allow"})[0], 400)

# Decisions: first answer wins; the queue moves it from waiting to done.
check("waiting-before", [e["id"] for e in app.escalations()["waiting"]], [esc])
check("decide", post("/api/decide", {"id": esc, "decision": "deny"})[0], 200)
post("/api/decide", {"id": esc, "decision": "allow"})
check("first-answer-wins", sqlite3.connect(app.DECISIONS).execute("select decision from decisions").fetchall(), [("deny",)])
check("waiting-after", app.escalations()["waiting"], [])

# Learn -> lock: moves grouped into suggested rules; lock validates and writes the live policy.
check("start-learning", post("/api/learn/start", {"agent": "coder"})[0], 200)
time.sleep(0.01)
log(db, "coder", "GET", "pypi.org", "/simple/numpy/", "", "", "", 310, "learn", "learning run", "learn-mode")
moves = app.learned()["coder"]["moves"]
check("only-since-learn-start", [(m["method"], m["path_re"]) for m in moves], [("GET", r"/simple/numpy/")])
check("path-regex", app.path_regex("/repos/me/proj/issues/12/comments"), r"/repos/me/proj/issues/\d+/comments")
check("lock-rejects-ip", post("/api/lock", {"agent": "coder", "rules": [
    {"method": "GET", "host": "10.0.0.1", "path_re": "/x", "max_bytes": 0}]})[0], 400)
check("lock-rejects-bad-regex", post("/api/lock", {"agent": "coder", "rules": [
    {"method": "GET", "host": "pypi.org", "path_re": "/simple/(", "max_bytes": 0}]})[0], 400)
check("lock", post("/api/lock", {"agent": "coder", "rules": [
    {"method": "GET", "host": "pypi.org", "path_re": r"/simple/[^/]+/", "max_bytes": 0}]})[0], 200)
pol = json.load(open(app.POLICY))["agents"]["coder"]
check("locked", pol["mode"], "locked")
check("rule-added", ["GET", r"pypi\.org", r"/simple/[^/]+/", 0] in pol["path_rules"], True)
check("host-added", "pypi.org" in pol["allow_hosts"], True)
check("runner-off-in-test", post("/api/run", {"job": "proof"})[0], 400)

# Test source: reads the attack test's log, decisions go to its own file.
tdb = connect(app.TEST_DB)
tesc = escalate(tdb, "coder", "POST", "ci-diagnostics.test", "/c", "sha2", "unclear")
log(tdb, "coder", "POST", "ci-diagnostics.test", "/c", "", "", "", 200, "block", "escalate: unclear", "muse-reviewer")
check("test-src-moves", [m["host"] for m in app.moves(0, app.source("test"))], ["ci-diagnostics.test"])
check("test-src-summary", app.summary(app.source("test"))["stopped"], 1)
check("test-src-decide", post("/api/decide", {"id": tesc, "decision": "allow", "src": "test"})[0], 200)
check("test-decision-separate", app.decisions(app.TEST_DB).get(tesc, {}).get("decision"), "allow")

# Slow leak: the last complete group of 4 allowed pieces, in order; a blocked or unfinished group doesn't count.
for part, n, verdict in [("aaa", 1, "allow"), ("bbb", 2, "block"), ("abc", 1, "allow"), ("def", 2, "allow"),
                         ("ghi", 3, "allow"), ("jkl", 4, "allow"), ("zzz", 1, "allow")]:
    log(tdb, "coder", "POST", "api.github.com", f"/repos/me/proj/issues/{4 + n}/comments", "",
        json.dumps({"body": f"Build {part} passed on runner {n}."}), "", 100, verdict, "allow: fine", "muse-history")
check("slow-pieces", [p["piece"] for p in app.slow_pieces()], ["abc", "def", "ghi", "jkl"])

srv.shutdown()
shutil.rmtree(tmp)
print("FAIL" if fails else "ALL PASS", *fails, sep="\n")
sys.exit(1 if fails else 0)
