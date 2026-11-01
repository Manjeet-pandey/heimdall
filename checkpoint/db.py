"""SQLite log (stdlib only). Stores placeholders, never real keys."""

import os
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS moves(
  id INTEGER PRIMARY KEY, ts REAL, agent TEXT, method TEXT, host TEXT,
  path TEXT, query TEXT DEFAULT '', body TEXT DEFAULT '', headers TEXT DEFAULT '',
  bytes_out INTEGER, verdict TEXT, reason TEXT, reviewer TEXT
);
-- Moves Muse (or strict mode) escalated to the human. req_sha pins the exact request: an approval
-- lets that request through once, not anything else sent to the same path.
CREATE TABLE IF NOT EXISTS escalations(
  id INTEGER PRIMARY KEY, ts REAL, agent TEXT, method TEXT, host TEXT, path TEXT,
  req_sha TEXT, reason TEXT, used INTEGER DEFAULT 0
);
"""


def connect(path: str = "checkpoint.db") -> sqlite3.Connection:
    # No WAL: data/ is a host folder shared into containers, where WAL's shared-memory file is unsafe
    # (the checkpoint died with SIGBUS under load). Rollback journal + a wait on locks instead (~1.6 ms/commit).
    c = sqlite3.connect(path, timeout=10)
    c.execute("PRAGMA journal_mode=DELETE")  # also converts a DB left in WAL mode by an earlier run
    c.executescript(SCHEMA)
    cols = {r[1] for r in c.execute("PRAGMA table_info(moves)")}
    for col in ("query", "body", "headers"):  # older logs predate these: widen in place, default empty
        if col not in cols:
            try:
                c.execute(f"ALTER TABLE moves ADD COLUMN {col} TEXT DEFAULT ''")
            except sqlite3.OperationalError as e:
                # Read-only checkout (bad perms): run without the new columns instead of refusing to start.
                # The review page falls back to the old column set; fix perms and restart to get full logging.
                print(f"heimdall: cannot migrate {path} ({e}); continuing without {col}", flush=True)
                break
    c.commit()
    return c


def log(
    c: sqlite3.Connection,
    agent: str,
    method: str,
    host: str,
    path: str,
    query: str,
    body: str,
    headers: str,
    bytes_out: int,
    verdict: str,
    reason: str,
    reviewer: str,
) -> None:
    c.execute(
        "INSERT INTO moves(ts,agent,method,host,path,query,body,headers,bytes_out,verdict,reason,reviewer)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (time.time(), agent, method, host, path, query, body, headers, bytes_out, verdict, reason, reviewer),
    )
    c.commit()


def recent(c: sqlite3.Connection, agent: str, n: int = 30) -> list[dict]:
    """Last n moves of an agent, oldest first: the history Muse reviews a write against."""
    cur = c.cursor()
    cur.row_factory = sqlite3.Row  # on the cursor: the shared connection keeps returning tuples
    rows = cur.execute(
        "SELECT method, host, path, bytes_out, verdict FROM moves WHERE agent = ? ORDER BY id DESC LIMIT ?", (agent, n)
    ).fetchall()
    return [dict(r) for r in reversed(rows)]


def flagged_today(c: sqlite3.Connection) -> set[str]:
    """Agents PromptGuard flagged today. Strict mode survives a checkpoint restart, resets at midnight."""
    today = time.mktime(time.localtime()[:3] + (0, 0, 0, 0, 0, -1))
    return {a for (a,) in c.execute("SELECT DISTINCT agent FROM moves WHERE verdict = 'flag' AND ts >= ?", (today,))}


def escalate(c: sqlite3.Connection, agent, method, host, path, req_sha, reason) -> int:
    cur = c.execute(
        "INSERT INTO escalations(ts,agent,method,host,path,req_sha,reason) VALUES(?,?,?,?,?,?,?)",
        (time.time(), agent, method, host, path, req_sha, reason),
    )
    c.commit()
    return cur.lastrowid


def open_escalation(c: sqlite3.Connection, agent: str, req_sha: str) -> int | None:
    """Latest not-yet-used escalation of this exact request, if any."""
    row = c.execute(
        "SELECT id FROM escalations WHERE agent = ? AND req_sha = ? AND used = 0 ORDER BY id DESC LIMIT 1",
        (agent, req_sha),
    ).fetchone()
    return row[0] if row else None


def mark_used(c: sqlite3.Connection, esc_id: int) -> None:
    c.execute("UPDATE escalations SET used = 1 WHERE id = ?", (esc_id,))
    c.commit()


def human_decision(path: str, esc_id: int) -> str | None:
    """'allow' / 'deny' from the review page's decisions.db (its only writer), None while pending.
    Separate file so each SQLite file has exactly one writer across containers."""
    if not os.path.exists(path):
        return None
    c = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2)
    try:
        row = c.execute("SELECT decision FROM decisions WHERE esc_id = ?", (esc_id,)).fetchone()
    except sqlite3.OperationalError:
        return None  # review page hasn't created the table yet
    finally:
        c.close()
    return row[0] if row else None
