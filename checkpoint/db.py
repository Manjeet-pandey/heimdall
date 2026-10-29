"""SQLite log (stdlib only). Stores placeholders, never real keys."""

import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS moves(
  id INTEGER PRIMARY KEY, ts REAL, agent TEXT, method TEXT, host TEXT,
  path TEXT, bytes_out INTEGER, verdict TEXT, reason TEXT, reviewer TEXT
);
"""


def connect(path: str = "checkpoint.db") -> sqlite3.Connection:
    c = sqlite3.connect(path)
    c.executescript(SCHEMA)
    return c


def log(
    c: sqlite3.Connection,
    agent: str,
    method: str,
    host: str,
    path: str,
    bytes_out: int,
    verdict: str,
    reason: str,
    reviewer: str,
) -> None:
    c.execute(
        "INSERT INTO moves(ts,agent,method,host,path,bytes_out,verdict,reason,reviewer) VALUES(?,?,?,?,?,?,?,?,?)",
        (time.time(), agent, method, host, path, bytes_out, verdict, reason, reviewer),
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
