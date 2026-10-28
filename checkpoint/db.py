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
