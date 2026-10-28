"""Muse Spark reviewer. Deny/escalate only — never overrides a hard rule.
Caller order: hard rules (dest, keys, provider-fetch, endpoint, budget) first.
Only unknown moves reach here. Verdicts: deny | escalate | allow-with-budget.
"""

import os
import re

CACHE: dict[
    tuple[str, str], tuple[str, str]
] = {}  # (method, path_template) -> (verdict, reason), body-less only
MAX_QUOTED = 2000
REDACT_RE = re.compile(
    r"(gw_ph_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]{4,}|ghp_[A-Za-z0-9_]{4,}|xox[bap]-[A-Za-z0-9-]{4,}|Bearer\s+[A-Za-z0-9._~-]{8,})"
)


def quote_redacted(text: str, limit: int = MAX_QUOTED) -> str:
    t = text[:limit]
    return REDACT_RE.sub("[REDACTED]", t)


def path_template(path: str) -> str:
    # /repos/me/foo -> /repos/me/* ; keep it conservative for cache keying.
    parts = path.split("?")
    p = parts[0]
    p = re.sub(r"/[^/]{1,64}$", "/*", p) if p.count("/") >= 3 else p
    return p or "/"


def review_unknown(
    agent: str, method: str, host: str, path: str, body: bytes
) -> tuple[str, str]:
    """Stub heuristic + real-API hook. Real call only if META_MODEL_API_KEY set; else deterministic stub."""
    key = (method, path_template(path))
    if not body and key in CACHE:
        return CACHE[key]
    quoted = quote_redacted(
        f"{method} {host}{path}\n{body[:MAX_QUOTED].decode('utf-8', 'ignore')}"
    )
    api_key = os.environ.get("META_MODEL_API_KEY", "")
    if not api_key:
        # Offline stub: fail-closed leaning — unknown with body data escalates, empty escalates.
        verdict, reason = (
            "escalate",
            f"unknown move needs human (offline stub): {method} {host}{path_template(path)} | quoted={quoted[:120]}",
        )
    else:
        # Real call goes here (Standard tier). Keep quoted/truncated/redacted input. Timeout short; on error escalate.
        verdict, reason = (
            "escalate",
            f"reviewer unavailable, escalate: {method} {host}{path_template(path)}",
        )
    if not body:
        CACHE[key] = (verdict, reason)
    return verdict, reason


def review_history(agent: str, task: str, moves: list[dict]) -> tuple[str, str]:
    """Slow-leak review inside caps: flags steady exfil-shaped growth the per-request rules allow."""
    total = sum(m.get("bytes_out", 0) for m in moves)
    dests = {m.get("host", "") for m in moves}
    if total > 50000 and len(dests) > 3:
        return (
            "deny",
            f"slow-leak pattern: {total}B across {len(dests)} dests for task={quote_redacted(task, 200)}",
        )
    return ("allow-with-budget", f"history ok: {total}B across {len(dests)} dests")
