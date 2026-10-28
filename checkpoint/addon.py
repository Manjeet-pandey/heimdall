"""mitmproxy entrypoint. Request bodies buffered, responses stream (SSE keeps working)."""

from checkpoint.rules import (
    check_destination,
    check_keys,
    check_provider_fetch,
    check_endpoint,
    count_egress,
)
from checkpoint.db import connect, log

try:
    from reviewer.muse import review_unknown
except Exception:  # unit tests without reviewer deps

    def review_unknown(agent, method, host, path, body):
        return ("escalate", "reviewer unavailable")


DB = connect()


def _block(flow, agent, host, path, nbytes, reason, who):
    from mitmproxy.http import Response

    flow.response = Response.make(403, reason.encode(), {"Content-Type": "text/plain"})
    log(DB, agent, flow.request.method, host, path, nbytes, "block", reason, who)


def request(flow):
    agent = flow.metadata.get("agent", "unknown")
    host = flow.request.host or ""
    method = flow.request.method
    path = flow.request.path or "/"
    body = flow.request.raw_content or b""
    nbytes = len(flow.request.pretty_url.encode()) + len(body)

    reason = check_destination(agent, host)
    if reason:
        return _block(flow, agent, host, path, 0, reason, "hard-rule:dest")
    headers = dict(flow.request.headers.items())
    for fn, who in [
        (
            lambda: check_keys(agent, host, headers, flow.request.pretty_url, body),
            "hard-rule:keys",
        ),
        (lambda: check_provider_fetch(agent, host, body), "hard-rule:provider-fetch"),
        (
            lambda: check_endpoint(agent, method, host, path.split("?")[0], len(body)),
            "hard-rule:endpoint",
        ),
        (lambda: count_egress(agent, host, nbytes), "hard-rule:budget"),
    ]:
        reason = fn()
        if reason:
            return _block(flow, agent, host, path, nbytes, reason, who)
    # Unknown move: reviewer can deny/escalate, never allow past a hard rule.
    verdict, rreason = review_unknown(agent, method, host, path.split("?")[0], body)
    if verdict in ("deny", "escalate"):
        return _block(
            flow, agent, host, path, nbytes, f"{verdict}: {rreason}", "muse-reviewer"
        )
    log(
        DB,
        agent,
        method,
        host,
        path,
        nbytes,
        "allow-with-budget",
        rreason,
        "muse-reviewer",
    )
