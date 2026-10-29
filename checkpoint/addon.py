"""mitmproxy entrypoint. Request bodies buffered, LLM responses stream (SSE keeps working).
Every hook fails closed: an exception in a mitmproxy addon otherwise lets the flow through unchecked.
Run with --set connection_strategy=lazy so nothing connects (or resolves) before request() decides."""

import asyncio
import os
import shutil
import socket
from pathlib import Path

from mitmproxy import ctx, http

from checkpoint import rules as R
from checkpoint.creds import swap_placeholders
from checkpoint.db import connect, log
from reviewer.muse import quote_redacted, review_unknown

R.load_policy(os.environ.get("HEIMDALL_POLICY", Path(__file__).with_name("policy.json")))
DB = connect(os.environ.get("HEIMDALL_DB", "checkpoint.db"))
# Attack/proof runs: every upstream connection goes to the mock server, never the internet.
MOCK = os.environ.get("HEIMDALL_MOCK_UPSTREAM")  # "mock:8000"
# Proof baseline ("no supervisor"): forward everything unchecked. Refuses to run outside mock mode.
SUPERVISOR_OFF = os.environ.get("HEIMDALL_SUPERVISOR") == "off"
if SUPERVISOR_OFF and not MOCK:
    raise SystemExit("HEIMDALL_SUPERVISOR=off requires HEIMDALL_MOCK_UPSTREAM")


def _agent(flow) -> str | None:
    # Set by mitmproxy's proxyauth addon: agent = proxy username.
    auth = flow.metadata.get("proxyauth")
    return auth[0] if auth else None


def _log(flow, agent, nbytes, verdict, reason, who):
    # Query strings dropped and everything redacted: a foreign key in a blocked request must not land in the log.
    r = flow.request
    path = quote_redacted(r.path.split("?", 1)[0], 512)
    log(DB, agent or "?", r.method, quote_redacted(r.host, 253), path, nbytes, verdict, quote_redacted(reason, 512), who)


def _block(flow, agent, nbytes, reason, who):
    flow.response = http.Response.make(
        403, f"heimdall [{who}]: {quote_redacted(reason, 512)}\n".encode(), {"Content-Type": "text/plain"}
    )
    _log(flow, agent, nbytes, "block", reason, who)


async def request(flow: http.HTTPFlow) -> None:
    agent = _agent(flow)
    if SUPERVISOR_OFF:
        _log(flow, agent, 0, "allow", "supervisor off (proof baseline)", "off")
    else:
        try:
            await _decide(flow, agent)
        except Exception as e:
            _block(flow, agent, 0, f"checkpoint error, fail-closed: {type(e).__name__}", "hard-rule:error")
    if MOCK and flow.response is None:
        # ponytail: plain HTTP/1 to the mock; an HTTP/2 agent would need h2c here.
        host_header = flow.request.host_header  # the mock routes on it; .host setter would overwrite it
        h, port = MOCK.rsplit(":", 1)
        flow.request.scheme = "http"
        flow.request.host, flow.request.port = h, int(port)
        flow.request.host_header = host_header


async def _decide(flow: http.HTTPFlow, agent: str | None) -> None:
    req = flow.request
    host = req.host.lower()
    path = req.path.split("?", 1)[0]
    body = req.raw_content or b""
    headers = list(req.headers.items(multi=True))
    header_bytes = sum(len(k) + len(v) + 4 for k, v in headers)
    nbytes = len(req.url) + header_bytes + len(body)  # all egress: URL + headers + body

    if agent not in R.ALLOWLIST:
        return _block(flow, agent, nbytes, "unknown agent", "hard-rule:agent")
    known_host = host in R.ALLOWLIST[agent]["allow_hosts"]
    for who, check in [
        ("hard-rule:size", lambda: R.check_sizes(req.url, header_bytes)),
        ("hard-rule:dest", lambda: R.check_destination(host)),
        ("hard-rule:sni", lambda: R.check_sni(host, req.host_header, flow.client_conn.sni, req.scheme)),
        ("hard-rule:encoding", lambda: None if req.headers.get("content-encoding", "identity").lower() == "identity"
         else "encoded request body refused (checks need plaintext)"),
        ("hard-rule:path", lambda: R.check_path(req.path)),
        ("hard-rule:upgrade", lambda: "upgrade to non-allowlisted host refused"
         if req.headers.get("upgrade") and not known_host else None),
        ("hard-rule:keys", lambda: R.check_keys(agent, host, headers, req.url, body)),
        ("hard-rule:provider-fetch", lambda: R.check_provider_fetch(agent, host, body)),
    ]:
        reason = check()
        if reason:
            return _block(flow, agent, nbytes, reason, who)

    cap = R.match_endpoint(agent, req.method, host, path)
    if cap is not None:
        if len(body) > cap:
            return _block(flow, agent, nbytes, f"body {len(body)}B over cap {cap}B for {req.method} {host}{path}",
                          "hard-rule:endpoint")
        verdict, why, who = "allow", "endpoint rule", "hard-rule:endpoint"
    else:
        # Unknown move: only an exact allow-with-budget passes; anything else (deny, escalate, garbage) blocks.
        # Worker thread: a 1-3s Muse call must not stall every other agent request on the event loop.
        verdict, why = await asyncio.to_thread(review_unknown, agent, req.method, host, path, body)
        who = "muse-reviewer"
        if verdict != "allow-with-budget":
            return _block(flow, agent, nbytes, f"{verdict}: {why}", who)

    reason = R.count_egress(agent, host, nbytes, known_host)
    if reason:
        return _block(flow, agent, nbytes, reason, "hard-rule:budget")
    swap_placeholders(agent, host, req.headers)
    _log(flow, agent, nbytes, verdict, why, who)


async def server_connect(data) -> None:
    """Resolve once, refuse non-global IPs, pin the IP we checked (no DNS-rebinding window). SNI stays the hostname."""
    if MOCK:  # hard guarantee: in mock mode nothing connects anywhere but the mock
        h, port = MOCK.rsplit(":", 1)
        data.server.address = (h, int(port))
        return
    host, port = data.server.address[:2]
    try:
        if R.is_ip_literal(host):
            data.server.error = "heimdall: IP literal refused"
            return
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
        ips = sorted({i[4][0] for i in infos})
        bad = [ip for ip in ips if R.is_private_target(ip)]
        if not ips or bad:
            data.server.error = f"heimdall: {host} resolves to non-public {bad}"
            return
        data.server.address = (ips[0], port)
    except Exception as e:
        data.server.error = f"heimdall: resolve failed, fail-closed: {type(e).__name__}"


def responseheaders(flow: http.HTTPFlow) -> None:
    # ponytail: non-LLM responses are buffered but not yet scanned; PromptGuard 2 hooks in here (Fri).
    if flow.request.host.lower() in R.LLM_HOSTS.get(_agent(flow), set()):
        flow.response.stream = True


def websocket_message(flow: http.HTTPFlow) -> None:
    msg = flow.websocket.messages[-1]
    if not msg.from_client:
        return
    agent = _agent(flow)
    try:
        if R.PLACEHOLDER_RE.search(msg.content.decode("utf-8", "ignore")):
            reason = "placeholder in websocket frame (tripwire)"
        else:
            reason = R.count_egress(agent, flow.request.host.lower(), len(msg.content), True)
    except Exception as e:
        reason = f"checkpoint error, fail-closed: {type(e).__name__}"
    if reason:
        msg.drop()
        flow.kill()
        _log(flow, agent, len(msg.content), "block", reason, "hard-rule:websocket")


def running() -> None:
    # Publish only the public CA cert for agents; the CA private key stays in the checkpoint's confdir.
    out = os.environ.get("HEIMDALL_CA_OUT")
    if out:
        # tlsconfig only creates the CA in its own running(), which can fire after ours (upstream FIXME); idempotent.
        ctx.master.addons.get("tlsconfig").configure({"confdir"})
        os.makedirs(os.path.dirname(out), exist_ok=True)
        shutil.copy(Path(ctx.options.confdir).expanduser() / "mitmproxy-ca-cert.pem", out)
