"""mitmproxy entrypoint. Request bodies buffered, LLM responses stream (SSE keeps working).
Every hook fails closed: an exception in a mitmproxy addon otherwise lets the flow through unchecked.
Run with --set connection_strategy=lazy so nothing connects (or resolves) before request() decides."""

import asyncio
import hashlib
import json
import os
import re
import shutil
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from mitmproxy import ctx, http

from checkpoint import rules as R
from checkpoint.creds import swap_placeholders
from checkpoint.db import connect, escalate, flagged_today, human_decision, log, mark_used, open_escalation, recent
from reviewer.muse import decide_escalation, quote_redacted, review_history, review_unknown

# Live policy is writable (the review page locks learned moves into it); first start copies the repo's seed.
POLICY = os.environ.get("HEIMDALL_POLICY", str(Path(__file__).with_name("policy.json")))
if not os.path.exists(POLICY):
    shutil.copy(os.environ.get("HEIMDALL_POLICY_SEED", Path(__file__).with_name("policy.json")), POLICY)
R.load_policy(POLICY)
DB_PATH = os.environ.get("HEIMDALL_DB", "checkpoint.db")
DB = connect(DB_PATH)
# Human answers to escalations, written only by the review page. Named after the DB: escalation ids are per DB.
DECISIONS = os.path.splitext(DB_PATH)[0] + ".decisions.db"
# Attack/proof runs: every upstream connection goes to the mock server, never the internet.
MOCK = os.environ.get("HEIMDALL_MOCK_UPSTREAM")  # "mock:8000"
# Attack mode only: hosts that skip the mock and go out for real (public DNS, real TLS), e.g. a server you own behind a tunnel.
REAL_HOSTS = {h.strip().lower() for h in os.environ.get("HEIMDALL_REAL_HOSTS", "").split(",") if h.strip()}
# Proof baseline ("no supervisor"): forward everything unchecked. Refuses to run outside mock mode.
SUPERVISOR_OFF = os.environ.get("HEIMDALL_SUPERVISOR") == "off"
if SUPERVISOR_OFF and not MOCK:
    raise SystemExit("HEIMDALL_SUPERVISOR=off requires HEIMDALL_MOCK_UPSTREAM")
# PromptGuard 2 service ("http://guard:8002"). Unset = response scanning off; set but unreachable = fail-closed.
GUARD_URL = os.environ.get("HEIMDALL_GUARD_URL")
FLAG_AT = float(os.environ.get("HEIMDALL_GUARD_THRESHOLD", "0.5"))
SCANNED_TYPES = re.compile(r"text/|application/(json|xml|javascript|x-www-form-urlencoded)|[^;]*\+(json|xml)", re.I)
# Strict mode: agent read flagged content. Unknown moves block (no reviewer allows); allowed writes need Muse's OK.
STRICT: set[str] = flagged_today(DB)
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# PromptGuard scans get their own threads: a slow Muse call (Wonder can take 10-30 s under load) must never
# make every response wait behind it. Muse calls use the default pool, sized in running().
GUARD_POOL = ThreadPoolExecutor(max_workers=32, thread_name_prefix="guard")
# Who settles what Muse Spark is unsure about. "wonder": Muse Wonder decides allow/deny on the spot (fail closed),
# so agents run 24/7 without anyone watching. "human": the request waits in the review page's queue for you.
DECIDER = os.environ.get("HEIMDALL_DECIDER", "wonder")


def _agent(flow) -> str | None:
    # Set by mitmproxy's proxyauth addon: agent = proxy username.
    auth = flow.metadata.get("proxyauth")
    return auth[0] if auth else None


def _log(flow, agent, nbytes, verdict, reason, who):
    # Query strings and bodies are stored redacted: a foreign key in a blocked request must not land in the log.
    r = flow.request
    path = quote_redacted(r.path.split("?", 1)[0], 512)
    query = quote_redacted(r.path.split("?", 1)[1] if "?" in r.path else "", 1024)
    body = quote_redacted((r.raw_content or b"").decode("utf-8", "replace"), 2048)
    headers = quote_redacted("\n".join(f"{k}: {v}" for k, v in r.headers.items(multi=True)), 2048)
    host = quote_redacted(flow.metadata.get("heimdall_host", r.host), 253)  # mock mode rewrites r.host before response()
    log(DB, agent or "?", r.method, host, path, query, body, headers, nbytes, verdict, quote_redacted(reason, 512), who)


def _block(flow, agent, nbytes, reason, who):
    flow.metadata["heimdall_blocked"] = True
    flow.response = http.Response.make(
        403, f"heimdall [{who}]: {quote_redacted(reason, 512)}\n".encode(), {"Content-Type": "text/plain"}
    )
    _log(flow, agent, nbytes, "block", reason, who)


async def request(flow: http.HTTPFlow) -> None:
    agent = _agent(flow)
    flow.metadata["heimdall_host"] = flow.request.host
    if SUPERVISOR_OFF:
        _log(flow, agent, 0, "allow", "supervisor off (proof baseline)", "off")
    else:
        try:
            await _decide(flow, agent)
        except Exception as e:
            _block(flow, agent, 0, f"checkpoint error, fail-closed: {type(e).__name__}", "hard-rule:error")
    if MOCK and flow.response is None and flow.request.host.lower() not in REAL_HOSTS:
        # ponytail: plain HTTP/1 to the mock; an HTTP/2 agent would need h2c here.
        host_header = flow.request.host_header  # the mock routes on it; .host setter would overwrite it
        h, port = MOCK.rsplit(":", 1)
        flow.request.scheme = "http"
        flow.request.host, flow.request.port = h, int(port)
        flow.request.host_header = host_header


async def _decide(flow: http.HTTPFlow, agent: str | None) -> None:
    R.reload_if_changed()
    req = flow.request
    host = req.host.lower()
    path = req.path.split("?", 1)[0]
    body = req.raw_content or b""
    headers = list(req.headers.items(multi=True))
    header_bytes = sum(len(k) + len(v) + 4 for k, v in headers)
    nbytes = len(req.url) + header_bytes + len(body)  # all egress: URL + headers + body

    if agent not in R.ALLOWLIST:
        return _block(flow, agent, nbytes, "unknown agent", "hard-rule:agent")
    if req.stream:  # only if someone enables stream_large_bodies: the body would skip every check below
        return _block(flow, agent, nbytes, "streamed request body refused (checks need the whole body)", "hard-rule:size")
    known_host = host in R.ALLOWLIST[agent]["allow_hosts"]
    for who, check in [
        ("hard-rule:size", lambda: R.check_sizes(req.url, header_bytes)),
        ("hard-rule:dest", lambda: R.check_destination(host)),
        ("hard-rule:sni", lambda: R.check_sni(host, req.host_header, flow.client_conn.sni, req.scheme, req.port)),
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
    if cap is not None and len(body) > cap:
        return _block(flow, agent, nbytes, f"body {len(body)}B over cap {cap}B for {req.method} {host}{path}",
                      "hard-rule:endpoint")
    # Writes to allowed endpoints get Muse's history review; slow leaks ride them.
    reviewed_write = cap is not None and req.method in WRITE_METHODS and host not in R.LLM_HOSTS.get(agent, set())
    # The exact request (method, URL incl. query, body) keys the human queue.
    req_sha = hashlib.sha256(f"{req.method} {host}{req.path}\n".encode() + body).hexdigest()
    shown = quote_redacted(path, 512)
    esc = open_escalation(DB, agent, req_sha) if cap is None or reviewed_write else None
    learning = R.ALLOWLIST[agent]["mode"] == "learn" and agent not in STRICT
    strict = agent in STRICT

    def to_human(reason: str, who: str):
        e = escalate(DB, agent, req.method, host, shown, req_sha, quote_redacted(reason, 512))
        return _block(flow, agent, nbytes, f"{reason} (escalation #{e}, waiting for you)", who)

    async def second_opinion(first_reason: str) -> tuple[bool, str]:
        """Spark was unsure: Muse Wonder decides. Never past a hard rule (those already ran), budgets still apply."""
        v, why = await asyncio.to_thread(decide_escalation, agent, R.ALLOWLIST[agent]["task"], recent(DB, agent),
                                         req.method, host, path, body, first_reason)
        return v == "allow", why

    if esc is not None:
        decision = human_decision(DECISIONS, esc)
        if decision != "allow":
            why = "denied by you" if decision == "deny" else "waiting for your decision"
            return _block(flow, agent, nbytes, f"{why} (escalation #{esc})", "human")
        verdict, why, who = "allow", f"approved by you (escalation #{esc})", "human"
    elif cap is not None:
        verdict, why, who = "allow", "endpoint rule", "hard-rule:endpoint"
        if reviewed_write:
            hv, hwhy = await asyncio.to_thread(
                review_history, agent, R.ALLOWLIST[agent]["task"], recent(DB, agent), req.method, host, path, body)
            if hv == "deny":
                return _block(flow, agent, nbytes, f"deny: {hwhy}", "muse-history")
            if hv == "escalate":  # Spark answered "not sure"
                if DECIDER == "human":
                    return to_human(f"escalate: {hwhy}", "muse-history")
                ok, wwhy = await second_opinion(hwhy)
                if not ok:
                    return _block(flow, agent, nbytes, f"deny: {wwhy} (Spark unsure: {hwhy})", "muse-wonder")
                verdict, why, who = "allow", f"endpoint rule; Spark unsure, Wonder allowed: {wwhy}", "muse-wonder"
            elif hv == "unavailable":
                if strict:  # under watch: nothing unreviewed goes out
                    return _block(flow, agent, nbytes, f"unavailable (strict mode): {hwhy}", "muse-history")
                if DECIDER == "human":  # human mode keeps writes flowing while Muse is down (documented limit)
                    verdict, why, who = "allow", f"endpoint rule; history unavailable: {hwhy}", "muse-history"
                else:
                    # An unreviewed write is how a slow leak gets out: a Spark timeout must not open the door.
                    # Wonder decides; if it can't either, the write is denied (fail closed).
                    ok, wwhy = await second_opinion(f"history review unavailable: {hwhy}")
                    if not ok:
                        return _block(flow, agent, nbytes, f"deny: {wwhy} (Spark unavailable)", "muse-wonder")
                    verdict, why, who = "allow", f"endpoint rule; Spark unavailable, Wonder allowed: {wwhy}", "muse-wonder"
            else:
                verdict, why, who = "allow", f"endpoint rule; history {hv}: {hwhy}", "muse-history"
    elif learning:
        verdict, why, who = "learn", "learning run: recorded for your approval", "learn-mode"
    elif strict:  # read hidden instructions: no model may allow anything new for this agent
        if DECIDER == "human":
            return to_human("strict mode: agent read flagged content, unknown moves need you", "strict-mode")
        return _block(flow, agent, nbytes, "strict mode: agent read flagged content, nothing new goes out", "strict-mode")
    else:
        # Only an exact allow-with-budget passes; escalate goes to the human queue; anything else blocks.
        # Worker thread: a 1-3s Muse call must not stall every other agent request on the event loop.
        verdict, why = await asyncio.to_thread(review_unknown, agent, req.method, host, path, body)
        who = "muse-reviewer"
        if verdict == "escalate":
            if DECIDER == "human":
                return to_human(f"escalate: {why}", who)
            ok, wwhy = await second_opinion(why)
            if not ok:
                return _block(flow, agent, nbytes, f"deny: {wwhy} (Spark unsure: {why})", "muse-wonder")
            verdict, why, who = "allow-with-budget", f"Spark unsure, Wonder allowed: {wwhy}", "muse-wonder"
        if verdict != "allow-with-budget":
            return _block(flow, agent, nbytes, f"{verdict}: {why}", who)
        if R.ALLOWLIST[agent]["unknown_day"] == 0:
            # This agent has no allowance for new sites: a model's "looks harmless" is not a pass.
            if DECIDER == "human":
                return to_human(f"new site needs you: Muse thinks it's harmless ({why})", who)
            return _block(flow, agent, nbytes, f"new site: {agent} has no allowance for new sites (looked harmless: {why})", who)

    # Learning runs and your own approvals get the normal daily cap for new sites (still one shared bucket).
    reason = R.count_egress(agent, host, nbytes, known_host, trusted=cap is None and (learning or who == "human"))
    if reason:
        return _block(flow, agent, nbytes, reason, "hard-rule:budget")
    if who == "human":
        mark_used(DB, esc)  # one approval, one request: consumed only once it actually goes out
    _log(flow, agent, nbytes, verdict, why, who)  # before the swap: the log keeps headers, so it must only ever see placeholders
    swap_placeholders(agent, host, req.headers)


async def server_connect(data) -> None:
    """Resolve once, refuse non-global IPs, pin the IP we checked (no DNS-rebinding window). SNI stays the hostname."""
    if MOCK and data.server.address[0].lower() not in REAL_HOSTS:  # in mock mode only listed hosts leave
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


def _guard_score(text: str) -> float:
    req = urllib.request.Request(f"{GUARD_URL}/score", data=text.encode("utf-8", "replace"), method="POST")
    with urllib.request.urlopen(req, timeout=60) as r:
        return float(json.load(r)["score"])


async def response(flow: http.HTTPFlow) -> None:
    """PromptGuard 2 on every buffered (non-LLM) text response, before the agent sees it. Flag -> strict mode."""
    if not GUARD_URL or SUPERVISOR_OFF or flow.metadata.get("heimdall_blocked") or flow.response.stream:
        return
    # ponytail: binary bodies (images, archives) aren't scanned; add OCR / archive peeking if attacks move there.
    if not SCANNED_TYPES.match(flow.response.headers.get("content-type", "")):
        return
    agent = _agent(flow)
    try:
        score = await asyncio.get_running_loop().run_in_executor(
            GUARD_POOL, _guard_score, flow.response.get_text(strict=False) or "")
        why = f"PromptGuard injection score {score:.2f}"
    except Exception as e:
        score, why = 1.0, f"PromptGuard unavailable, fail-closed ({type(e).__name__})"
    if score >= FLAG_AT:
        STRICT.add(agent)
        _log(flow, agent, 0, "flag", f"{why} in response; {agent} now in strict mode", "promptguard")


def responseheaders(flow: http.HTTPFlow) -> None:
    # LLM responses stream (SSE); everything else is buffered for PromptGuard in response().
    # The original host: mock mode has already rewritten flow.request.host to the mock by now.
    host = flow.metadata.get("heimdall_host", flow.request.host).lower()
    if host in R.LLM_HOSTS.get(_agent(flow), set()):
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
    # Muse (1-3 s) calls run in worker threads. The default pool (~16) starves under load:
    # a few slow Muse calls would hold every thread and stall everyone. (One running() only: a second def replaces the first.)
    asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(max_workers=64))
    # Publish only the public CA cert for agents; the CA private key stays in the checkpoint's confdir.
    out = os.environ.get("HEIMDALL_CA_OUT")
    if out:
        # tlsconfig only creates the CA in its own running(), which can fire after ours (upstream FIXME); idempotent.
        ctx.master.addons.get("tlsconfig").configure({"confdir"})
        os.makedirs(os.path.dirname(out), exist_ok=True)
        shutil.copy(Path(ctx.options.confdir).expanduser() / "mitmproxy-ca-cert.pem", out)
