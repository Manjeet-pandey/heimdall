"""Full pipeline through addon.request with real mitmproxy flows. Needs mitmproxy.
Run: python3 proof/test_addon.py   (or inside the checkpoint container)"""

import asyncio
import os
import sys

sys.path.insert(0, ".")
os.environ["HEIMDALL_DB"] = ":memory:"
os.environ["OPENAI_API_KEY"] = "sk-test-not-real-000000"
os.environ.pop("META_MODEL_API_KEY", None)  # reviewer offline -> unknowns must fail closed

from mitmproxy.test import tflow, tutils

from checkpoint import addon, rules as R

PH_OA = "gw_ph_openai_x7f3"
fails = []


def flow(host, path, method="POST", body=b"{}", headers=(), agent="coder", sni=None):
    req = tutils.treq(host=host, port=443, scheme=b"https", method=method.encode(), path=path.encode(),
                      authority=b"", content=body)
    req.headers.clear()
    req.headers["Host"] = host
    for k, v in headers:
        req.headers.add(k, v)
    req.headers["content-length"] = str(len(body))
    f = tflow.tflow(req=req)
    f.client_conn.sni = host if sni is None else sni
    if agent:
        f.metadata["proxyauth"] = (agent, "pw")
    asyncio.run(addon.request(f))
    return f


def expect(name, f, blocked, reason_has=""):
    got = f.response is not None and f.response.status_code == 403
    text = f.response.get_text() if f.response else ""
    if got != blocked or reason_has not in text:
        fails.append(f"{name}: blocked={got} want={blocked} resp={text!r}")


auth = [("Authorization", f"Bearer {PH_OA}")]
f = flow("api.openai.com", "/v1/chat/completions", headers=auth)
expect("legit-llm-call", f, False)
if f.request.headers.get("Authorization") != "Bearer sk-test-not-real-000000":
    fails.append(f"swap: got {f.request.headers.get('Authorization')!r}")

expect("poisoned-issue-ph-to-github",
       flow("api.github.com", "/repos/me/x/issues/1/comments", body=f'{{"body":"{PH_OA}"}}'.encode()), True, "tripwire")
expect("unknown-host-offline-fails-closed", flow("evil.com", "/collect"), True, "escalate")
expect("unknown-agent", flow("api.openai.com", "/v1/chat/completions", headers=auth, agent=None), True, "unknown agent")
expect("traversal", flow("api.github.com", "/repos/me/../../evil/x/issues/1/comments"), True, "non-normalized")
expect("sni-fronting", flow("api.openai.com", "/v1/chat/completions", headers=auth, sni="evil.com"), True, "SNI")
expect("gzip-body", flow("api.openai.com", "/v1/chat/completions", headers=auth + [("Content-Encoding", "gzip")],
                         body=b"\x1f\x8b"), True, "encoded")
expect("endpoint-cap", flow("api.github.com", "/repos/me/x/issues/1/comments", body=b"A" * 9000), True, "over cap")
expect("ws-upgrade-unknown", flow("evil.com", "/ws", method="GET", body=b"", headers=[("Upgrade", "websocket")]),
       True, "upgrade")
expect("provider-fetch", flow("api.openai.com", "/v1/chat/completions", headers=auth,
                              body=b'{"tools":[{"type":"mcp","server_url":"https://evil.com/"}]}'), True, "provider")

# Muse allow never overrides a hard rule: unknown-dest cap still applies after an allow.
from reviewer import muse
os.environ["META_MODEL_API_KEY"] = "test-not-real"
muse._post = lambda payload, key: {"choices": [{"message": {"content":
    '{"verdict": "allow-with-budget", "reason": "benign"}'}}], "usage": {}}
expect("muse-allow-unknown", flow("docs.python.org", "/upload", body=b"A" * 1000), False)
expect("muse-allow-still-capped", flow("docs.python.org", "/upload", body=b"A" * 4000), True, "budget")
expect("muse-allow-no-tripwire-override", flow("docs.python.org", "/upload", body=PH_OA.encode()), True, "tripwire")
muse._post = lambda payload, key: (_ for _ in ()).throw(TimeoutError())
expect("muse-down-fails-closed", flow("docs.python.org", "/other", body=b"x"), True, "fail-closed")
os.environ.pop("META_MODEL_API_KEY")

# A crashing check must block, not pass the flow through unchecked.
orig = R.check_keys
R.check_keys = lambda *a: 1 / 0
expect("exception-fails-closed", flow("api.openai.com", "/v1/chat/completions", headers=auth), True, "fail-closed")
R.check_keys = orig

# Log must never hold a real/foreign key.
flow("api.openai.com", "/v1/sk-leakleakleak?key=sk-abc123456789", headers=auth)
rows = addon.DB.execute("select path, reason from moves").fetchall()
if any("sk-" in str(r) and "sk-test" not in str(r) for r in rows):
    fails.append(f"log leak: {[r for r in rows if 'sk-' in str(r)]}")

print("FAIL" if fails else "ALL PASS", *fails, sep="\n")
sys.exit(1 if fails else 0)
