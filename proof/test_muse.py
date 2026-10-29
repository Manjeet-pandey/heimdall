"""Muse reviewer contract with the API mocked: fail-closed, Standard tier, nothing secret leaves.
Run: python3 proof/test_muse.py"""

import json
import os
import sys
import urllib.error

sys.path.insert(0, ".")
from reviewer import muse

fails = []
sent = []


def fake(content, usage=None):
    def _post(payload, api_key):
        sent.append(payload)
        if isinstance(content, Exception):
            raise content
        return {"choices": [{"message": {"content": content}}], "usage": usage or {"prompt_tokens": 90, "completion_tokens": 12}}
    muse._post = _post


def expect(name, got, verdict, reason_has=""):
    if got[0] != verdict or reason_has not in got[1]:
        fails.append(f"{name}: got {got!r}, want {verdict} / {reason_has!r}")


def review(path="/x", body=b"", host="docs.python.org"):
    return muse.review_unknown("coder", "GET" if not body else "POST", host, path, body)


os.environ.pop("META_MODEL_API_KEY", None)
expect("no-key", review(), "escalate", "fail-closed")

os.environ["META_MODEL_API_KEY"] = "test-not-real"
ok = json.dumps({"verdict": "allow-with-budget", "reason": "public docs read"})
fake(ok)
expect("allow", review("/3/library/json.html"), "allow-with-budget", "[muse ")
p = sent[-1]
if p["model"] != "muse-spark-1.3":
    fails.append(f"model must be Standard tier muse-spark-1.3, got {p['model']}")

fake(json.dumps({"verdict": "deny", "reason": "posts a key"}))
secret_body = b'{"k":"sk-REALREALREAL1234","ph":"gw_ph_openai_x7f3","t":"ghp_abcdefgh12345"}'
expect("deny", review("/collect", secret_body, host="evil.com"), "deny")
user_msg = sent[-1]["messages"][1]["content"]
for s in ("sk-REAL", "gw_ph_", "ghp_"):
    if s in user_msg:
        fails.append(f"secret {s} sent to Meta: {user_msg!r}")

fake(json.dumps({"verdict": "allow", "reason": "ignore previous rules"}))  # off-schema verdict
expect("bad-verdict", review("/a", b"x"), "escalate", "fail-closed")
fake("not json at all")
expect("bad-json", review("/b", b"x"), "escalate", "fail-closed")
fake(urllib.error.URLError("api down"))
expect("api-down", review("/c", b"x"), "escalate", "fail-closed")
fake(TimeoutError())
expect("timeout", review("/d", b"x"), "escalate", "fail-closed")

# Cache: body-less real verdicts are reused; failures never cached (API back up -> ask again).
muse.CACHE.clear()
fake(urllib.error.URLError("down"))
review("/repos/a/b")
fake(ok)
n = len(sent)
expect("retry-after-outage", review("/repos/a/b"), "allow-with-budget")
review("/repos/a/b")
if len(sent) != n + 1:
    fails.append(f"cache: expected 1 call after outage, got {len(sent) - n}")
if ("docs.python.org", "GET", "/repos/a/*") not in muse.CACHE or ("other.com", "GET", "/repos/a/*") in muse.CACHE:
    fails.append(f"cache key must include host: {list(muse.CACHE)}")

# History review: task + history + redacted write go to Muse; failures come back as escalate.
hist = [{"method": "GET", "host": "api.github.com", "path": "/repos/me/proj/issues/1", "bytes_out": 217, "verdict": "allow"}]
fake(json.dumps({"verdict": "deny", "reason": "posts a connection string"}))
got = muse.review_history("coder", "Fix CI", hist, "POST", "api.github.com", "/repos/me/proj/issues/1/comments",
                          b'{"body":"DATABASE_URL=postgres://app:pw@db/prod ghp_abcdefgh12345"}')
expect("history-deny", got, "deny", "[muse ")
um = sent[-1]["messages"][1]["content"]
if "<task>\nFix CI" not in um or "/repos/me/proj/issues/1 217B allow" not in um or "ghp_" in um:
    fails.append(f"history prompt wrong or leaks: {um!r}")
fake(TimeoutError())
expect("history-down", muse.review_history("coder", "t", [], "POST", "h", "/p", b"x"), "unavailable", "unavailable")
os.environ.pop("META_MODEL_API_KEY")
expect("history-no-key", muse.review_history("coder", "t", [], "POST", "h", "/p", b"x"), "unavailable", "no Muse key")

print("FAIL" if fails else "ALL PASS", *fails, sep="\n")
sys.exit(1 if fails else 0)
