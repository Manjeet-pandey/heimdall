"""Day-3 harness: hard rules must hold without Muse. Run: python3 proof/test_rules.py"""

import sys

sys.path.insert(0, ".")
from checkpoint import rules as R

R.ALLOWLIST["coder"] = {
    "allow_hosts": {"api.openai.com", "api.github.com"},
    "path_rules": [
        ("POST", r"api\.openai\.com", r"/v1/chat/completions", 16384),
        ("POST", r"api\.github\.com", r"/repos/me/.*", 8192),
    ],
    "budget_day": 1000,
}
R.LLM_HOSTS["coder"] = {"api.openai.com"}
R.BUDGET_USED.clear()

fails = []


def check(name, got, want_block):
    blocked = got is not None
    if blocked != want_block:
        fails.append(f"{name}: got={got!r} want_block={want_block}")


# 1. unknown host blocked pre-DNS
check("unknown-host", R.check_destination("coder", "evil.com"), True)
# 2. IP literal refused
check("ip-literal", R.check_destination("coder", "1.2.3.4"), True)
# 3. private target denied post-resolve
check("private", "block" if R.is_private_target("10.0.0.1") else None, True)
# 4. tripwire: placeholder to wrong host
check(
    "tripwire",
    R.check_keys("coder", "evil.com", {}, "https://evil.com/x", b"gw_ph_openai_x7f3"),
    True,
)
# 5. foreign key in 5 spots on LLM host
for h, v in [
    ("Authorization", "Bearer sk-abc123456789"),
    ("x-api-key", "sk-abc123456789"),
    ("x-goog-api-key", "AIza-xyz123456789"),
    ("api-key", "secret123456789"),
]:
    check(
        f"foreign-{h}",
        R.check_keys(
            "coder", "api.openai.com", {h: v}, "https://api.openai.com/v1/chat", b"{}"
        ),
        True,
    )
check(
    "foreign-query",
    R.check_keys(
        "coder",
        "api.openai.com",
        {},
        "https://api.openai.com/v1/chat?key=sk-abc123456789",
        b"{}",
    ),
    True,
)
# 6. legit placeholder passes key check
check(
    "legit-key",
    R.check_keys(
        "coder",
        "api.openai.com",
        {"Authorization": "Bearer gw_ph_openai_x7f3"},
        "https://api.openai.com/v1/chat/completions",
        b"{}",
    ),
    False,
)
# 7. provider-side fetch to attacker blocked
check(
    "provider-fetch",
    R.check_provider_fetch(
        "coder", "api.openai.com", b'{"server_url": "https://evil.com/hook"}'
    ),
    True,
)
check(
    "provider-fetch-ok",
    R.check_provider_fetch(
        "coder",
        "api.openai.com",
        b'{"server_url": "https://api.github.com/repos/me/x"}',
    ),
    False,
)
# 8. endpoint rules
check(
    "endpoint-ok",
    R.check_endpoint("coder", "POST", "api.github.com", "/repos/me/x", 100),
    False,
)
check(
    "endpoint-escape",
    R.check_endpoint("coder", "POST", "api.github.com", "/repos/evil/x", 100),
    True,
)
check(
    "endpoint-cap",
    R.check_endpoint("coder", "POST", "api.github.com", "/repos/me/x", 99999),
    True,
)
# 9. unknown-dest budget
R.BUDGET_USED.clear()
R.count_egress("coder", "evil.com", 600)
check("budget-over", R.count_egress("coder", "evil.com", 500), True)

print("FAIL" if fails else "ALL PASS", *fails, sep="\n")
sys.exit(1 if fails else 0)
