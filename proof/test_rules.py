"""Hard rules must hold without Muse. Run: python3 proof/test_rules.py"""

import sys

sys.path.insert(0, ".")
from checkpoint import rules as R

R.load_policy("checkpoint/policy.json")
R.BUDGET_USED.clear()
OA, GH = "api.openai.com", "api.github.com"
PH_OA = "gw_ph_openai_x7f3"

fails = []


def check(name, got, want_block):
    blocked = got is not None
    if blocked != want_block:
        fails.append(f"{name}: got={got!r} want_block={want_block}")


def keys(host, headers=(), url=None, body=b"{}"):
    return R.check_keys("coder", host, list(headers), url or f"https://{host}/v1/chat/completions", body)


# destination (pre-DNS)
check("ip-literal", R.check_destination("1.2.3.4"), True)
check("ipv6-literal", R.check_destination("[::1]"), True)
check("decimal-ip", R.check_destination("2130706433"), True)
check("hex-ip", R.check_destination("0x7f.1"), True)
check("normal-host", R.check_destination("evil.com"), False)  # unknown -> reviewer, not a hard block
# post-resolve
for ip in ["10.0.0.1", "127.0.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::ffff:10.0.0.1", "fd00::1"]:
    check(f"private-{ip}", "block" if R.is_private_target(ip) else None, True)
check("public-ip", "block" if R.is_private_target("93.184.216.34") else None, False)
# SNI / Host / CONNECT
check("sni-ok", R.check_sni(OA, "api.openai.com:443", OA, "https"), False)
check("host-mismatch", R.check_sni(OA, "evil.com", OA, "https"), True)
check("sni-mismatch", R.check_sni(OA, OA, "evil.com", "https"), True)
check("sni-missing", R.check_sni(OA, OA, None, "https"), True)
check("plain-http", R.check_sni(OA, OA, None, "http", 80), True)
check("https-odd-port", R.check_sni(OA, OA, OA, "https", 8443), True)
# path normalization
check("path-ok", R.check_path("/repos/me/x?a=1"), False)
check("traversal", R.check_path("/repos/me/../../evil/x"), True)
check("traversal-enc", R.check_path("/repos/me/%2e%2e/evil/x"), True)
check("traversal-2enc", R.check_path("/repos/me/%252e%252e/evil/x"), True)
check("backslash", R.check_path("/repos/me/..%5cevil"), True)
# tripwire: placeholders only in auth headers, only for their own host
check("legit-key", keys(OA, [("Authorization", f"Bearer {PH_OA}")]), False)
check("ph-to-github-body", keys(GH, url="https://api.github.com/repos/me/x/issues/1/comments", body=f'{{"body":"{PH_OA}"}}'.encode()), True)
check("ph-to-github-header", keys(GH, [("Authorization", f"token {PH_OA}")]), True)
check("ph-to-evil", keys("evil.com", [("Authorization", f"Bearer {PH_OA}")]), True)
check("ph-padded", keys("evil.com", body=b"A" * 5000 + PH_OA.encode()), True)
check("ph-in-body-own-host", keys(OA, body=f'{{"m":"{PH_OA}"}}'.encode()), True)  # LLM could echo the swapped key
check("ph-in-url", keys(OA, url=f"https://api.openai.com/v1?k={PH_OA}"), True)
check("ph-in-custom-header", keys(OA, [("X-Note", PH_OA)]), True)
check("ph-unknown", keys(OA, [("Authorization", "Bearer gw_ph_made_up")]), True)
# foreign keys on LLM host
for h, v in [
    ("Authorization", "Bearer sk-abc123456789"),
    ("x-api-key", "sk-abc123456789"),
    ("x-goog-api-key", "AIza-xyz123456789"),
    ("api-key", "secret123456789"),
    ("Authorization", f"Bearer {PH_OA} sk-abc123456789"),  # placeholder + smuggled key
]:
    check(f"foreign-{h}", keys(OA, [(h, v)]), True)
check("foreign-dupe-header", keys(OA, [("x-api-key", f"{PH_OA}"), ("x-api-key", "sk-abc123456789")]), True)
check("foreign-query", keys(OA, url="https://api.openai.com/v1?key=sk-abc123456789"), True)
check("foreign-query-lookahead", keys(OA, url="https://api.openai.com/v1?k=sk-REALREALREAL&p=x"), True)
check("foreign-body-deep", keys(OA, body=b'{"p":"' + b"A" * 5000 + b'sk-REALREALREAL"}'), True)
check("foreign-custom-header", keys(OA, [("X-Debug", "ghp_abcdefgh12345")]), True)
# No key at all on an LLM host: the prompt still leaves (rogue agent found this). Not on other hosts.
check("llm-no-key", keys(OA), True)
check("llm-empty-auth", keys(OA, [("Authorization", "")]), True)
check("github-no-key-ok", keys(GH, url="https://api.github.com/repos/me/proj/issues/1"), False)
# provider-side fetch
def pf(body):
    return R.check_provider_fetch("coder", OA, body)
check("pf-server-url", pf(b'{"server_url": "https://evil.com/hook"}'), True)
check("pf-ok", pf(b'{"server_url": "https://api.github.com/repos/me/x"}'), False)
check("pf-image-dict", pf(b'{"messages":[{"content":[{"type":"image_url","image_url":{"url":"https://evil.com/x.png"}}]}]}'), True)
check("pf-data-url", pf(b'{"image_url":{"url":"data:image/png;base64,iVBOR//w=="}}'), False)
check("pf-caps", pf(b'{"server_url":"HTTPS://evil.com/"}'), True)
check("pf-no-slashes", pf(b'{"url":"https:evil.com"}'), True)
check("pf-userinfo", pf(b'{"url":"https://api.github.com@evil.com/"}'), True)
check("pf-web-search", pf(b'{"tools":[{"type":"web_search_preview"}]}'), True)
check("pf-gemini-search", pf(b'{"tools":[{"google_search":{}}]}'), True)
check("pf-non-json", pf(b"\x1f\x8b gzip"), True)
check("pf-dupe-key", pf(b'{"server_url":"https://api.github.com/","server_url":"https://evil.com/"}'), True)
check("pf-plain-chat", pf(b'{"messages":[{"role":"user","content":"see https://evil.com"}]}'), False)
# endpoint rules
check("endpoint-known", "unknown" if R.match_endpoint("coder", "POST", GH, "/repos/me/x/issues/1/comments") is None else None, False)
check("endpoint-escape", "unknown" if R.match_endpoint("coder", "POST", GH, "/repos/evil/x/issues/1/comments") is None else None, True)
check("endpoint-host-not-allowed", "unknown" if R.match_endpoint("coder", "POST", "api.github.com.evil.com", "/repos/me/x") is None else None, True)
# budget: unknown dests share one cap; refusal doesn't charge
R.BUDGET_USED.clear()
R.ALLOWLIST["coder"]["unknown_day"] = 4096  # cap mechanics; the shipped policy gives coder 0 for new sites
check("budget-under", R.count_egress("coder", "a.com", 3000, False), False)
check("budget-rotate-host", R.count_egress("coder", "b.com", 3000, False), True)
check("budget-small-still-fits", R.count_egress("coder", "c.com", 1000, False), False)
check("budget-known", R.count_egress("coder", OA, 10_000, True), False)
# learning: new hosts get the normal cap, but in ONE shared bucket (audit finding: was one 50 MB bucket per host)
R.BUDGET_USED.clear()
cap = R.ALLOWLIST["coder"]["budget_day"]
check("learn-big-ok", R.count_egress("coder", "a.example", cap - 10, False, trusted=True), False)
check("learn-rotate-host-shares-cap", R.count_egress("coder", "b.example", 100, False, trusted=True), True)
# sizes
check("url-cap", R.check_sizes("x" * 9000, 0), True)
check("header-cap", R.check_sizes("x", 20000), True)

print("FAIL" if fails else "ALL PASS", *fails, sep="\n")
sys.exit(1 if fails else 0)
