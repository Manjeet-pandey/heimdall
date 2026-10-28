"""Checkpoint pipeline skeleton. See AGENTS.md section 3. Hard rules first, reviewer never overrides."""

import ipaddress
import re
import urllib.parse

# Agent -> {"allow_hosts": set, "path_rules": [(method, host_re, path_re, max_bytes)], "budget_day": int}
ALLOWLIST = {}
BUDGET_USED = {}  # (agent, dest_host) -> bytes

PLACEHOLDER_RE = re.compile(r"gw_ph_[A-Za-z0-9_]+")
FOREIGN_KEY_HEADERS = ("authorization", "x-api-key", "x-goog-api-key", "api-key")
MAX_URL = 8192
MAX_HEADERS = 16384


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def is_private_target(host_or_ip: str) -> bool:
    """Called AFTER resolve. Proxy's own resolver must not become an exfil oracle."""
    try:
        ip = ipaddress.ip_address(host_or_ip.strip("[]"))
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
        )
    except ValueError:
        return False


def check_destination(agent: str, host: str) -> str | None:
    """Returns block reason or None. Runs BEFORE any DNS lookup by caller."""
    if not host or len(host) > 253:
        return "empty/oversize host"
    if is_ip_literal(host):
        return "IP literal refused"
    allowed = ALLOWLIST.get(agent, {}).get("allow_hosts", set())
    if host not in allowed:
        return f"host {host} not on allowlist"
    return None


def check_keys(
    agent: str, host: str, headers: dict, url: str, body: bytes
) -> str | None:
    blob = (
        url
        + "\n"
        + "\n".join(f"{k}: {v}" for k, v in headers.items())
        + "\n"
        + body[:4096].decode("utf-8", "ignore")
    )
    has_placeholder = bool(PLACEHOLDER_RE.search(blob))
    allow_hosts = ALLOWLIST.get(agent, {}).get("allow_hosts", set())
    # Tripwire: my placeholder anywhere unexpected is always a block.
    if has_placeholder and host not in allow_hosts:
        return "placeholder key to non-allowlisted host (tripwire)"
    # Foreign-key block on LLM hosts: only my placeholder may authenticate.
    if host in allow_hosts and "api." in host:  # narrowed per-agent in rules.py
        low = {k.lower(): v for k, v in headers.items()}
        for h in FOREIGN_KEY_HEADERS:
            v = low.get(h, "")
            if v and not PLACEHOLDER_RE.search(v):
                return f"foreign credential in {h} on LLM host"
        qs = urllib.parse.urlparse(url).query + body[:2048].decode("utf-8", "ignore")
        if re.search(
            r"sk-(?!.*gw_ph_)[A-Za-z0-9]{8,}|ghp_[A-Za-z0-9]{8,}|xox[bap]-", qs
        ):
            return "foreign credential in query/body on LLM host"
    return None


PROVIDER_FETCH_KEYS = ("server_url", "image_url", "file_url", "web_search")
# LLM hosts per agent — explicit set, not substring match. Filled by learn-lock.
LLM_HOSTS: dict[str, set[str]] = {}


def check_provider_fetch(agent: str, host: str, body: bytes) -> str | None:
    """Blocks making the LLM provider fetch an attacker URL with our key."""
    if host not in LLM_HOSTS.get(agent, set()):
        return None
    try:
        import json

        obj = json.loads(body.decode("utf-8") or "{}")
    except Exception:
        return None
    allowed = ALLOWLIST.get(agent, {}).get("allow_hosts", set())

    def host_of(u: str) -> str:
        try:
            return urllib.parse.urlparse(u).hostname or ""
        except Exception:
            return ""

    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if (
                    k in PROVIDER_FETCH_KEYS
                    and isinstance(v, str)
                    and v.startswith("http")
                ):
                    if host_of(v) not in allowed:
                        return f"provider-side fetch to non-allowlisted {host_of(v)}"
                if isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return None


def check_endpoint(
    agent: str, method: str, host: str, path: str, nbytes: int
) -> str | None:
    rules = ALLOWLIST.get(agent, {}).get("path_rules", [])
    for m, h_re, p_re, max_b in rules:
        if m in ("*", method) and re.fullmatch(h_re, host) and re.fullmatch(p_re, path):
            if nbytes > max_b:
                return f"body {nbytes}B over cap {max_b}B for {method} {host}{path}"
            return None
    return f"no endpoint rule for {method} {host}{path}"


def count_egress(agent: str, host: str, nbytes: int) -> str | None:
    cap = ALLOWLIST.get(agent, {}).get("budget_day", 1 << 20)
    key = (agent, host)
    BUDGET_USED[key] = BUDGET_USED.get(key, 0) + nbytes
    if host not in ALLOWLIST.get(agent, {}).get("allow_hosts", set()):
        if BUDGET_USED[key] > cap:
            return f"unknown-dest budget exceeded ({BUDGET_USED[key]} > {cap})"
    return None


class Addon:
    def request(self, flow):
        # mitmproxy wires this in. Unit-tested via proof/ without mitmproxy.
        pass
