"""Checkpoint hard rules. See AGENTS.md section 3. Hard rules first, reviewer never overrides."""

import ipaddress
import json
import re
import time
import urllib.parse

from checkpoint.creds import PLACEHOLDERS

# Agent -> {"allow_hosts": set, "path_rules": [(method, host_re, path_re, max_bytes)], "budget_day": int, "unknown_day": int}
ALLOWLIST = {}
# LLM hosts per agent — explicit set, not substring match. Filled from policy.json (learn-lock output).
LLM_HOSTS: dict[str, set[str]] = {}
# ponytail: in-memory, lost on restart and old days never pruned; move to SQLite if the checkpoint runs for weeks.
BUDGET_USED = {}  # (day, agent, dest_host | UNKNOWN) -> bytes
UNKNOWN = "<unknown-dests>"  # unknown dests share one cap so rotating hosts doesn't multiply it

PLACEHOLDER_RE = re.compile(r"gw_ph_[A-Za-z0-9_]+")
AUTH_VALUE_RE = re.compile(r"(?:(?:Bearer|token)\s+)?gw_ph_[A-Za-z0-9_]+", re.I)
FOREIGN_KEY_HEADERS = ("authorization", "x-api-key", "x-goog-api-key", "api-key")
FOREIGN_KEY_RE = re.compile(
    r"sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{8,}|github_pat_\w{8,}"
    r"|xox[abprs]-|AIza[0-9A-Za-z_-]{20,}|AKIA[0-9A-Z]{16}"
)
# Keys whose string value the provider would fetch, and tools that make it browse.
FETCH_KEYS = {"url", "uri", "server_url", "image_url", "file_url", "audio_url", "video_url", "document_url"}
FETCH_TOOL_RE = re.compile(r"web_search|web_fetch|url_context|google_search", re.I)
HOST_RE = re.compile(r"([a-z0-9-]+\.)*[a-z][a-z0-9-]*")  # last label starts with a letter: no 0x7f.1 / 2130706433
MAX_URL = 8192
MAX_HEADERS = 16384
DEFAULT_UNKNOWN_DAY = 4096


def load_policy(path) -> None:
    with open(path) as f:
        p = json.load(f)
    for agent, a in p["agents"].items():
        ALLOWLIST[agent] = {
            "allow_hosts": set(a["allow_hosts"]),
            "path_rules": [tuple(r) for r in a["path_rules"]],
            "budget_day": a["budget_day"],
            "unknown_day": a.get("unknown_day", DEFAULT_UNKNOWN_DAY),
        }
        LLM_HOSTS[agent] = set(a["llm_hosts"])
    PLACEHOLDERS.update({k: tuple(v) for k, v in p["placeholders"].items()})


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def is_private_target(ip_str: str) -> bool:
    """Called AFTER resolve, on every resolved address. Anything not globally routable is refused."""
    ip = ipaddress.ip_address(ip_str.split("%")[0])
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not ip.is_global or ip.is_multicast


def check_sizes(url: str, header_bytes: int) -> str | None:
    if len(url) > MAX_URL:
        return f"URL {len(url)}B over cap {MAX_URL}B"
    if header_bytes > MAX_HEADERS:
        return f"headers {header_bytes}B over cap {MAX_HEADERS}B"
    return None


def check_destination(host: str) -> str | None:
    """Returns block reason or None. Runs BEFORE any DNS lookup. Allowlist membership is the caller's call."""
    if is_ip_literal(host):
        return "IP literal refused"
    if not host or len(host) > 253 or not HOST_RE.fullmatch(host):
        return "malformed host"
    return None


def check_sni(host: str, host_header: str | None, sni: str | None, scheme: str) -> str | None:
    """CONNECT target (request.host) = TLS SNI = Host header, else domain fronting."""
    hh = re.sub(r":\d+$", "", (host_header or "").lower())
    if hh != host:
        return f"Host header {hh!r} != CONNECT host {host}"
    if scheme == "https" and (sni or "").lower() != host:
        return f"SNI {sni!r} != CONNECT host {host}"
    return None


def check_path(path: str) -> str | None:
    """Refuse dot-segments / backslashes after percent-decoding, so /repos/me/../evil can't ride a /repos/me/.* rule."""
    p = path.split("?", 1)[0]
    for _ in range(5):  # %252e%252e -> %2e%2e -> ..
        p, prev = urllib.parse.unquote(p), p
        if p == prev:
            break
    if not p.startswith("/") or "\\" in p or any(s in (".", "..") for s in p.split("/")):
        return "non-normalized path refused"
    return None


def check_keys(
    agent: str, host: str, headers: list[tuple[str, str]], url: str, body: bytes
) -> str | None:
    blob = url + "\n" + body.decode("utf-8", "ignore")
    # Tripwire: placeholders are swapped in auth headers only. Anywhere else (URL, body, other
    # headers, another host) is an exfil attempt — and swapping in a body would let an LLM echo the real key.
    if PLACEHOLDER_RE.search(blob):
        return "placeholder in URL/body (tripwire)"
    for k, v in headers:
        for ph in PLACEHOLDER_RE.findall(f"{k}: {v}"):
            owner = PLACEHOLDERS.get(ph)
            if (
                k.lower() not in FOREIGN_KEY_HEADERS
                or not AUTH_VALUE_RE.fullmatch(v.strip())
                or owner is None
                or owner[:2] != (agent, host)
            ):
                return f"placeholder {ph} misused in {k.lower()} to {host} (tripwire)"
    # Foreign-key block on LLM hosts: only my placeholder may authenticate.
    if host in LLM_HOSTS.get(agent, set()):
        for k, v in headers:
            if k.lower() in FOREIGN_KEY_HEADERS and not AUTH_VALUE_RE.fullmatch(v.strip()):
                return f"foreign credential in {k.lower()} on LLM host"
        if FOREIGN_KEY_RE.search(blob + "\n" + "\n".join(v for _, v in headers)):
            return "foreign credential in query/body/headers on LLM host"
    return None


def _no_dupe_keys(pairs):
    # Parsers disagree on which duplicate wins; refuse instead of guessing what the provider sees.
    if len({k for k, _ in pairs}) != len(pairs):
        raise ValueError("duplicate JSON key")
    return dict(pairs)


def check_provider_fetch(agent: str, host: str, body: bytes) -> str | None:
    """Blocks making the LLM provider fetch an attacker URL with our key. Fails closed on unparseable bodies."""
    if host not in LLM_HOSTS.get(agent, set()) or not body:
        return None
    try:
        obj = json.loads(body, object_pairs_hook=_no_dupe_keys)
    except (ValueError, RecursionError):
        return "non-JSON or duplicate-key body on LLM host"
    allowed = ALLOWLIST.get(agent, {}).get("allow_hosts", set())
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, list):
            stack.extend(cur)
        if not isinstance(cur, dict):
            continue
        for k, v in cur.items():
            if FETCH_TOOL_RE.search(k) or (
                k == "type" and isinstance(v, str) and FETCH_TOOL_RE.search(v)
            ):
                return f"provider-side browsing tool refused ({k})"
            if k in FETCH_KEYS and isinstance(v, str):
                u = urllib.parse.urlsplit(v.strip())
                scheme = u.scheme.lower()
                if scheme != "data" and not (scheme in ("http", "https") and u.hostname in allowed):
                    return f"provider-side fetch to non-allowlisted {u.hostname or v[:40]!r}"
            if isinstance(v, (dict, list)):
                stack.append(v)
    return None


def match_endpoint(agent: str, method: str, host: str, path: str) -> int | None:
    """Max body bytes of the first matching rule, or None if no rule matches (= unknown move)."""
    a = ALLOWLIST.get(agent, {})
    if host not in a.get("allow_hosts", set()):
        return None
    for m, h_re, p_re, max_b in a.get("path_rules", []):
        if m in ("*", method) and re.fullmatch(h_re, host) and re.fullmatch(p_re, path):
            return max_b
    return None


def count_egress(agent: str, host: str, nbytes: int, known_host: bool) -> str | None:
    """Charge nbytes to today's budget; refuse (without charging) if it would go over the cap."""
    a = ALLOWLIST.get(agent, {})
    cap = a.get("budget_day", 0) if known_host else a.get("unknown_day", DEFAULT_UNKNOWN_DAY)
    key = (time.strftime("%Y-%m-%d"), agent, host if known_host else UNKNOWN)
    used = BUDGET_USED.get(key, 0) + nbytes
    if used > cap:
        return f"{'' if known_host else 'unknown-dest '}budget exceeded for {host} ({used} > {cap})"
    BUDGET_USED[key] = used
    return None
