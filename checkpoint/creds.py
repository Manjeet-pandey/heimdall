"""Real keys live in process env (from .env.secrets). Agents only ever see placeholders."""

import os
import re

# placeholder -> (agent, host, env var holding the real key). Filled from policy.json.
PLACEHOLDERS: dict[str, tuple[str, str, str]] = {}
_PH_RE = re.compile(rb"gw_ph_[A-Za-z0-9_]+")


def real_key(name: str) -> str:
    v = os.environ.get(name, "")
    if not v:
        raise RuntimeError(f"missing {name} in checkpoint env")
    return v


def swap_placeholders(agent: str, host: str, headers) -> None:
    """Header-only swap, run after check_keys. A placeholder in URL/body never becomes a real key
    (an LLM could echo it back). Only this agent's placeholders for this exact host are swapped."""

    def sub(m: re.Match) -> bytes:
        owner = PLACEHOLDERS.get(m.group().decode())
        if owner is None or owner[:2] != (agent, host):
            return m.group()
        return real_key(owner[2]).encode()

    headers.fields = tuple((k, _PH_RE.sub(sub, v)) for k, v in headers.fields)
