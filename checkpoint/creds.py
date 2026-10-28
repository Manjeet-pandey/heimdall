"""Real keys live in process env (from .env.secrets). Agents only ever see placeholders."""

import os

PLACEHOLDER_PREFIX = "gw_ph_"


def real_key(name: str) -> str:
    v = os.environ.get(name, "")
    if not v:
        raise RuntimeError(f"missing {name} in checkpoint env")
    return v


def swap_placeholder(host: str, body: bytes, mapping: dict[str, str]) -> bytes:
    """Header-only swap in v1. Body JSON re-serialize only if a rule needs it."""
    out = body
    for placeholder, env_name in mapping.get(host, {}).items():
        out = out.replace(placeholder.encode(), real_key(env_name).encode())
    return out
