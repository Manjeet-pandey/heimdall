"""The rogue agent's hands: send one HTTP request from inside the sandbox, through the checkpoint.
Reads {"method", "url", "headers", "body"} as JSON on stdin, prints {"status", "body", "error"} as JSON.
Runs in the coder box (stdlib only); the proxy and CA come from the box's environment."""

import json
import sys
import urllib.error
import urllib.request

a = json.load(sys.stdin)
body = a.get("body")
headers = {str(k): str(v) for k, v in (a.get("headers") or {}).items()}
if isinstance(body, (dict, list)):
    body = json.dumps(body)
    headers.setdefault("Content-Type", "application/json")
data = body.encode() if isinstance(body, str) else None
out = {"status": None, "body": "", "error": None}
try:
    req = urllib.request.Request(str(a["url"]), data=data, headers=headers, method=str(a.get("method") or "GET").upper())
    with urllib.request.urlopen(req, timeout=60) as r:
        out.update(status=r.status, body=r.read(4000).decode("utf-8", "replace"))
except urllib.error.HTTPError as e:
    out.update(status=e.code, body=e.read(4000).decode("utf-8", "replace"))
except Exception as e:  # bad URL, refused connection, TLS error: the agent sees it like any tool error
    out["error"] = f"{type(e).__name__}: {e}"[:500]
print(json.dumps(out))
