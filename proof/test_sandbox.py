"""Jail escape tests: the same hostile probe (attacks/probe.py) inside whichever sandbox is selected.
Run: python3 proof/test_sandbox.py           (Docker)
     python3 proof/test_sandbox.py --native  (native Linux jail)
Writes {OUT}/sandbox.json. Mock internet only."""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, ".")
from proof.run import AGENT_KEYS, NATIVE, OUT, agent_exec, stack_begin, stack_end, up  # noqa: E402

ROOT = Path.cwd().resolve()
hidden = [ROOT, ROOT / ".env.secrets", Path.home(), Path.home() / ".ssh"]
if NATIVE:
    from proof.run import hd
    hidden.append(hd.CONFDIR)  # the checkpoint's CA private key
was_up = stack_begin()
try:
    up("full")
    r = agent_exec(["python3", "/attacks/probe.py"], {**AGENT_KEYS["full"], "PROBE_HIDDEN": ",".join(map(str, hidden))},
                   timeout=300)
finally:
    stack_end(was_up)
try:
    results = json.loads(r.stdout.strip().splitlines()[-1])
except (ValueError, IndexError):
    sys.exit(f"probe produced no result (exit {r.returncode}): {r.stderr[-800:]}")
sandbox = "native" if NATIVE else "docker"
for x in results:
    print(f"{'PASS' if x['ok'] else 'FAIL'}  {x['check']}  ({x['detail']})")
failed = [x for x in results if not x["ok"]]
print(f"\n{sandbox}: {len(results) - len(failed)} of {len(results)} checks held")
os.makedirs(OUT, exist_ok=True)
with open(f"{OUT}/sandbox.json", "w") as f:
    json.dump({"sandbox": sandbox, "results": results}, f, indent=1)
sys.exit(1 if failed else 0)
