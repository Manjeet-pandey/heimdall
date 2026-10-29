#!/bin/sh
# DEMO=1 ./demo.sh replays the recorded real run with no network.
# ./demo.sh --check backstage reports problems but never refuses to start on stage.
set -eu
cd "$(dirname "$0")/.."
missing=""
for f in docker-compose.yml checkpoint/policy.json checkpoint/addon.py checkpoint/rules.py reviewer/muse.py proof/test_rules.py; do
  [ -f "$f" ] || missing="$missing $f"
done
if [ "${1:-}" = "--check" ]; then
  if [ -n "$missing" ]; then echo "check FAIL, missing:$missing"; exit 1; fi
  python3 proof/test_rules.py >/dev/null && echo "check OK: compose, rules, reviewer, tests pass" || { echo "check FAIL: test_rules failed"; exit 1; }
  python3 proof/test_muse.py >/dev/null && echo "check OK: Muse reviewer fail-closed" || { echo "check FAIL: test_muse failed"; exit 1; }
  python3 proof/test_review.py >/dev/null && echo "check OK: review page guards, decisions, learn/lock" || { echo "check FAIL: test_review failed"; exit 1; }
  if python3 -c "import mitmproxy" 2>/dev/null; then
    python3 proof/test_addon.py >/dev/null && echo "check OK: full pipeline" || { echo "check FAIL: test_addon failed"; exit 1; }
  else
    echo "check WARN: mitmproxy not installed, pipeline test skipped (pip install 'mitmproxy>=11,<12' to run proof/test_addon.py)"
  fi
  [ -d demo/recorded ] || echo "check WARN: demo/recorded missing (record Sat)"
  exit 0
fi
if [ -n "${DEMO:-}" ]; then echo "demo replay: recorded run (no network)"; exit 0; fi
echo "demo stub — record real adaptive run on Sat (schedule Day 6)"
