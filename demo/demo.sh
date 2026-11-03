#!/bin/sh
# Demo: record the real run, or replay it with no network.
#   ./demo.sh           record a fresh run (needs mitmproxy; writes demo/recorded/)
#   DEMO=1 ./demo.sh    replay the recording (local file reads only, no network)
#   ./demo.sh --check   backstage validation; reports problems but the replay below
#                       never refuses to start on stage (it only reads local files).
set -eu
cd "$(dirname "$0")/.."
missing=""
for f in docker-compose.yml checkpoint/policy.json checkpoint/addon.py checkpoint/rules.py reviewer/muse.py attacks/llama_attacker.py proof/test_rules.py proof/test_llama.py proof/test_llama_e2e.py demo/record.py; do
  [ -f "$f" ] || missing="$missing $f"
done
if [ "${1:-}" = "--check" ]; then
  if [ -n "$missing" ]; then echo "check FAIL, missing:$missing"; exit 1; fi
  python3 proof/test_rules.py >/dev/null && echo "check OK: compose, rules, reviewer, tests pass" || { echo "check FAIL: test_rules failed"; exit 1; }
  python3 proof/test_muse.py >/dev/null && echo "check OK: Muse reviewer fail-closed" || { echo "check FAIL: test_muse failed"; exit 1; }
  python3 proof/test_review.py >/dev/null && echo "check OK: review page guards, decisions, learn/lock" || { echo "check FAIL: test_review failed"; exit 1; }
  python3 proof/test_llama.py >/dev/null && echo "check OK: Llama adaptive attacker (1-round)" || { echo "check FAIL: test_llama failed"; exit 1; }
  if python3 -c "import mitmproxy" 2>/dev/null; then
    python3 proof/test_addon.py >/dev/null && echo "check OK: full pipeline" || { echo "check FAIL: test_addon failed"; exit 1; }
    python3 proof/test_llama_e2e.py >/dev/null && echo "check OK: adaptive attacker e2e (mock + pipeline)" || { echo "check FAIL: test_llama_e2e failed"; exit 1; }
  elif docker image inspect mitmproxy/mitmproxy:11 >/dev/null 2>&1; then
    # No mitmproxy on the host (the Mac): run the pipeline tests in the checkpoint's own image.
    run_mitm() { docker run --rm -v "$PWD":/app -w /app -e PYTHONPATH=/app --entrypoint python3 mitmproxy/mitmproxy:11 "$@" >/dev/null; }
    run_mitm proof/test_addon.py && echo "check OK: full pipeline (in mitmproxy image)" || { echo "check FAIL: test_addon failed"; exit 1; }
    run_mitm proof/test_llama_e2e.py && echo "check OK: adaptive attacker e2e (in mitmproxy image)" || { echo "check FAIL: test_llama_e2e failed"; exit 1; }
  else
    echo "check WARN: mitmproxy not installed, pipeline tests skipped (pip install 'mitmproxy>=11,<12' to run proof/test_addon.py proof/test_llama_e2e.py)"
  fi
  if [ -d demo/recorded ] && [ -f demo/recorded/transcript.txt ] && [ -f demo/recorded/summary.json ]; then
    python3 -c "
import json
moves = [json.loads(l) for l in open('demo/recorded/moves.jsonl')]
attacks = [m for m in moves if m['attack'] != 'task']
assert attacks and all(m['status'] == 403 for m in attacks), 'attack step not blocked'
s = json.load(open('demo/recorded/summary.json'))
assert s['canaries_leaked'] == [], 'canary leaked in recording'
blob = open('demo/recorded/transcript.txt').read() + open('demo/recorded/moves.jsonl').read()
assert 'sk-e2e-not-real' not in blob and 'ghp_e2e_not_real' not in blob, 'secret in recording'
assert s.get('rogue', {}).get('leaked', 0) == 0, 'rogue run leaked in recording'
assert s.get('load', {}).get('attacks_leaked', 0) == 0, 'load attack leaked in recording'
for k in ('rogue', 'load'):
    if k not in s: print('check WARN: no %s section in recording (run the proofs, then ./demo.sh)' % k)
print('check OK: demo recording (%d steps, %d/%d attack steps blocked, muse_live=%s)' % (
    s['steps'], s['attack_blocked'], s['attack_steps'], s['muse_live']))
" || { echo "check FAIL: demo/recorded invalid"; exit 1; }
  else
    echo "check WARN: demo/recorded missing (run ./demo.sh to record)"
  fi
  exit 0
fi
if [ -n "${DEMO:-}" ]; then
  # Replay: local file reads only. Never refuses to start: fall back to the
  # summary line if the transcript is missing.
  if [ -f demo/recorded/transcript.txt ]; then cat demo/recorded/transcript.txt; else
    echo "demo replay: no recording found (run ./demo.sh backstage to record)"
  fi
  exit 0
fi
exec python3 demo/record.py
