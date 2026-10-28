# CHECKPOINT — handoff log (update after every work block)

## 2026-10-28 — decisions locked (do NOT re-ask)
1. Theme = Push the Frontier (software: safe autonomy). Why: Build for Your World requires a firsthand problem; user confirmed this is not their daily pain (no 24/7 agents, no real leak). Push fits without dogfood.
2. No distillation, no training on Muse outputs. Why: user decision 2026-10-27; avoids Credit Terms risk. Plan B is the plan: Muse single-move verdicts + history slow-leak review, fail-closed when API down. Removed `reviewer/local.py`, no LoRA/Modal work.
3. No false dogfood. Why: user has no always-on AI, no leak numbers. Leak cost in plan is an illustrative scenario (e.g. $50 cap), video must label it as scenario. Proof uses demo-agent traffic Oct 27–Nov 1 (synthetic), never "my traffic".
4. Standard tier ($150, no training on our data). Why: Contributor ($0.10) lets Meta train on prompts + 100 RPM kills proof runs.
5. Cut: morning summary, ntfy (toast only), PromptGuard dial, Pipelock, latency table, OAuth/cookies, k8s, file-read logging. Cut order: review polish → adaptive 3→1 → second image.

## Built so far (verified `py_compile` OK 2026-10-27)
- compose: internal net, no DNS, checkpoint + coder (non-root, ro rootfs, CA env vars).
- checkpoint/rules.py: dest check (pre-DNS, IP-literal refuse), private-deny helper, key checks (placeholder tripwire + foreign-key block).
- checkpoint/creds.py (header-only swap), db.py (SQLite moves log), addon.py (403 + log skeleton).
- reviewer/muse.py stub, review/app.py `/health`, review/index.html stub, demo/demo.sh stub, proof/run.py stub.
- MIT, .gitignore, .env.secrets.example, README skeleton.

## Next: Wed Oct 28 (Day 3 due) — DONE 2026-10-28
- [x] Provider-side tool block, endpoint rules, byte counting, foreign-key in 5 spots.
- [x] Test harness `proof/test_rules.py`: ALL PASS.
- [x] Muse reviewer stub: quoted/redacted input, body-less cache, history review, offline escalate (fail-closed). Import verified.
- [x] Full pipeline in `checkpoint/addon.py`: dest → keys → provider-fetch → endpoint → budget → reviewer.
- [x] `./demo/demo.sh --check` passes (WARN only: demo/recorded until Sat).

## Open (user only)
- None for agents. Leak scenario numbers stay illustrative unless user pastes reals.

## File map
- Truth: hackathon-plan.html. Contract: AGENTS.md. Log: this file.
- Code: checkpoint/, reviewer/muse.py, review/, attacks/, proof/, demo/, docker-compose.yml.
