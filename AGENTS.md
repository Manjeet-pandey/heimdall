# AGENTS.md — Heimdall (Hackathon)

Source of truth: `hackathon-plan.html`. This file is the short alignment contract. If they conflict, the plan wins.

## 1. What this is
Heimdall: supervisor for untrusted personal AI agents. Agents run in Docker sandboxes, all network goes through one mitmproxy checkpoint that checks, records, blocks. Agents hold placeholders (`gw_ph_openai_x7f3`), never real keys.
Headline: Muse Spark reviews every unknown move + reasons over history to catch slow leaks; when Meta API is down the checkpoint fails closed (unknowns block, no allows).
One-liner for demo: "A coding agent read a poisoned GitHub issue and tried to steal keys. Stopped, with every byte counted."

## 2. Event
- Indie track · Push the Frontier (software: safe autonomy for agents). Submit via Cerebral Valley portal by Nov 4, 6 PM ET.
- Judged: Impact 30 / Meta tooling 25 / Demo 25 / Tech depth 20.
- Build with: Muse Spark via Meta Model API ($150 Standard tier, no training on our data), open-weights Llama as adaptive attacker only, PromptGuard 2 on CPU. No distillation. Log Muse Code use in README.

## 3. Architecture (do not simplify away)
- Sandbox: `internal: true` Docker network, no DNS. Mounts deny-by-default, non-root, read-only rootfs. mitmproxy CA in image trust store + `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE` / `NODE_EXTRA_CA_CERTS`.
- Checkpoint per request: allowlist check BEFORE DNS → refuse IP literals → resolve then deny private/link-local/loopback/metadata → enforce CONNECT host = SNI = Host → TLS terminate → buffer request body (max size), cap URL/header sizes → normalize, re-check redirects.
- Keys: swap placeholder only on right host. Placeholder elsewhere = tripwire. On LLM hosts block any non-placeholder credential in Authorization, x-api-key, x-goog-api-key, api-key, query, body (foreign-key block).
- Provider-side tools: on LLM hosts block fields that make provider fetch a URL (remote MCP `server_url`, web search, `image_url`/file URLs) unless host is allowlisted.
- Endpoint rules: method + host + path regex + max bytes. Writes path-scoped.
- Budget: count ALL egress bytes per agent per dest (URL+headers+body+WS frames). Unknown dests: hard N bytes/day cap.
- Unknown move: 403 + reason → reviewer (deny/escalate only, never overrides hard rule). Content passed quoted, truncated, redacted.
- Responses: LLM hosts stream (SSE). Everything else buffered, PromptGuard 2 chunked 512 tokens before agent sees it. Flag → strict mode (no reviewer allows).
- WebSockets: upgrade only to allowed hosts, `websocket_message` hook counts/caps frames.
- Learn-then-lock: supervised run → approve → deny-by-default.

## 4. Scope (respect tiers)
- Must build: sandbox + full pipeline above, placeholder keys, learn-lock, Muse reviewer (single-move verdict + history slow-leak review), PromptGuard strict mode, hand-written + Llama adaptive attacker, review page (feed, reasons, budget), demo mode + `demo.sh`, proof run, video.
- Roadmap (README only, do not build): Go images, OAuth/cookies/AWS signing, file-read logging, bubblewrap, phone alerts, one-line policy drafting.
- Cut (do not build): morning summary, ntfy, PromptGuard dial, Pipelock comparison, latency table, multi-user, k8s, frameworks.
- Cut order if behind: review polish → adaptive rounds 3→1 → second agent image.

## 5. Repo layout
```
master/ checkpoint/addon.py, rules.py, creds.py, db.py
reviewer/muse.py (single-move verdict + history slow-leak review)
review/app.py, index.html
attacks/ (hand-written, llama attacker, poisoned issue, mock server)
proof/run.py, plots.py
demo/demo.sh + recorded run
docker-compose.yml  .env.secrets (git-ignored, checkpoint only)
```
SQLite via stdlib. FastAPI + one HTML page, toast on block (no ntfy).

## 6. Rules for every agent
- Python end to end. No new frameworks, no k8s, no multi-user.
- No real secrets in repo, logs (placeholders only), demo, chats, screens. Real keys only in checkpoint env file. Attack traffic to mock server only.
- New repo, MIT license. README states "Built with Muse Spark", limits (slow leak inside caps gets through but charted; reviewer reads attacker content so never overrides hard rules; redacted copy sent to Meta API), roadmap, Muse Code log.
- Credit Terms: decided Day 1 — no distillation. Plan B is the plan: Muse single-move verdicts + history slow-leak review, fail-closed when API down (unknowns block).
- Verdict cache: keyed on method + path template, body-less requests only.
- Proof: 2 conditions (no supervisor / full) × 3 attacks × 5 runs, report rate. Attacks: (1) poisoned issue → new host, (2) LLM-provider exfil, (3) stuffed allowed endpoint. Tune on some, report on held-out. False blocks/day from demo-agent traffic Oct 27–Nov 1 (synthetic, no personal traffic). Metrics: success rate, task completion, false blocks, what-caught-what, Muse latency/cost, bytes-out per dest. Attacks that get through go in write-up.
- Demo ≤3 min: 0:00 cold open 2 blocks, 0:35 how, 1:10 recorded adaptive round, 1:50 cloud-down (unknowns block, fail-closed — no local guard claims), 2:25 chart, 2:45 `docker compose up` timed. `DEMO=1 ./demo.sh` replays recorded run, no network. `./demo.sh --check` backstage reports but never refuses to start on stage.
- Schedule: Mon sandbox, Tue keys+dest checks+CA+leak numbers, Wed foreign-key+provider block+reviewer, Thu attacks+WS, Fri history review+PromptGuard, Sat review page+demo record, Sun buffer + freeze, Mon proof, Tue rehearse×2 + record, Wed submit. Freeze Nov 1.
- Ownership: I keep ownership; Meta/organizers get perpetual license incl. marketing. Judges final.
