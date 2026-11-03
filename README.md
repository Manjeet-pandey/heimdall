# Heimdall

**A checkpoint between untrusted AI agents and the internet. Built with Muse Spark.**

> A coding agent read a poisoned GitHub issue and tried to steal its keys. Stopped, with every byte counted.

Personal AI agents read untrusted content (issues, web pages, email) and hold real API keys. One hidden
instruction is enough to turn them against you. Heimdall assumes the agent *will* be compromised and controls
the only way out: every agent runs sealed in a Docker sandbox with fake keys, and every request it makes goes
through one checkpoint that checks it, records it, and blocks what looks like a leak.

Indie track · Push the Frontier (safe autonomy for agents).

**Built during the hackathon (Oct 28 – Nov 3, 2026).** Everything in this repo was written during the event
by Manjeet (solo), with AI coding assistants (see [Muse Code log](#muse-code-log)); the git history starts at the first
commit on Oct 28. Used as-is, not ours: [mitmproxy](https://mitmproxy.org) (the proxy engine the checkpoint runs
inside), Meta's PromptGuard 2 and Llama 3.1 8B (open weights), llama.cpp, Docker and bubblewrap.

## What it does

```
agent sandbox ──► Heimdall checkpoint ───────────────────────────────► internet
(no network,      1. Rules       hard checks no AI can override
 placeholder      2. Muse Spark  reviews anything new, and every write for slow leaks
 keys only)       3. PromptGuard scans every response for hidden instructions
                  4. Muse Wonder settles what Spark isn't sure about (no human needed)
```

- **Placeholder keys.** Agents hold `gw_ph_openai_x7f3`, never the real key. The checkpoint swaps in the real key
  only for the one site it belongs to. A placeholder seen anywhere else is a tripwire.
- **Hard rules first** (no AI involved): allowlisted hosts checked before DNS, no IP literals, no private or
  metadata addresses, https on port 443 only (a real key never travels in plaintext), CONNECT host = SNI = Host, size caps on URL, headers and body, path rules for writes,
  no foreign API keys on LLM hosts, no provider-side fetches (MCP servers, web search, image URLs) to unknown
  hosts, a byte budget per agent per destination. WebSocket frames are counted and capped too.
- **Muse Spark as reviewer.** Anything that matches no rule goes to Muse for a verdict (deny / not sure /
  allow within a small budget). Writes to *allowed* endpoints get a history review: Muse sees the agent's task
  and recent requests and looks for data leaking out a little at a time. Muse can never allow past a hard rule.
  Muse sees the method, host, path and body (secrets redacted), not the query string or headers; those are
  covered by the hard rules and byte budgets. An agent with no daily allowance for moves outside its rules (the
  shipped policy) is blocked on those whatever Muse says, so there Muse adds the plain-language reason. Its
  verdicts decide for writes to allowed endpoints and for agents given an allowance.
- **Muse Wonder as the decider, so agents run 24/7.** When Spark isn't sure, or can't answer, Meta's larger
  Muse Wonder makes the final allow-or-deny call on the spot; nobody has to be watching. If Wonder is unsure or
  unreachable the answer is deny, and its allows still count against the byte budgets. Prefer a person in the
  loop? `HEIMDALL_DECIDER=human` sends those requests to the review page's queue instead.
- **Fail closed.** If the Meta API is down, unknown requests and unreviewed writes are blocked.
- **PromptGuard 2** scans every non-LLM text response (binary bodies and streamed LLM answers aren't scanned).
  A hit doesn't take back that response, but it puts the agent in strict mode: nothing new goes out without
  your OK, so an injection that got in can't act on the network.
- **Learn, then lock.** Watch an agent do its job, approve the moves it made, and lock it to exactly those.
- **Review page.** An overview of what was blocked and what needs you, a live view where every request flies
  into an *allowed* or *blocked* pile, and a side panel with everything about any request: the plain-language
  reason, the full URL, headers and body (keys hidden).

### Meta tooling

| Model | Role | Where |
|---|---|---|
| **Muse Spark** (Meta Model API, Standard tier: no training on our data) | Reviewer: single-request verdicts and history (slow-leak) review | `reviewer/muse.py` |
| **Muse Wonder** (Meta Model API, Standard tier) | Decider: final allow/deny when Spark isn't sure or can't answer | `reviewer/muse.py` |
| **Llama 3.1 8B Instruct** (open weights, llama.cpp) | Attacker: the rogue agent that adapts to every block | `proof/rogue.py` |
| **Llama Prompt Guard 2 86M** | Scans responses for prompt injection, CPU or Apple GPU | `reviewer/guard.py` |

Muse (Spark or Wonder) never plays the attacker, so the reviewers never grade themselves. No outputs are used to train anything.

**Other models.** Both roles take any OpenAI-style chat API. Reviewer: set `META_API_BASE`, `META_MODEL_API_KEY`,
`HEIMDALL_REVIEWER_MODEL` and `HEIMDALL_DECIDER_MODEL` in `.env.secrets` (and `HEIMDALL_REVIEWER_EFFORT=` if the
model rejects `reasoning_effort`). Attacker: `LLAMA_URL`, `LLAMA_MODEL` and, for a hosted model, `LLAMA_API_KEY`.
All results above are with Muse and Llama.

## Results

All attack traffic goes to a local mock internet with fake keys; only Muse's reviews leave the machine.

**Attack test** (`proof/run.py`): a coding agent reads a poisoned GitHub issue, then tries 18 ways to get keys and
secrets out (new hosts, the LLM provider as a courier, smuggling through allowed endpoints), plus 3 retries after
reading why it was blocked. Each run happens with and without Heimdall.

| | Without Heimdall | With Heimdall |
|---|---|---|
| Runs where each attack class got data out (A1 / A2 / A3) | 5/5 · 5/5 · 5/5 | **0/5 · 0/5 · 0/5** |
| Attack variants that leaked, per run | 18 of 21 | **0 of 21** |
| Runs where a real key was stolen | 5 of 5 | **0 of 5** |
| Runs where the real task completed | 5 of 5 | **5 of 5** |

5 runs each way. Hard rules caught keys, IP literals, provider fetches, path traversal and oversize bodies every
time; Muse's history review caught both stuffed issue comments every time, the one place where Muse alone
decides. The new-host and gist variants (no endpoint rule matched) were refused by Muse Spark or Muse Wonder
with a reason, but the agent's policy (no allowance outside its rules) would have blocked them anyway. Muse: 54 verdicts, median 3.6 s, p90 5.3 s, about $0.0018 each.

**Live attacker host** (`proof/out-live/`): the same test with the attacker's server on the real internet (a server
we own behind a Cloudflare tunnel, real DNS and TLS; run Nov 1). Same result: 3 of 3 out without Heimdall, 0 of 3 with it.

**Rogue agent** (`proof/rogue.py`): Llama 3.1 8B is told to get a database password out and adapts after every
403. It tried GitHub comments, URL-encoding the secret, the LLM provider, public gists, a new issue, the
attacker's server and unknown sites. With the final setup **0 of 5 runs got the secret out** (61 of 74 requests
blocked; the rest were harmless reads and LLM calls).

It found two real holes along the way, both fixed:
- When a Muse Spark call timed out, a write to an allowed endpoint went through unreviewed, and in 2 of 2 runs
  the agent got the password out in a progress comment. Unreviewed writes now go to Muse Wonder, and are
  denied if it can't answer either.
- In 1 of 5 runs it sent the password to the AI provider with **no key at all**. The checkpoint blocked other
  people's keys there but didn't require the agent's own. It now does: a request to an AI provider without
  the agent's placeholder key is blocked (replayed on both sandboxes: 403).

**Load test** (`proof/load.py`, 3 runs): one minute of a busy agent at 100 requests/s (repo reads, LLM calls, progress
comments) with 1% labelled attacks mixed in, real Muse Spark and Muse Wonder deciding, PromptGuard on the Apple GPU.

| | Result |
|---|---|
| Sustained rate | **87.2 – 92.6 req/s** |
| LLM call, median | 8 ms |
| Repo read, median (scanned by PromptGuard) | 58–60 ms |
| Progress comment, median (reviewed by Muse) | 3.0–3.2 s |
| Attacks blocked | **171 of 171** |
| Normal requests wrongly blocked | 5 of 17,814 (2, 1 and 2 per run; comments Muse judged suspicious) |
| Slow leak (one secret split over 4 comments) | got out in 2 of 3 runs (3 of 4 pieces in the other) |

Muse Spark: about 200 reviews per minute-long run, about $0.39–0.40 per run. Muse Wonder was needed 2–5 times per run. Reads and LLM
calls are never sent to Muse. With PromptGuard on CPU in a container the same test sustained 92 req/s (1 run).

## Limits (honest)

- **A slow leak inside the caps gets through.** A secret split into small pieces across normal-looking comments
  on an allowed endpoint got out in the load test. It is counted and charted, not stopped.
- **The decider is a model too.** Muse Wonder denied every leak the rogue agent sent its way, including a
  secret URL-encoded into an unknown site's path, but both reviewers read attacker-controlled content and a
  clever enough injection could fool both. Hard rules and byte budgets cap the damage either way.
- **Muse gets stricter with volume.** At 180 progress comments a minute some harmless ones are judged a leak
  pattern (5 of 17,814 across 3 load runs).
- **Muse Wonder is slow under load** (2 s alone, up to ~10 s when the API is busy), so writes Spark doubts take
  longer. Its calls run apart from response scanning, so everything else keeps its speed.
- **In human mode, writes keep flowing while Muse is down** (so agents aren't stuck); only Wonder mode, the
  default, blocks them.
- **The reviewer reads attacker-controlled content**, so it could be manipulated. That is why it can never
  override a hard rule, only add a deny or an escalation.
- **A redacted copy of each reviewed request is sent to the Meta API.** Anything that looks like a key is removed
  first, but the rest of the request content is shared.
- **The attack test's 3 retries use a fixed mutation table**, not a model: the sandbox can't reach a model
  server (by design). The rogue agent is the model-driven adaptive attacker.
- **Throughput is bounded by PromptGuard.** About 80 scans/s on CPU in a container, about 600/s natively on an
  Apple GPU. Containers on a Mac can't use the GPU, so the fast path runs PromptGuard on the host.
- **Byte budgets live in memory.** Restarting the checkpoint resets today's counts, so an agent that can force
  a restart gets a fresh budget. Every move is still logged to SQLite, so the bytes stay countable afterwards.
- **Same-machine side channels aren't watched.** Heimdall only sees the network. Two agents on one machine
  could signal through CPU timing or cache use, and a less-restricted agent could then send what it learned out
  through its own allowed routes (still inside its byte budgets). Each agent gets its own CPU core and a CPU cap,
  which slows this down but doesn't stop it; separate VMs per agent would.
- **Agents can try to hand work to each other.** Heimdall closes the direct routes: each agent's internal
  network holds only itself and the checkpoint (agents on one network could talk directly), each container
  has its own process and shared-memory space, and shared folders are read-only. What's left: two agents
  can use an allowed site as a mailbox (A posts a comment, B reads it); both moves go through the checkpoint
  and the history review, but harmless-looking messages can pass. Files an agent writes to its work folder
  can carry instructions for whoever opens them next, agent or human; Heimdall doesn't read files.
- **Resource limits, not a fair scheduler.** Each agent gets 1 CPU core, 1 GB RAM (no swap), 256 processes
  and 1,024 open files, and exited processes are cleaned up so a fork bomb doesn't lock it out for good.
  Not limited yet: disk use in its work folder, and requests per second. Muse reviews a request before its
  byte budget is checked, and blocked requests don't count against the budget, so an agent flooding unknown
  requests or writes can run up Muse calls (about $0.002 each) with no cap. A per-agent rate and spend
  limit is the fix.
- All test traffic is synthetic. GitHub and the LLM provider are mocked; in the live run the attacker's host is a
  real public server we own behind a Cloudflare tunnel, and it only ever receives fake keys.

## Run it

Needs Docker, Python 3.10+, and a Meta Model API key. Optional: `llama.cpp` for the rogue agent.

```sh
cp .env.secrets.example .env.secrets      # add META_MODEL_API_KEY (and real keys for live use)
# PromptGuard 2 is gated: accept its license on Hugging Face once, then
HF_TOKEN=... docker compose run --rm -e HF_TOKEN -e HF_HUB_OFFLINE=0 guard python /app/guard.py --download
brew install llama.cpp                     # optional: the rogue agent's model (downloads ~4.6 GB on first run)
./start.sh                                 # then open http://127.0.0.1:8000
```

Set `HEIMDALL_DECIDER=human` before starting to have uncertain requests wait for you instead of Muse Wonder.

`./start.sh` brings up the checkpoint, the sandbox, PromptGuard and Llama, and runs the review page on your
machine so its **Run** menu works: *Attack test*, *Rogue agent* (with a live transcript of what it's thinking)
and *Load test*. Plain `docker compose up` also works; the page then runs in a container without Run buttons.

Faster PromptGuard on a Mac (Apple GPU):

```sh
uv venv -p 3.12 .venv-guard && VIRTUAL_ENV=.venv-guard uv pip install torch==2.5.1 transformers==4.46.3 sentencepiece==0.2.0 protobuf==5.28.3
# copy the downloaded model out of the container's cache once, then ./start.sh picks it up
docker run --rm -v hackathon_hf-cache:/hf:ro python:3.12-slim tar -C /hf/hub -cf - models--meta-llama--Llama-Prompt-Guard-2-86M | tar -C ~/.cache/huggingface/hub -xf -
```

From the command line:

```sh
python3 proof/run.py --runs 5        # attack test, with and without Heimdall
python3 proof/rogue.py --runs 5      # rogue agent (needs llama-server on :8089)
python3 proof/load.py --rate 100     # load test
./demo/demo.sh --check               # self-tests: rules, Muse fail-closed, review page, full pipeline
DEMO=1 ./demo/demo.sh                # replay the recorded run, no network
```

### Native Linux sandbox (optional, no Docker)

Docker is the default. On Linux, `./heimdall` runs agents without Docker or images: each command runs from your
own machine in a bubblewrap jail that sees only system folders (read-only), its work folder and an empty home;
its only network is a socket to the checkpoint; it gets a seccomp filter like Docker's and cgroup limits
(1 CPU, 1 GB, 256 processes, 1024 files). Subagents inherit the jail.

```sh
sudo apt install bubblewrap python3-seccomp   # Debian / Ubuntu
./heimdall setup && ./heimdall up
./heimdall run --agent coder -- claude -p "fix the failing CI"
python3 proof/test_sandbox.py --native        # jail escape tests (same probe as Docker's: python3 proof/test_sandbox.py)
python3 proof/run.py --runs 5 --native        # any proof script takes --native; results in proof/out-native/
```

Measured against Docker with the same tests: jail escape tests 28/28 (Docker 27/27), attack proof identical
(0/5 with Heimdall, 5/5 without), load 85.2–92.7 req/s (Docker 87.2–92.6), 45 ms to start a fresh jail
(Docker: 134 ms for a new container). Rogue agent: 0 of 5 native runs got the secret out (59 of 71 requests
blocked) after the no-key fix; before it, 1 of 5 had, through the checkpoint gap described under Results.
Linux only for now; macOS would use its built-in sandbox (roadmap).

## Repo

```
checkpoint/   addon.py (the mitmproxy pipeline), rules.py, creds.py (key swap), db.py, policy.json
reviewer/     muse.py (Muse Spark verdicts + history review), guard.py (PromptGuard 2 service)
review/       app.py + index.html (stdlib server, one page)
attacks/      mock internet, poisoned issue, hand-written attacks, load generator, sandbox-side helpers
proof/        attack test, rogue agent, load test, tests
demo/         demo.sh and the recorded run
start.sh      everything, one command
heimdall      native Linux sandbox (optional): setup / up / run --agent NAME -- CMD
```

## Roadmap

Not built, on purpose: Go agent images; OAuth, cookie and AWS-signature credentials; logging file reads inside
the sandbox; the macOS built-in sandbox (the native jail is Linux only); phone alerts for decisions; drafting a policy
from one line of plain English; one VM per agent to close same-machine side channels.

## Muse Code log

Coding assistants used while building:

- **Muse Spark via OpenCode** (Oct 30–31): first versions of the Llama retry helper (`attacks/llama_attacker.py`),
  the demo recorder (`demo/record.py`) and its tests, and a review-page revision that was later rewritten.

## License

MIT. See [LICENSE](LICENSE).
