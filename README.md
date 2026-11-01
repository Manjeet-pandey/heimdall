# Heimdall

**A checkpoint between untrusted AI agents and the internet. Built with Muse Spark.**

> A coding agent read a poisoned GitHub issue and tried to steal its keys. Stopped, with every byte counted.

Personal AI agents read untrusted content (issues, web pages, email) and hold real API keys. One hidden
instruction is enough to turn them against you. Heimdall assumes the agent *will* be compromised and controls
the only way out: every agent runs sealed in a Docker sandbox with fake keys, and every request it makes goes
through one checkpoint that checks it, records it, and blocks what looks like a leak.

Indie track · Push the Frontier (safe autonomy for agents).

## What it does

```
agent sandbox ──► Heimdall checkpoint ───────────────────────────────► internet
(no network,      1. Rules       hard checks no AI can override
 placeholder      2. Muse Spark  reviews anything new, and every write for slow leaks
 keys only)       3. PromptGuard scans every response for hidden instructions
                  4. You         decide what Muse isn't sure about
```

- **Placeholder keys.** Agents hold `gw_ph_openai_x7f3`, never the real key. The checkpoint swaps in the real key
  only for the one site it belongs to. A placeholder seen anywhere else is a tripwire.
- **Hard rules first** (no AI involved): allowlisted hosts checked before DNS, no IP literals, no private or
  metadata addresses, CONNECT host = SNI = Host, size caps on URL, headers and body, path rules for writes,
  no foreign API keys on LLM hosts, no provider-side fetches (MCP servers, web search, image URLs) to unknown
  hosts, a byte budget per agent per destination. WebSocket frames are counted and capped too.
- **Muse Spark as reviewer.** Anything that matches no rule goes to Muse for a verdict (deny / escalate to you /
  allow within a small budget). Writes to *allowed* endpoints get a history review: Muse sees the agent's task
  and recent requests and looks for data leaking out a little at a time. Muse can only deny or escalate past a
  hard rule, never allow. If the Meta API is down, the checkpoint fails closed: unknown requests are blocked.
- **PromptGuard 2** scans every non-LLM response before the agent sees it. A hit puts the agent in strict mode:
  nothing new goes out without your OK.
- **Learn, then lock.** Watch an agent do its job, approve the moves it made, and lock it to exactly those.
- **Review page.** An overview of what was blocked and what needs you, a live view where every request flies
  into an *allowed* or *blocked* pile, and a side panel with everything about any request: the plain-language
  reason, the full URL, headers and body (keys hidden).

### Meta tooling

| Model | Role | Where |
|---|---|---|
| **Muse Spark** (Meta Model API, Standard tier: no training on our data) | Reviewer: single-request verdicts and history (slow-leak) review | `reviewer/muse.py` |
| **Llama 3.1 8B Instruct** (open weights, llama.cpp) | Attacker: the rogue agent that adapts to every block | `proof/rogue.py` |
| **Llama Prompt Guard 2 86M** | Scans responses for prompt injection, CPU or Apple GPU | `reviewer/guard.py` |

Muse never plays the attacker, so the reviewer never grades itself. No outputs are used to train anything.

## Results

All attack traffic goes to a local mock internet with fake keys; only Muse's reviews leave the machine.

**Attack test** (`proof/run.py`): a coding agent reads a poisoned GitHub issue, then tries 18 ways to get keys and
secrets out (new hosts, the LLM provider as a courier, smuggling through allowed endpoints), plus 3 retries after
reading why it was blocked. Each run happens with and without Heimdall.

| | Without Heimdall | With Heimdall |
|---|---|---|
| Attack classes that got data out | 3 of 3 | **0 of 3** |
| Real key stolen | yes | **no** |
| Real task completed | yes | **yes** |

*(1 run each way so far; the 5-run proof is scheduled before submission.)*

**Rogue agent** (`proof/rogue.py`): Llama 3.1 8B is told to get a database password out and adapts after every
403. It tried GitHub comments, URL-encoding the secret, the LLM provider, public gists, the attacker's server and
unknown sites. **0 of 4 runs got the secret out**; 40 of 52 of its requests were blocked (the rest were harmless
reads and LLM calls).

**Load test** (`proof/load.py`): one minute of a busy agent at 100 requests/s (repo reads, LLM calls, progress
comments) with 1% labelled attacks mixed in, real Muse reviewing.

| | PromptGuard on CPU (container) | PromptGuard on Apple GPU |
|---|---|---|
| Sustained rate | 66.8 req/s | **93.2 req/s** |
| LLM call, median / p95 | 504 / 788 ms | **7 / 236 ms** |
| Repo read, median / p95 | 1,065 / 1,339 ms | **56 / 539 ms** |
| Attacks blocked | 58 of 58 | **57 of 57** |
| Normal requests wrongly blocked | 2 of 5,938 | 9 of 5,938 |
| Slow leak (one secret split over 4 comments) | got out | got out |

Muse: median ~2 s per verdict, about $0.0018 each; under load about $0.39 per minute (only writes and unknown
destinations are reviewed, so reads and LLM calls cost nothing).

## Limits (honest)

- **A slow leak inside the caps gets through.** A secret split into small pieces across normal-looking comments
  on an allowed endpoint got out in the load test. It is counted and charted, not stopped.
- **Muse sometimes escalates instead of denying.** The rogue agent URL-encoded the secret into an unknown site's
  path; Muse wasn't sure and sent it to the human queue. It stays blocked until someone clicks *Allow once*, so a
  careless approval would leak it.
- **Muse gets stricter with volume.** At 180 progress comments a minute the history review starts blocking some
  harmless ones as a leak pattern (9 of 5,938 in the load test).
- **The reviewer reads attacker-controlled content**, so it could be manipulated. That is why it can never
  override a hard rule, only add a deny or an escalation.
- **A redacted copy of each reviewed request is sent to the Meta API.** Anything that looks like a key is removed
  first, but the rest of the request content is shared.
- **The attack test's 3 retries use a fixed mutation table**, not a model: the sandbox can't reach a model
  server (by design). The rogue agent is the model-driven adaptive attacker.
- **Throughput is bounded by PromptGuard.** About 80 scans/s on CPU in a container, about 600/s natively on an
  Apple GPU. Containers on a Mac can't use the GPU, so the fast path runs PromptGuard on the host.
- All test traffic is synthetic and every test uses a mock internet.

## Run it

Needs Docker, Python 3.10+, and a Meta Model API key. Optional: `llama.cpp` for the rogue agent.

```sh
cp .env.secrets.example .env.secrets      # add META_MODEL_API_KEY (and real keys for live use)
# PromptGuard 2 is gated: accept its license on Hugging Face once, then
HF_TOKEN=... docker compose run --rm -e HF_TOKEN -e HF_HUB_OFFLINE=0 guard python /app/guard.py --download
brew install llama.cpp                     # optional: the rogue agent's model (downloads ~4.6 GB on first run)
./start.sh                                 # then open http://127.0.0.1:8000
```

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

## Repo

```
checkpoint/   addon.py (the mitmproxy pipeline), rules.py, creds.py (key swap), db.py, policy.json
reviewer/     muse.py (Muse Spark verdicts + history review), guard.py (PromptGuard 2 service)
review/       app.py + index.html (stdlib server, one page)
attacks/      mock internet, poisoned issue, hand-written attacks, load generator, sandbox-side helpers
proof/        attack test, rogue agent, load test, tests
demo/         demo.sh and the recorded run
start.sh      everything, one command
```

## Roadmap

Not built, on purpose: Go agent images; OAuth, cookie and AWS-signature credentials; logging file reads inside
the sandbox; bubblewrap instead of Docker for lighter sandboxes; phone alerts for decisions; drafting a policy
from one line of plain English.

## Muse Code log

Coding assistants used while building, as the rules require:

- **Muse Spark via OpenCode** (Oct 30–31): first versions of the Llama retry helper (`attacks/llama_attacker.py`),
  the demo recorder (`demo/record.py`) and its tests, and a review-page revision that was later rewritten.
- *(add any other Muse Code sessions here before submitting)*

## License

MIT. See [LICENSE](LICENSE).
