#!/bin/sh
# One command: the Heimdall stack, the rogue agent's Llama, a fast PromptGuard, and the review page with working
# Run buttons. Open the page it prints (http://127.0.0.1:8000). Ctrl-C stops what this script started.
#   ./start.sh
# Reuses anything already running on its port (llama-server on 8089, PromptGuard on 8002).
set -eu
cd "$(dirname "$0")"
started=""
wait_for=""
cleanup() { [ -n "$started" ] && kill $started 2>/dev/null; exit 0; }
trap cleanup INT TERM
up() { curl -s -m 2 -o /dev/null "$1"; }
mkdir -p data

# The review page needs Python 3.10+ (macOS's /usr/bin/python3 is 3.9).
PY=""
for p in python3.13 python3.12 python3.11 python3.10 python3; do
  if command -v "$p" >/dev/null && "$p" -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then PY=$p; break; fi
done
[ -n "$PY" ] || { echo "Need Python 3.10 or newer (brew install python@3.12)."; exit 1; }
PORT=${REVIEW_PORT:-8000}
if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN 2>/dev/null | grep -Eqv "^COMMAND|com\.docke"; then
  echo "Port $PORT is in use by another program (an older review page?). Stop it, or run REVIEW_PORT=8010 ./start.sh"; exit 1
fi
docker info >/dev/null 2>&1 || { echo "Docker isn't running. Start Docker and try again."; exit 1; }
[ -f .env.secrets ] || { echo "No .env.secrets: copy .env.secrets.example and add your keys (META_MODEL_API_KEY for Muse)."; exit 1; }

# 1. Llama 3.1 8B for the rogue agent (llama.cpp). Local GGUF if we have one, else llama.cpp downloads it once.
if up http://127.0.0.1:8089/health; then
  echo "llama: already running on 8089"
elif command -v llama-server >/dev/null; then
  gguf=${LLAMA_GGUF:-$(ls ~/.cache/huggingface/hub/models--bartowski--Meta-Llama-3.1-8B-Instruct-GGUF/snapshots/*/Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf 2>/dev/null | head -1)}
  if [ -n "$gguf" ]; then model="-m $gguf"; else model="-hf bartowski/Meta-Llama-3.1-8B-Instruct-GGUF:Q4_K_M"; echo "llama: first run downloads ~4.6 GB"; fi
  # shellcheck disable=SC2086
  llama-server $model --alias llama3.1-8b --host 127.0.0.1 --port 8089 -c 16384 -ngl 99 --jinja >data/llama.log 2>&1 &
  started="$started $!"; wait_for="$wait_for http://127.0.0.1:8089/health"
  echo "llama: starting (log: data/llama.log)"
else
  echo "llama: llama-server not installed (brew install llama.cpp); the rogue agent won't run"
fi

# 2. PromptGuard on the Mac GPU when its venv exists (~6x the container's CPU); otherwise the container.
if up http://127.0.0.1:8002/; then
  export HEIMDALL_GUARD_URL=http://host.docker.internal:8002
  echo "promptguard: GPU copy already running on 8002"
elif [ -x .venv-guard/bin/python ]; then
  HF_HUB_OFFLINE=1 GUARD_BIND=127.0.0.1 .venv-guard/bin/python reviewer/guard.py >data/guard.log 2>&1 &
  started="$started $!"; wait_for="$wait_for http://127.0.0.1:8002/"
  export HEIMDALL_GUARD_URL=http://host.docker.internal:8002
  echo "promptguard: starting on the GPU (log: data/guard.log)"
else
  echo "promptguard: in a container on CPU (see README for the faster GPU setup)"
fi

# 3. The stack. The review page runs here instead of in its container, so its Run buttons can start runs.
docker compose stop review >/dev/null 2>&1 || true
docker compose up -d checkpoint coder guard >/dev/null
echo "stack: checkpoint, sandbox and PromptGuard up"

# 4. Wait for the pieces we started, then the page.
for u in $wait_for; do
  i=0; while ! up "$u" && [ $i -lt 90 ]; do sleep 2; i=$((i + 1)); done
done
echo "review page: http://127.0.0.1:$PORT  (Ctrl-C to stop)"
REVIEW_PORT=$PORT "$PY" review/app.py &
started="$started $!"
wait
