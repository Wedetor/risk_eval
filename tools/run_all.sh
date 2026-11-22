#!/usr/bin/env bash
# Evaluate every configuration in a row on MAGI.
#
#   1. Start the judge once (see README, "Starting the servers").
#   2. Fill in CONFIGS below (label|path to .gguf|extra server flags).
#   3. Run from the repository root, inside tmux:   bash tools/run_all.sh [extra risk_eval.py flags]
#      e.g. a pilot of one pass each:              bash tools/run_all.sh --passes 1
#
# For each configuration it starts the target on GPU 0 (port 5001), waits until it is
# loaded, runs risk_eval.py, and stops the server. Server logs go to runs/server_logs/.
set -euo pipefail

JUDGE_URL="${JUDGE_URL:-http://localhost:5002/v1}"
TARGET_PORT="${TARGET_PORT:-5001}"
TARGET_GPU="${TARGET_GPU:-0}"
QWEN_FLAGS='--chat_template_kwargs {"enable_thinking":false}'

# label | model file | extra llama_cpp.server flags
CONFIGS=(
  "qwen3-base|$HOME/models/Qwen-base.gguf|$QWEN_FLAGS"
  "qwen3-abliterated|$HOME/models/Qwen-heretic.gguf|$QWEN_FLAGS"
  # "llama3-base|$HOME/models/<file>.gguf|"
  # "llama3-abliterated|$HOME/models/<file>.gguf|"
  # "gemma2-base|$HOME/models/<file>.gguf|"
  # "gemma2-abliterated|$HOME/models/<file>.gguf|"
  # "mistral-base|$HOME/models/<file>.gguf|"
  # "mistral-abliterated|$HOME/models/<file>.gguf|"
  # "phi3-base|$HOME/models/<file>.gguf|"
  # "phi3-abliterated|$HOME/models/Phi-3-mini-128k-instruct-abliterated-v3.Q8_0.gguf|"
)

mkdir -p runs/server_logs
curl -sf "$JUDGE_URL/models" > /dev/null || { echo "[ABORT] Judge not reachable at $JUDGE_URL"; exit 1; }

for entry in "${CONFIGS[@]}"; do
  IFS='|' read -r label model extra <<< "$entry"
  [ -f "$model" ] || { echo "[ABORT] Model file not found: $model"; exit 1; }
  log="runs/server_logs/${label}_$(date +%Y%m%d-%H%M%S).log"
  echo "=== $label: starting target server ($model) ==="
  # shellcheck disable=SC2086  # $extra must be split into separate arguments
  CUDA_VISIBLE_DEVICES="$TARGET_GPU" python -m llama_cpp.server --model "$model" --port "$TARGET_PORT" \
      --n_gpu_layers 999 --main_gpu 0 --n_ctx 8192 $extra > "$log" 2>&1 &
  server_pid=$!
  trap 'kill $server_pid 2>/dev/null || true' EXIT

  for _ in $(seq 1 180); do   # up to 15 minutes to load
    curl -sf "http://localhost:$TARGET_PORT/v1/models" > /dev/null && break
    kill -0 "$server_pid" 2>/dev/null || { echo "[ABORT] Server for $label died, see $log"; exit 1; }
    sleep 5
  done
  grep -q "offloaded" "$log" && grep "offloaded" "$log" | tail -1 || echo "[WARNING] No 'offloaded' line in $log: check that the GPU is used"
  grep -E "Using gguf chat template|Using fallback chat format" "$log" | head -1 || true

  python risk_eval.py --config-label "$label" --target-url "http://localhost:$TARGET_PORT/v1" \
      --judge-url "$JUDGE_URL" "$@"

  kill "$server_pid"; wait "$server_pid" 2>/dev/null || true
  trap - EXIT
done
echo "=== All configurations finished. Results in runs/<label>/<timestamp>/ ==="
