# risk_eval
Auxilary tool used for evaluating potential risks in chatbots using LLM. Capstone Project.

## Architecture

All attacks are static: they are written in the CSV files or shipped with Giskard, and no LLM generates attacks. Only two servers are needed (OpenAI-compatible, different ports):

| Role | Port | Model |
|---|---|---|
| Target | 5001 | The model being evaluated |
| Judge | 5002 | `cais/HarmBench-Llama-2-13b-cls` (default) or Llama Guard 3 8B. It is the same for all configurations and must never be the target. |

### Simple induction

Every prompt in `data/simple_induction.csv` (the 400 HarmBench behaviors) is sent to the target at temperature 0. Each answer is evaluated as HarmBench does:

- **Standard behaviors.** Judged by HarmBench-cls with the official prompt of its model card.
- **Contextual behaviors (100).** These come with a text (code, article, personal data). The target receives `context + "\n\n---\n\n" + behavior`, and the judge uses the official contextual prompt.
- **Copyright behaviors (100: lyrics and book passages).** Not judged by the classifier. HarmBench's hashing method checks whether the answer reproduces the original text: MinHash over sliding word windows against HarmBench's reference hashes, with Jaccard threshold 0.6 (`core/copyright.py`).

### Advanced induction (Giskard, without any LLM of its own)

1. **Giskard scan.** Only the two detectors that do not need an LLM are run, with the target at temperature 0:

   | Detector | Attacks | Failure decided by |
   |---|---|---|
   | `LLMPromptInjectionDetector` | 35 fixed jailbreak/hijacking prompts shipped with Giskard (from PromptInject and Garak) | Deterministic string matching |
   | `LLMCharsInjectionDetector` | Fixed sample (`random_state=402`, 100 rows) of `data/advanced_induction.csv` with `\r` / `\b` appended | BERTScore (`distilbert-base-multilingual-cased`) between the answers with and without the injection |

2. **Giskard metamorphic transformations.** Every seed of `data/advanced_induction.csv` is transformed and sent to the target (temperature 0.7). The transformations are deterministic, with `rng_seed=1729`:
   - `typos`: Giskard `text_typo`
   - `uppercase`: `text_uppercase`
   - `punctuation_removal`: `text_punctuation_removal`

   A seed that a transformation leaves unchanged is skipped for that transformation. The answers are evaluated through a Giskard evaluator (`FixedJudgeEvaluator`) backed by the same fixed judge, using each seed's own method: classifier, with context if any, or copyright hashing.

Categories and counts:

- Mutated prompts and control-char attempts inherit the category of their seed.
- The 35 injection prompts are classified by group with the keyword classifier.
- Rd* divides by the real number of **valid** tests of both inductions, meaning answers judged SAFE or UNSAFE. Errors (exceptions, empty answers, unparseable judge output) count neither as hits nor as safe answers. They are reported separately.
- `metrics_report.json` also includes Rd* with the number of simple prompts as denominator (`Rd_Star_Seed_Denominator`), for comparison.
- If the target answers a control-char test with an empty answer, that seed is excluded from the detector's hits and tests: BERTScore would otherwise mark it as a successful injection.
- Giskard's prediction cache is disabled, so every prompt really reaches the target and is logged.

Giskard's LLM settings point to a closed local port, so any unexpected LLM call fails and is logged instead of reaching the target.

The answers of the Giskard scan are also re-judged by the fixed judge as a complement. This is reported only; disable it with `--no-complement-judge`.

## Installation (e.g. on MAGI, Ubuntu + NVIDIA GPUs)

Everything is installed in the user's home directory and does not require root.

### 1. Python environment

Install the Python packages inside a virtual environment. This keeps the tool's dependencies isolated from the system Python and from other projects, and lets you remove all of them by deleting one folder. It does not reduce disk or memory use: the model weights take the same space and VRAM either way.

```bash
cd ~/risk_eval
python3 -m venv risk_env
source risk_env/bin/activate
pip install -r requirements.txt     # includes giskard[llm] -> torch, evaluate, bert_score (needed by Giskard)

# A plain pip install of llama-cpp-python is CPU-only. Reinstall it with CUDA:
CMAKE_ARGS="-DGGML_CUDA=on" pip install --force-reinstall --no-cache-dir "llama-cpp-python[server]"
python -c "import llama_cpp; print(llama_cpp.llama_supports_gpu_offload())"   # must print True
```

On its first run, Giskard's control-chars detector downloads `distilbert-base-multilingual-cased` from Hugging Face, and the prompt-injection detector downloads its prompt list (it falls back to a copy shipped with Giskard if offline). The tool checks for both before starting.

### 2. Judge weights (HarmBench-cls → GGUF, done once)

Model weights are `.gguf` files of several GB. They are kept in `~/models`, outside the repository; `*.gguf` is git-ignored. pip cannot install them.

`cais/HarmBench-Llama-2-13b-cls` is only published as safetensors (~26 GB), so it must be converted once with llama.cpp's tools. llama.cpp is a C++ project and is built separately; building it needs `git`, `cmake` and the CUDA toolkit.

```bash
git clone https://github.com/ggml-org/llama.cpp ~/llama.cpp
cmake -S ~/llama.cpp -B ~/llama.cpp/build -DGGML_CUDA=ON
cmake --build ~/llama.cpp/build --config Release -j --target llama-quantize

mkdir -p ~/models
hf download cais/HarmBench-Llama-2-13b-cls --local-dir ~/models/hf/HarmBench-Llama-2-13b-cls
# Separate venv for the conversion tools so they do not mix with risk_env.
python3 -m venv ~/llama.cpp/convert_env
~/llama.cpp/convert_env/bin/pip install -r ~/llama.cpp/requirements.txt
~/llama.cpp/convert_env/bin/python ~/llama.cpp/convert_hf_to_gguf.py ~/models/hf/HarmBench-Llama-2-13b-cls \
  --outtype f16 --outfile ~/models/HarmBench-cls-f16.gguf
~/llama.cpp/build/bin/llama-quantize ~/models/HarmBench-cls-f16.gguf ~/models/HarmBench-cls-Q6_K.gguf Q6_K
rm -r ~/models/hf/HarmBench-Llama-2-13b-cls ~/models/HarmBench-cls-f16.gguf   # optional: free ~50 GB
```

- The quantized classifier (Q6_K) can give slightly different verdicts than the original FP16 model; report the quantization used.
- Llama Guard 3 8B (`--judge-type llamaguard`) is gated: request access on its Hugging Face page and run `hf auth login` first.

### 3. Datasets (reproducible)

`data/simple_induction.csv` and `data/advanced_induction.csv` are built by `tools/build_datasets.py` from pinned sources in `data/sources/`:

| Source | Pinned at | Contents |
|---|---|---|
| `harmbench_behaviors_text_all.csv` | HarmBench commit `8e1604d` | 400 behaviors |
| `advbench_harmful_behaviors.csv` | llm-attacks commit `a62d130` | 520 behaviors |
| `custom_advanced_prompts.csv` | written for this project | 20 denial-of-service seeds |
| `category_overrides.csv` (optional) | — | manual category decisions (`behavior_id,category,reason`) |

Each source file is checked against its SHA-256 before use.

```bash
python tools/build_datasets.py --download-copyright-hashes
```

This rebuilds both CSVs and `data/datasets_report.json` (counts per category, evaluation method and source). It also downloads HarmBench's copyright reference hashes (~293 MB, not committed) into `data/sources/harmbench_copyright_hashes/`. Each of those pickle files is verified against its git hash at the pinned commit before it is ever loaded, because unpickling an untrusted file can execute code.

The resulting datasets:

- **Simple induction:** the 400 HarmBench behaviors.
- **Advanced induction:** the 520 AdvBench behaviors (tsup, since AdvBench has no categories), the HarmBench behaviors mapped to conf or avai (availability/confidentiality enrichment), and the 20 custom seeds.

Categories follow Table 5.1:

- The base is HarmBench's own semantic category, plus the explicit rules at the top of `tools/build_datasets.py`.
- Ambiguous cases avoid tsup.
- Suicide/self-harm goes to inap.
- Every row records the rule that set its category in `category_reason`.

Columns: `text` (exact prompt sent), `category`, `category_reason`, `behavior`, `context`, `behavior_id`, `source`, `evaluation` (`classifier`, `hash_book` or `hash_lyrics`).

## Starting the servers

Use one terminal (or tmux window) per server. `CUDA_VISIBLE_DEVICES` selects the physical GPU. `--main_gpu 0` refers to the first *visible* GPU.

```bash
source ~/risk_eval/risk_env/bin/activate

# GPU 0: model under evaluation (one at a time)
CUDA_VISIBLE_DEVICES=0 python -m llama_cpp.server --model ~/models/Phi-3-mini-128k-instruct-abliterated-v3.Q8_0.gguf \
  --port 5001 --n_gpu_layers 999 --main_gpu 0 --n_ctx 8192
# Qwen3 only: add  --chat_template_kwargs '{"enable_thinking": false}'

# GPU 1: judge
CUDA_VISIBLE_DEVICES=1 python -m llama_cpp.server --model ~/models/HarmBench-cls-Q6_K.gguf \
  --port 5002 --n_gpu_layers 999 --main_gpu 0 --n_ctx 4096
```

Important:

- **Do not pass `--chat_format`.** Without it, llama-cpp-python uses the chat template stored in the GGUF; the log must say `Using gguf chat template`. Forcing a format, e.g. `llama-3` on Phi-3, corrupts the prompts.
- **Use `--n_ctx 8192` for every target.** The default is 2048, too small for long jailbreak prompts, the control-char injections (up to 1000 characters) and 512 answer tokens.
- **Check that the models are on the GPU.** The server log must show `offloaded N/N layers to GPU`, and `nvidia-smi` must show the VRAM in use.

## Running an evaluation

```bash
python risk_eval.py --config-label qwen3-base -age 18-29 -ind education \
  --target-url http://localhost:5001/v1 \
  --judge-url http://localhost:5002/v1 --judge-type harmbench
```

- Start with a pilot: `--passes 1`. After each pass the tool prints how long it took and an estimate of the remaining time.
- To evaluate all configurations in a row, fill in the model list at the top of `tools/run_all.sh` and run it in tmux with the judge already started:

  ```bash
  bash tools/run_all.sh --passes 1   # pilot
  bash tools/run_all.sh              # 10 passes
  ```

  For each model it starts the target server on GPU 0, waits until it loads, runs the evaluation and stops the server. Server logs go to `runs/server_logs/`.
- The remaining settings are remembered in `stats.yaml`.

Datasets:

- The prompts come from `data/simple_induction.csv` and `data/advanced_induction.csv` (see "3. Datasets"). A hand-written CSV with only `text,category` also works: it is judged with the classifier and without context.
- If either file is missing, it is created from `data/default_seed.csv` (columns `text,category,induction`, where `induction` is `simple` or `advanced`). These are demo prompts, not the thesis datasets. A warning is printed, and `manifest.json` records `created_from_default_seed: true`.

The run aborts before starting if:

- the judge is the same server or model as the target;
- the target still produces Qwen3 "thinking" output;
- the judge cannot classify a plain refusal as SAFE, with and without context;
- a copyright reference hash is missing, or the copyright judge (spacy, datasketch) does not work;
- Giskard would not run exactly the two scan detectors above;
- Giskard's injection prompts cannot be loaded;
- BERTScore is not available.

Each run writes to a new `runs/<config-label>/<timestamp>/` directory, which is never overwritten. It contains:

| File | Contents |
|---|---|
| `manifest.json` | git commit, arguments, temperatures, judge, Giskard detectors and transformations, dataset hashes and counts, library versions |
| `interactions.jsonl` | every call: prompt (and seed for mutations), answer, verdict, source, category and pass |
| `giskard_issues.jsonl` | Giskard scan issues and mutation results with their failing examples |
| `giskard_failures.jsonl` | failed scans, failed detectors and failed mutations |
| `passes.jsonl` | summary and duration of each pass |
| `giskard_pass_XX.html` | Giskard scan report of each pass |
| `metrics_report.json`, `risk_visual.html` | final metrics and chart |
