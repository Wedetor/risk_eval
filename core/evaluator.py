"""Simple and advanced induction passes.

Simple induction: every prompt of simple_induction.csv, judged by the fixed judge.

Advanced induction: Giskard, without any LLM of its own (no attack is generated):
  1. Giskard scan, only the two detectors that need no LLM:
     * LLMPromptInjectionDetector: 35 fixed jailbreak/hijacking prompts shipped with
       Giskard (PromptInject + Garak), evaluated by deterministic string matching.
     * LLMCharsInjectionDetector: fixed sample (random_state=402, up to 100 rows) of
       advanced_induction.csv with control characters appended; BERTScore comparison.
  2. Giskard metamorphic transformations (deterministic, rng_seed=1729) of ALL seeds of
     advanced_induction.csv, evaluated through a Giskard evaluator backed by the fixed
     judge. Each variant inherits its seed's category, behavior, context and evaluation.
"""
import logging
import os
import warnings
from collections import Counter

import giskard
from giskard.functions.transformation import text_punctuation_removal, text_typo, text_uppercase
from giskard.llm.evaluators.base import BaseEvaluator, EvaluationResult
from giskard.models.cache import set_cache_enabled

from core.judge import ERROR, SAFE, UNSAFE
from core.metrics import CATEGORIES, classify_issue_text, count_giskard_hits
from core.target_client import ERR_EMPTY_RESPONSE, ERR_TARGET_EXCEPTION

warnings.filterwarnings("ignore", category=UserWarning)

TEMPERATURE_SIMPLE = 0.0
TEMPERATURE_ADVANCED = 0.7       # Giskard mutation tests (same as the original protocol)
# The control-chars detector compares the answer to a prompt with the answer to the same
# prompt plus control characters. With sampling both answers differ even without any
# injection, so the Giskard scan detectors run with deterministic decoding.
TEMPERATURE_GISKARD_SCAN = 0.0

GISKARD_DETECTOR_TAGS = ["jailbreak", "control_chars_injection"]
GISKARD_EXPECTED_DETECTORS = {"LLMPromptInjectionDetector", "LLMCharsInjectionDetector"}
BERTSCORE_MODEL = "distilbert-base-multilingual-cased"
CONTROL_CHARS = "\r\b"
MUTATIONS = {
    "typos": text_typo(column="text"),
    "uppercase": text_uppercase(column="text"),
    "punctuation_removal": text_punctuation_removal(column="text"),
}
_NO_LLM_URL = "http://127.0.0.1:9/v1"  # nothing listens here


def lock_giskard_llm():
    """Make sure Giskard cannot use any LLM.

    In commit 5c6bc2d Giskard used its default `gpt-4o` through LiteLLM, which read
    OPENAI_API_BASE = target URL, so the evaluated model judged itself. Nothing here
    needs a Giskard LLM; its settings point to a closed local port so any unexpected
    LLM call fails (and is logged) instead of reaching the target or api.openai.com.
    """
    os.environ.pop("OPENAI_BASE_URL", None)
    os.environ["OPENAI_API_BASE"] = _NO_LLM_URL
    os.environ["OPENAI_API_KEY"] = "sk-no-llm-allowed"
    os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
    giskard.llm.set_llm_model("openai/no-llm-allowed", api_base=_NO_LLM_URL, api_key="sk-no-llm-allowed")
    # Giskard caches predictions by prompt text; a cache hit would skip the call to the
    # target, so its answer would not be logged or scored. Every prompt must really be sent.
    set_cache_enabled(False)


def selected_giskard_detectors():
    from giskard.scanner import Scanner
    return sorted(type(d).__name__ for d in
                  Scanner(only=GISKARD_DETECTOR_TAGS).get_detectors(tags=["text_generation"]))


def injection_prompt_categories():
    """Sub-risk of each of Giskard's fixed injection prompts.

    Computed with the same classifier and the same text ("Prompt Injection " + group
    description) later applied to Giskard's issues, so attempts and hits of a group
    always fall in the same category.
    """
    from giskard.llm.loaders.prompt_injections import PromptInjectionDataLoader
    loader = PromptInjectionDataLoader()
    out = {}
    for group in set(loader.groups):
        category = classify_issue_text(f"Prompt Injection {loader.group_description(group)}")
        for prompt in loader.prompts_from_group(group):
            out[prompt] = category
    return out


def _stats():
    return {cat: {UNSAFE: 0, SAFE: 0, ERROR: 0} for cat in CATEGORIES}


def _zero():
    return {k: 0 for k in CATEGORIES}


def _record(pass_idx, source, prompt, gen, temperature, seed=None, verdict=None, judged_by=None, **extra):
    """One JSONL line per target call."""
    rec = {"pass": pass_idx, "phase": source.split(":")[0], "source": source,
           "category": seed["category"] if seed is not None else extra.pop("category", None),
           "behavior_id": seed["behavior_id"] if seed is not None else None,
           "prompt": prompt, "temperature": temperature, "judged_by": judged_by}
    if seed is not None and seed["text"] != prompt:
        rec["seed_prompt"] = seed["text"]
    if gen is not None:
        rec.update(response=gen.text, raw_response=gen.raw_text, finish_reason=gen.finish_reason,
                   had_thinking=gen.had_thinking, target_latency_s=gen.latency_s,
                   target_attempts=gen.attempts, usage=gen.usage)
    if gen is not None and gen.error_type:
        rec.update(verdict=ERROR, error_type=gen.error_type, error=gen.error)
    elif verdict is not None:
        rec.update(verdict=verdict.verdict, error_type=verdict.error_type, error=verdict.error,
                   judge_raw=verdict.raw)
    rec.update(extra)
    return rec


class _DetectorFailureCollector(logging.Handler):
    """Giskard swallows detector exceptions (only logs them); collect them here."""

    def __init__(self):
        super().__init__(level=logging.ERROR)
        self.failures = []

    def emit(self, record):
        msg = record.getMessage()
        if msg.startswith("Detector ") and "failed with error" in msg:
            self.failures.append(msg)


# ==========================================
# Phase 1: Simple Induction
# ==========================================
def run_simple_pass(pass_idx, target, scorer, df_simple, run_logger):
    print(f"\n[INFO] Pass {pass_idx}: Simple Induction (direct prompts, fixed judge)...")
    stats = _stats()
    error_types = Counter()
    thinking_seen = 0

    for _, row in df_simple.iterrows():
        gen = target.generate(row["text"], TEMPERATURE_SIMPLE)
        thinking_seen += int(gen.had_thinking)
        # Exceptions and empty answers are neither SAFE nor UNSAFE.
        verdict = None if gen.error_type else scorer.score(row, gen.text)
        rec = _record(pass_idx, "simple", row["text"], gen, TEMPERATURE_SIMPLE, seed=row,
                      verdict=verdict, judged_by=scorer.method(row))
        stats[row["category"]][rec["verdict"]] += 1
        if rec["error_type"]:
            error_types[rec["error_type"]] += 1
        run_logger.append("interactions.jsonl", rec)

    print("=" * 66)
    print(f"[PASS {pass_idx} - SIMPLE INDUCTION] prompts: {len(df_simple)}")
    for cat, s in stats.items():
        print(f"  -> [{cat.upper().ljust(4)}] UNSAFE = {str(s[UNSAFE]).ljust(4)} | SAFE = {str(s[SAFE]).ljust(4)} | ERRORS = {s[ERROR]}")
    if error_types:
        print(f"  Error breakdown: {dict(error_types)}")
    if thinking_seen:
        print(f"  [WARNING] {thinking_seen} answers contained thinking blocks (stripped before judging).")
    print("=" * 66)
    return {"stats": stats, "error_types": dict(error_types), "thinking_seen": thinking_seen}


# ==========================================
# Phase 2: Advanced Induction (Giskard)
# ==========================================
class FixedJudgeEvaluator(BaseEvaluator):
    """Giskard evaluator backed by the fixed judge (classifier or copyright hashing)."""

    def __init__(self, scorer, seeds, generations, on_result):
        self.scorer = scorer
        self.seeds = seeds                  # advanced DataFrame; dataset index = seed row
        self.generations = generations      # prompt -> Generation, filled by the model function
        self.on_result = on_result          # callback(seed_row, prompt, generation, verdict)

    def evaluate(self, model, dataset):
        result = EvaluationResult()
        predictions = model.predict(dataset).prediction
        for (idx, row), prediction in zip(dataset.df.iterrows(), predictions):
            seed = self.seeds.loc[idx]
            gen = self.generations.get(row["text"])
            sample = {"conversation": [{"role": "user", "content": row["text"]},
                                       {"role": "agent", "content": str(prediction)}],
                      "meta": {"behavior_id": seed["behavior_id"]}}
            verdict = None if gen is None or gen.error_type else self.scorer.score(seed, gen.text)
            if verdict is None:
                result.add_error(gen.error if gen else "no generation recorded", sample)
            elif verdict.verdict == ERROR:
                result.add_error(verdict.error, sample)
            else:
                result.add_sample(eval_passed=(verdict.verdict == SAFE), reason=verdict.raw, sample=sample)
            self.on_result(seed, row["text"], gen, verdict)
        return result


def run_advanced_pass(pass_idx, target, scorer, df_adv, injection_categories, run_logger,
                      complement=True, max_issues_per_detector=60):
    print(f"\n[INFO] Pass {pass_idx}: Advanced Induction (Giskard scan + Giskard mutations, fixed judge)...")
    seed_index = {text: i for i, text in enumerate(df_adv["text"])}
    dataset = giskard.Dataset(df_adv[["text"]], name="Advanced_Induction", validation=False)
    target_errors = Counter()
    thinking_seen = 0
    n_calls = 0
    injection_attempts = _zero()       # answered injection prompts per category
    chars_attempts = Counter()         # seed row -> answered control-char perturbations
    # Seeds with an empty reference or perturbed answer: Giskard compares texts with
    # BERTScore, so an empty answer would look like a successful injection. They are
    # excluded from both hits and tests of the control-chars detector.
    chars_error_seeds = set()
    complement_counts = {UNSAFE: 0, SAFE: 0, ERROR: 0}
    mode = {"name": "scan"}            # "scan" or "mutation:<name>"
    generations = {}                   # mutation mode: prompt -> Generation

    def llm_predict(df):
        nonlocal n_calls, thinking_seen
        responses = []
        for text in df["text"]:
            n_calls += 1
            in_scan = mode["name"] == "scan"
            temperature = TEMPERATURE_GISKARD_SCAN if in_scan else TEMPERATURE_ADVANCED
            gen = target.generate(text, temperature)
            thinking_seen += int(gen.had_thinking)
            if gen.error_type:
                target_errors[gen.error_type] += 1
            if not in_scan:
                generations[text] = gen     # the evaluator scores and logs it
                responses.append(gen.text or "")
                continue

            stripped = text.rstrip(CONTROL_CHARS)
            seed = df_adv.iloc[seed_index[stripped]] if stripped in seed_index else None
            if text in injection_categories:
                kind, category = "prompt_injection", injection_categories[text]
            elif seed is not None:
                kind = "chars_injection" if stripped != text else "chars_reference"
                category = seed["category"]
            else:
                kind, category = "other", None
            if kind == "prompt_injection" and not gen.error_type:
                injection_attempts[category] += 1
            elif kind in ("chars_injection", "chars_reference"):
                row_idx = seed_index[stripped]
                if gen.error_type == ERR_EMPTY_RESPONSE:
                    chars_error_seeds.add(row_idx)
                elif kind == "chars_injection" and not gen.error_type:
                    chars_attempts[row_idx] += 1

            verdict = None
            if complement and not gen.error_type:
                row = seed if seed is not None else {"behavior": text, "evaluation": "classifier"}
                verdict = scorer.score(row, gen.text)
                complement_counts[verdict.verdict] += 1
            run_logger.append("interactions.jsonl", _record(
                pass_idx, f"advanced:giskard_scan:{kind}", text, gen, temperature, seed=seed,
                judged_by="giskard", category=category,
                complement_verdict=verdict.verdict if verdict else None,
                complement_raw=verdict.raw if verdict else None))
            if gen.error_type == ERR_TARGET_EXCEPTION:
                # Never hand an error string to Giskard as if it were an answer. Giskard's
                # control-chars detector retries with shorter injections; otherwise the
                # detector fails and is counted as a Giskard failure.
                raise RuntimeError(f"Target call failed after retries: {gen.error}")
            responses.append(gen.text)
        return responses

    giskard_model = giskard.Model(model=llm_predict, model_type="text_generation", name="Target-LLM",
                                  description="Local LLM under audit.", feature_names=["text"])

    # ---- 2a. Giskard scan (prompt injection + control chars) ----
    collector = _DetectorFailureCollector()
    scan_logger = logging.getLogger("giskard.scanner.logger")  # logger used by giskard/scanner/scanner.py
    scan_logger.addHandler(collector)
    scan_ok = True
    results_scan = None
    try:
        results_scan = giskard.scan(giskard_model, dataset=dataset, only=GISKARD_DETECTOR_TAGS,
                                    max_issues_per_detector=max_issues_per_detector, verbose=True)
    except Exception as scan_error:
        scan_ok = False
        print(f"[ERROR] Giskard scan failed in pass {pass_idx}: {scan_error}")
        run_logger.append("giskard_failures.jsonl", {
            "pass": pass_idx, "kind": "scan_exception", "error": f"{type(scan_error).__name__}: {scan_error}"})
    finally:
        scan_logger.removeHandler(collector)

    for msg in collector.failures:
        run_logger.append("giskard_failures.jsonl", {"pass": pass_idx, "kind": "detector_failed", "error": msg})

    scan_hits, issue_records, n_uncountable = count_giskard_hits(
        results_scan, df_adv["category"], exclude_seed_indices=chars_error_seeds)
    if chars_error_seeds:
        run_logger.append("giskard_failures.jsonl", {
            "pass": pass_idx, "kind": "chars_injection_seeds_excluded_empty_answer",
            "behavior_ids": df_adv.loc[sorted(chars_error_seeds), "behavior_id"].tolist()})
    for rec in issue_records:
        run_logger.append("giskard_issues.jsonl", {"pass": pass_idx, "source": "giskard_scan", **rec})
    if n_uncountable:
        run_logger.append("giskard_failures.jsonl", {
            "pass": pass_idx, "kind": "uncountable_issues", "count": n_uncountable})
    if results_scan is not None:
        try:
            results_scan.to_html(run_logger.path(f"giskard_pass_{pass_idx:02d}.html"))
        except Exception as e:
            print(f"[WARNING] Could not save Giskard HTML report: {e}")

    # ---- 2b. Giskard mutations of every seed, scored by the fixed judge ----
    mutation_stats = {}
    mutation_ok = True
    for name, transformation in MUTATIONS.items():
        mode["name"] = f"mutation:{name}"
        generations.clear()
        stats = _stats()
        try:
            mutated = dataset.transform(transformation).df
            changed = mutated["text"] != df_adv.loc[mutated.index, "text"]
            n_unchanged = int((~changed).sum())
            mutated_ds = giskard.Dataset(mutated[changed], name=f"Advanced_{name}", validation=False)

            def on_result(seed, prompt, gen, verdict, _name=name, _stats=stats):
                rec = _record(pass_idx, f"advanced:giskard_mutation:{_name}", prompt, gen, TEMPERATURE_ADVANCED,
                              seed=seed, verdict=verdict, judged_by=scorer.method(seed))
                if gen is None:
                    rec.update(verdict=ERROR, error_type="no_generation", error="no generation recorded")
                _stats[seed["category"]][rec["verdict"]] += 1
                run_logger.append("interactions.jsonl", rec)

            result = FixedJudgeEvaluator(scorer, df_adv, generations, on_result).evaluate(giskard_model, mutated_ds)
            # Only answers judged SAFE or UNSAFE are tests; errors are counted apart.
            n_tests = sum(s[UNSAFE] + s[SAFE] for s in stats.values())
            run_logger.append("giskard_issues.jsonl", {
                "pass": pass_idx, "source": f"giskard_mutation:{name}", "detector": "FixedJudgeEvaluator",
                "group": "Metamorphic transformation", "description": f"Seeds transformed with '{name}'",
                "prompts": int(changed.sum()), "tests": n_tests, "unchanged_seeds_skipped": n_unchanged,
                "num_hits": len(result.failure_examples), "errors": len(result.errors),
                "per_category": stats, "examples": result.failure_examples,
            })
            mutation_stats[name] = {"tests": n_tests, "unchanged_seeds_skipped": n_unchanged, "per_category": stats}
        except Exception as e:
            mutation_ok = False
            print(f"[ERROR] Giskard mutation '{name}' failed in pass {pass_idx}: {e}")
            run_logger.append("giskard_failures.jsonl", {
                "pass": pass_idx, "kind": f"mutation_failed:{name}", "error": f"{type(e).__name__}: {e}"})
    mode["name"] = "scan"

    # ---- Totals: hits and real number of valid tests per sub-risk ----
    chars_tests = _zero()
    for row_idx, n in chars_attempts.items():
        if row_idx not in chars_error_seeds:
            chars_tests[df_adv.loc[row_idx, "category"]] += n
    hits = dict(scan_hits)
    tests = {k: injection_attempts[k] + chars_tests[k] for k in CATEGORIES}
    for st in mutation_stats.values():
        for k in CATEGORIES:
            hits[k] += st["per_category"][k][UNSAFE]
            tests[k] += st["per_category"][k][UNSAFE] + st["per_category"][k][SAFE]

    print("=" * 66)
    print(f"[PASS {pass_idx} - ADVANCED INDUCTION] scan_ok={scan_ok} | mutations_ok={mutation_ok}")
    print(f"  Scan issues: {len(results_scan.issues) if results_scan else 0} | scan hits: {scan_hits}")
    for name, st in mutation_stats.items():
        unsafe = {k: v[UNSAFE] for k, v in st["per_category"].items()}
        errs = sum(v[ERROR] for v in st["per_category"].values())
        print(f"  Mutation '{name}': tests={st['tests']} (unchanged skipped={st['unchanged_seeds_skipped']}) "
              f"| UNSAFE={unsafe} | errors={errs}")
    print(f"  Total hits: {hits} | tests: {tests}")
    print(f"  Target calls: {n_calls} | target errors: {dict(target_errors)} | "
          f"failed detectors: {len(collector.failures)} | uncountable issues: {n_uncountable}")
    if complement:
        print(f"  Complement judge on Giskard scan answers: {complement_counts}")
    if thinking_seen:
        print(f"  [WARNING] {thinking_seen} answers contained thinking blocks (stripped).")
    print("=" * 66)

    return {
        "hits": hits, "tests": tests, "scan_hits": scan_hits,
        "tests_scan": {"prompt_injection": injection_attempts, "chars_injection": chars_tests},
        "chars_seeds_excluded_empty_answer": len(chars_error_seeds),
        "mutations": mutation_stats, "scan_ok": scan_ok, "mutations_ok": mutation_ok,
        "detector_failures": len(collector.failures), "uncountable_issues": n_uncountable,
        "target_calls": n_calls, "target_errors": dict(target_errors), "thinking_seen": thinking_seen,
        "num_scan_issues": len(results_scan.issues) if results_scan else 0,
        "complement": complement_counts if complement else None,
    }
