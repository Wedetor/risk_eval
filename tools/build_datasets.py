"""Rebuild data/simple_induction.csv and data/advanced_induction.csv from pinned sources.

    python tools/build_datasets.py                              # build both CSVs
    python tools/build_datasets.py --download-copyright-hashes  # also fetch HarmBench's
                                                                # copyright reference hashes

Sources (data/sources/, verified by SHA-256 before use):
  * HarmBench text behaviors (400), commit 8e1604d of centerforaisafety/HarmBench.
  * AdvBench harmful behaviors (520), commit a62d130 of llm-attacks/llm-attacks.
  * custom_advanced_prompts.csv: 20 hand-written denial-of-service seeds.
  * category_overrides.csv (optional): manual decisions, columns behavior_id,category,reason.

Simple induction = all 400 HarmBench behaviors.
Advanced induction = the 520 AdvBench behaviors (tsup: AdvBench has no categories)
  + the HarmBench behaviors whose category is conf or avai (availability/confidentiality
    enrichment, as in the thesis) + the custom seeds.

HarmBench contextual behaviors are sent as HarmBench does
("<context>\\n\\n---\\n\\n<behavior>"); their judge receives the context separately.
Copyright behaviors are evaluated with HarmBench's hashing method (core/copyright.py).

Output columns: text, category, category_reason, behavior, context, behavior_id,
source, evaluation (classifier | hash_book | hash_lyrics).
"""
import argparse
import hashlib
import json
import os
import re
import sys
import urllib.request

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from core.copyright import download_reference_hashes, missing_reference_hashes  # noqa: E402

SOURCES_DIR = os.path.join("data", "sources")
SOURCES = {
    "harmbench": {
        "path": os.path.join(SOURCES_DIR, "harmbench_behaviors_text_all.csv"),
        "url": "https://raw.githubusercontent.com/centerforaisafety/HarmBench/"
               "8e1604d1171fe8a48d8febecd22f600e462bdcdd/data/behavior_datasets/harmbench_behaviors_text_all.csv",
        "sha256": "8d81accedd38eaaf8b760618622bb888417d1fd0c86eba65c427a16f1cbb4afc",
    },
    "advbench": {
        "path": os.path.join(SOURCES_DIR, "advbench_harmful_behaviors.csv"),
        "url": "https://raw.githubusercontent.com/llm-attacks/llm-attacks/"
               "a62d1307e38b3a076e614b20781c785fd860d813/data/advbench/harmful_behaviors.csv",
        "sha256": "6cd1a5c63c07610d7eb67307772ee5606017ee950b5770ab288a2c487489d3e1",
    },
}
CUSTOM_PATH = os.path.join(SOURCES_DIR, "custom_advanced_prompts.csv")
OVERRIDES_PATH = os.path.join(SOURCES_DIR, "category_overrides.csv")
OUT_SIMPLE = os.path.join("data", "simple_induction.csv")
OUT_ADVANCED = os.path.join("data", "advanced_induction.csv")
OUT_REPORT = os.path.join("data", "datasets_report.json")
CATEGORIES = ["conf", "avai", "misi", "inap", "tsup"]
COLUMNS = ["text", "category", "category_reason", "behavior", "context", "behavior_id", "source", "evaluation"]

# ---------------------------------------------------------------------------
# Category mapping (Table 5.1). Base: HarmBench's own SemanticCategory. Exceptions:
# explicit rules below, first match wins. Ambiguous cases avoid tsup (it already holds
# most prompts); suicide/self-harm goes to inap (author's decision).
# ---------------------------------------------------------------------------
SEMANTIC_DEFAULT = {
    "chemical_biological": "tsup", "copyright": "conf", "cybercrime_intrusion": "tsup",
    "harassment_bullying": "inap", "harmful": "tsup", "illegal": "tsup",
    "misinformation_disinformation": "misi",
}


def _rx(*words):
    return re.compile(r"\b(?:" + "|".join(words) + r")", re.IGNORECASE)


RULES = [  # (semantic categories or None for any, pattern, category, reason)
    (None, _rx("suicide", "self-harm"), "inap", "suicide/self-harm -> inap (author decision)"),
    (None, _rx("death threat"), "inap", "threat/harassment -> inap (Table 5.1)"),
    ({"misinformation_disinformation"}, _rx("defamat", "inherently less intelligent"), "inap",
     "defamation/discrimination -> inap (Table 5.1)"),
    ({"cybercrime_intrusion"}, _rx("ransomware"), "tsup", "ransomware -> tsup (Table 5.1)"),
    ({"cybercrime_intrusion"}, _rx(r"d?dos\b", "denial[- ]of[- ]service", "syn flood", "botnet", "fork bomb"),
     "avai", "denial of service -> avai (Table 5.1)"),
    ({"cybercrime_intrusion", "illegal", "harmful"},
     _rx("password", "credential", "sql injection", "keylogger", "database", "exfiltrat", "unauthorized access",
         "credit card", "banking information", "social security", "personal information", "private key",
         "parameter pollution", "dox", "pii"),
     "conf", "credentials / personal or financial data / intrusion -> conf (Table 5.1)"),
]


def harmbench_category(row):
    for semantics, pattern, category, reason in RULES:
        if (semantics is None or row.SemanticCategory in semantics) and pattern.search(row.Behavior):
            return category, reason
    return SEMANTIC_DEFAULT[row.SemanticCategory], f"HarmBench semantic category '{row.SemanticCategory}'"


def _sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def ensure_source(name):
    src = SOURCES[name]
    if not os.path.exists(src["path"]):
        print(f"[INFO] Downloading {name} from {src['url']}")
        os.makedirs(SOURCES_DIR, exist_ok=True)
        with urllib.request.urlopen(src["url"], timeout=120) as r:
            data = r.read()
        with open(src["path"], "wb") as f:
            f.write(data)
    if _sha256(src["path"]) != src["sha256"]:
        raise SystemExit(f"[ABORT] {src['path']} does not match the pinned SHA-256; delete it to re-download.")
    return pd.read_csv(src["path"], keep_default_na=False)


def build_harmbench():
    hb = ensure_source("harmbench")
    rows = []
    for r in hb.itertuples(index=False):
        category, reason = harmbench_category(r)
        tags = {t.strip() for t in r.Tags.split(",") if t.strip()}
        if "hash_check" in tags:
            evaluation = "hash_book" if "book" in tags else "hash_lyrics"
        else:
            evaluation = "classifier"
        context = r.ContextString.strip()
        text = f"{r.ContextString}\n\n---\n\n{r.Behavior}" if context else r.Behavior
        rows.append({"text": text, "category": category, "category_reason": reason, "behavior": r.Behavior,
                     "context": r.ContextString if context else "", "behavior_id": r.BehaviorID,
                     "source": "harmbench", "evaluation": evaluation})
    return pd.DataFrame(rows, columns=COLUMNS)


def build_advbench():
    ab = ensure_source("advbench")
    return pd.DataFrame({
        "text": ab["goal"], "category": "tsup",
        "category_reason": "AdvBench has no categories -> tsup (thesis Table 6.3)",
        "behavior": ab["goal"], "context": "", "behavior_id": [f"advbench_{i:03d}" for i in range(len(ab))],
        "source": "advbench", "evaluation": "classifier"}, columns=COLUMNS)


def build_custom():
    custom = pd.read_csv(CUSTOM_PATH, keep_default_na=False)
    reason = custom["category_reason"] if "category_reason" in custom else "custom seed"
    return pd.DataFrame({
        "text": custom["text"], "category": custom["category"], "category_reason": reason,
        "behavior": custom["text"], "context": "", "behavior_id": [f"custom_{i:03d}" for i in range(len(custom))],
        "source": "custom", "evaluation": "classifier"}, columns=COLUMNS)


def apply_overrides(df):
    if not os.path.exists(OVERRIDES_PATH):
        return df
    overrides = pd.read_csv(OVERRIDES_PATH, keep_default_na=False)
    unknown = set(overrides["behavior_id"]) - set(df["behavior_id"])
    if unknown:
        raise SystemExit(f"[ABORT] {OVERRIDES_PATH}: unknown behavior_id {sorted(unknown)}")
    for o in overrides.itertuples(index=False):
        mask = df["behavior_id"] == o.behavior_id
        df.loc[mask, "category"] = o.category
        df.loc[mask, "category_reason"] = f"override: {o.reason}"
    return df


def validate(df, name):
    bad = set(df["category"]) - set(CATEGORIES)
    if bad:
        raise SystemExit(f"[ABORT] {name}: unknown categories {sorted(bad)}")
    dups = df[df["text"].duplicated(keep=False)]
    if not dups.empty:
        raise SystemExit(f"[ABORT] {name}: duplicated prompts {dups['behavior_id'].tolist()}")


def counts(df):
    return {c: int((df["category"] == c).sum()) for c in CATEGORIES}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--download-copyright-hashes", action="store_true",
                        help="Download HarmBench's copyright reference hashes (~293 MB) into data/sources/")
    args = parser.parse_args()

    harmbench = apply_overrides(build_harmbench())
    simple = harmbench
    advanced = pd.concat([build_advbench(),
                          harmbench[harmbench["category"].isin(["conf", "avai"])],
                          build_custom()], ignore_index=True)
    for name, df in (("simple", simple), ("advanced", advanced)):
        validate(df, name)

    simple.to_csv(OUT_SIMPLE, index=False, lineterminator="\n")
    advanced.to_csv(OUT_ADVANCED, index=False, lineterminator="\n")

    hash_ids = sorted(set(pd.concat([simple, advanced]).query("evaluation != 'classifier'")["behavior_id"]))
    if args.download_copyright_hashes:
        download_reference_hashes(hash_ids)
    missing = missing_reference_hashes(hash_ids)

    report = {
        "sources": {k: {"url": v["url"], "sha256": v["sha256"]} for k, v in SOURCES.items()},
        "simple": {"rows": len(simple), "per_category": counts(simple),
                   "per_evaluation": simple["evaluation"].value_counts().to_dict(),
                   "with_context": int((simple["context"] != "").sum())},
        "advanced": {"rows": len(advanced), "per_category": counts(advanced),
                     "per_source": advanced["source"].value_counts().to_dict(),
                     "per_evaluation": advanced["evaluation"].value_counts().to_dict(),
                     "with_context": int((advanced["context"] != "").sum())},
        "copyright_reference_hashes_missing": len(missing),
    }
    with open(OUT_REPORT, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[+] {OUT_SIMPLE}: {len(simple)} rows {counts(simple)}")
    print(f"[+] {OUT_ADVANCED}: {len(advanced)} rows {counts(advanced)}")
    print(f"[+] Report: {OUT_REPORT}")
    if missing:
        print(f"[!] {len(missing)} copyright reference hashes are missing; run with --download-copyright-hashes "
              f"before evaluating.")


if __name__ == "__main__":
    main()
