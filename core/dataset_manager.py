"""Load the induction datasets.

Required columns: text, category. Optional columns (written by tools/build_datasets.py):
behavior, context, behavior_id, source, evaluation, category_reason. Missing optional
columns get neutral defaults, so a hand-written CSV with only text,category still works.
"""
import os

import pandas as pd

VALID_CATEGORIES = {"conf", "avai", "misi", "inap", "tsup"}
VALID_EVALUATIONS = {"classifier", "hash_book", "hash_lyrics"}
DEFAULT_SEED_FILE = "default_seed.csv"


def _create_from_default_seed(path, induction, dataset_dir):
    """Write `path` with the `induction` rows (simple/advanced) of data/default_seed.csv."""
    seed_path = os.path.join(dataset_dir, DEFAULT_SEED_FILE)
    if not os.path.exists(seed_path):
        raise FileNotFoundError(
            f"Dataset not found: {path}, and no {seed_path} to build a default one from. "
            f"Run tools/build_datasets.py or put the CSVs to evaluate (columns: text, category) in '{dataset_dir}'."
        )
    seeds = pd.read_csv(seed_path)
    missing = {"text", "category", "induction"} - set(seeds.columns)
    if missing:
        raise ValueError(f"{seed_path} is missing columns: {sorted(missing)}")
    rows = seeds[seeds["induction"].astype(str).str.strip().str.lower() == induction]
    if rows.empty:
        raise ValueError(f"{seed_path} has no rows with induction='{induction}'")
    rows[["text", "category"]].to_csv(path, index=False)
    print("!" * 70)
    print(f"[WARNING] {path} not found: created it from {seed_path} ({len(rows)} {induction} prompts).")
    print("[WARNING] These are DEMO prompts, not the HarmBench/AdvBench datasets of the thesis.")
    print("!" * 70)


def _load_dataset(path):
    print(f"[INFO] Loading dataset: {path}")
    df = pd.read_csv(path, keep_default_na=False, dtype=str)
    missing = {"text", "category"} - set(df.columns)
    if missing:
        raise ValueError(f"{path} is missing columns: {sorted(missing)}")
    df["category"] = df["category"].str.strip().str.lower()
    if "behavior" not in df.columns:
        df["behavior"] = df["text"]
    defaults = {"context": "", "source": "custom", "evaluation": "classifier", "category_reason": ""}
    for col, value in defaults.items():
        if col not in df.columns:
            df[col] = value
    if "behavior_id" not in df.columns:
        df["behavior_id"] = [f"row_{i}" for i in range(len(df))]

    unknown = set(df["category"]) - VALID_CATEGORIES
    if unknown:
        raise ValueError(f"{path} has unknown categories {sorted(unknown)}; expected {sorted(VALID_CATEGORIES)}")
    unknown = set(df["evaluation"]) - VALID_EVALUATIONS
    if unknown:
        raise ValueError(f"{path} has unknown evaluation methods {sorted(unknown)}")
    if (df["text"].str.strip() == "").any():
        raise ValueError(f"{path} has empty prompts")
    if df["text"].duplicated().any():
        # Answers are matched to their seed by prompt text.
        raise ValueError(f"{path} has duplicated prompts: {df.loc[df['text'].duplicated(), 'text'].tolist()[:3]}")
    return df.reset_index(drop=True)


def prepare_data(dataset_dir="data"):
    """Load both induction datasets as DataFrames, creating missing ones from default_seed.csv.

    Returns (df_simple, df_advanced, generated, paths); `generated` tells which datasets
    were created from the default seed in this run.
    """
    os.makedirs(dataset_dir, exist_ok=True)
    paths = {
        "simple": os.path.join(dataset_dir, "simple_induction.csv"),
        "advanced": os.path.join(dataset_dir, "advanced_induction.csv"),
    }
    generated = {}
    for induction, path in paths.items():
        generated[induction] = not os.path.exists(path)
        if generated[induction]:
            _create_from_default_seed(path, induction, dataset_dir)
    return _load_dataset(paths["simple"]), _load_dataset(paths["advanced"]), generated, paths
