"""Append-only JSONL logging for one evaluated configuration.

Layout (one directory per run, never reused):

    runs/<config_label>/<YYYYmmdd-HHMMSS>/
        manifest.json            commit, arguments, judge, datasets (hash + counts), versions
        interactions.jsonl       every target call: prompt, response, verdict, phase, category, pass
        giskard_issues.jsonl     every Giskard issue + its failing examples + mapped category
        giskard_failures.jsonl   scan crashes and failed Giskard detectors
        passes.jsonl             per-pass summary (hits, valid, errors per category)
        giskard_pass_XX.html     Giskard HTML report of each pass
        metrics_report.json      final metrics
        risk_visual.html         final chart
"""
import json
import os
import re
import threading
from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc).isoformat()


def _safe(obj):
    """Make objects JSON-serializable without losing information."""
    try:
        json.dumps(obj)
        return obj
    except TypeError:
        if isinstance(obj, dict):
            return {str(k): _safe(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple, set)):
            return [_safe(v) for v in obj]
        return str(obj)


class RunLogger:
    def __init__(self, runs_dir, config_label):
        if not re.fullmatch(r"[A-Za-z0-9._\-]+", config_label):
            raise ValueError("--config-label may only contain letters, digits, '.', '_' and '-'")
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.run_dir = os.path.join(runs_dir, config_label, stamp)
        # exist_ok=False: an existing run directory is never overwritten.
        os.makedirs(self.run_dir, exist_ok=False)
        self.config_label = config_label
        self.run_id = f"{config_label}/{stamp}"
        self._lock = threading.Lock()

    def path(self, name):
        return os.path.join(self.run_dir, name)

    def append(self, filename, record):
        record = {"run_id": self.run_id, "config": self.config_label, "ts": _now(), **record}
        line = json.dumps(_safe(record), ensure_ascii=False)
        with self._lock:
            with open(self.path(filename), "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())

    def write_json_once(self, filename, data):
        """Write a JSON file that must not already exist."""
        with open(self.path(filename), "x", encoding="utf-8") as f:
            json.dump(_safe(data), f, indent=2, ensure_ascii=False)
