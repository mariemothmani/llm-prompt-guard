"""Evaluate the detector on a labeled JSONL dataset.

Each line: {"text": "...", "label": 1}   (1 = injection, 0 = benign)

Usage:
    python scripts/evaluate.py data/sample_prompts.jsonl            # rules only
    python scripts/evaluate.py data/sample_prompts.jsonl --ml       # rules + ML
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prompt_guard import Action, PromptInjectionDetector  # noqa: E402
from prompt_guard.classifier import load_default  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("--ml", action="store_true", help="enable the ML layer")
    ap.add_argument("--show-errors", action="store_true")
    args = ap.parse_args()

    det = PromptInjectionDetector(classifier=load_default() if args.ml else None)
    rows = [json.loads(l) for l in Path(args.dataset).read_text(encoding="utf-8").splitlines() if l.strip()]

    tp = fp = tn = fn = 0
    errors = []
    start = time.perf_counter()
    for row in rows:
        predicted = det.analyze(row["text"]).action is not Action.ALLOW
        actual = bool(row["label"])
        if predicted and actual: tp += 1
        elif predicted and not actual: fp += 1; errors.append(("FP", row["text"]))
        elif not predicted and actual: fn += 1; errors.append(("FN", row["text"]))
        else: tn += 1
    elapsed_ms = (time.perf_counter() - start) * 1000 / max(len(rows), 1)

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0

    mode = "rules + ML" if det.classifier else "rules only"
    print(f"\nMode: {mode}  |  samples: {len(rows)}  |  avg latency: {elapsed_ms:.1f} ms\n")
    print("| Metric | Value |\n|---|---|")
    print(f"| Precision | {precision:.2%} |\n| Recall | {recall:.2%} |")
    print(f"| F1-score | {f1:.2%} |\n| False positive rate | {fpr:.2%} |")
    print(f"\nConfusion: TP={tp} FP={fp} TN={tn} FN={fn}")

    if args.show_errors:
        for kind, text in errors:
            print(f"  [{kind}] {text[:100]}")


if __name__ == "__main__":
    main()
