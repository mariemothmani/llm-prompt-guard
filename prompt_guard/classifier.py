"""Layer 2 — local ML classifier (Hugging Face transformers).

Default model: protectai/deberta-v3-base-prompt-injection-v2
(Apache-2.0, runs on CPU, ~180M params). Downloaded once, then fully offline.

The classifier is optional: if `transformers` is not installed or the model
cannot be loaded, the detector falls back to rules only.
"""

from __future__ import annotations

import logging
from typing import Protocol

log = logging.getLogger(__name__)

DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"


class Classifier(Protocol):
    name: str

    def score(self, text: str) -> float:
        """Return the probability (0..1) that the text is an injection."""
        ...


class HFClassifier:
    def __init__(self, model_name: str = DEFAULT_MODEL, max_length: int = 512):
        from transformers import pipeline  # imported lazily: optional dependency

        self.name = model_name
        self._pipe = pipeline("text-classification", model=model_name,
                              truncation=True, max_length=max_length)

    def score(self, text: str) -> float:
        result = self._pipe(text)[0]
        label, prob = result["label"].upper(), float(result["score"])
        return round(prob if label == "INJECTION" else 1.0 - prob, 4)


def load_default() -> Classifier | None:
    try:
        return HFClassifier()
    except Exception as exc:  # missing deps, no network on first run, etc.
        log.warning("ML classifier disabled, using rules only: %s", exc)
        return None
