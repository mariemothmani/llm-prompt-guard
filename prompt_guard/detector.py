"""Combines the rule layer and the ML layer into one verdict."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum

from . import rules
from .classifier import Classifier


class Action(str, Enum):
    ALLOW = "allow"
    FLAG = "flag"    # let through but log / alert the SOC
    BLOCK = "block"


@dataclass
class Verdict:
    action: Action
    risk_score: float
    rule_score: float
    ml_score: float | None
    matches: list[dict] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["action"] = self.action.value
        return d


class PromptInjectionDetector:
    """Two-layer detector.

    risk = max(rule_score, ml_score), then thresholds decide the action.
    Taking the max means a strong signal from either layer is enough,
    which favours recall — the right trade-off for a security filter.
    """

    def __init__(self, classifier: Classifier | None = None,
                 block_threshold: float = 0.8, flag_threshold: float = 0.5,
                 max_input_chars: int = 20_000):
        if not 0 <= flag_threshold <= block_threshold <= 1:
            raise ValueError("expected 0 <= flag_threshold <= block_threshold <= 1")
        self.classifier = classifier
        self.block_threshold = block_threshold
        self.flag_threshold = flag_threshold
        self.max_input_chars = max_input_chars

    def analyze(self, text: str) -> Verdict:
        text = text[: self.max_input_chars]
        matches = rules.scan(text)
        r_score = rules.rule_score(matches)
        ml_score = self.classifier.score(text) if self.classifier else None

        risk = max(r_score, ml_score or 0.0)
        if risk >= self.block_threshold:
            action = Action.BLOCK
        elif risk >= self.flag_threshold:
            action = Action.FLAG
        else:
            action = Action.ALLOW

        return Verdict(
            action=action,
            risk_score=round(risk, 4),
            rule_score=r_score,
            ml_score=ml_score,
            matches=[asdict(m) for m in matches],
            categories=sorted({m.category for m in matches}),
        )
