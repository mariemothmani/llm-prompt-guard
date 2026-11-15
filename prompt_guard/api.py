"""FastAPI service: a guard placed in front of a chatbot.

Endpoints
  POST /analyze  -> returns the verdict only
  POST /chat     -> runs the guard, then forwards safe messages to the bot
  GET  /health

Every FLAG/BLOCK decision is written as a JSON line to the security log,
ready to be shipped to a SIEM (Wazuh, Elastic...).
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

from fastapi import FastAPI
from pydantic import BaseModel, Field

from . import __version__
from .classifier import load_default
from .detector import Action, PromptInjectionDetector

security_log = logging.getLogger("prompt_guard.security")
if not security_log.handlers:
    handler = logging.FileHandler(os.getenv("PG_LOG_FILE", "security_events.jsonl"))
    handler.setFormatter(logging.Formatter("%(message)s"))
    security_log.addHandler(handler)
    security_log.setLevel(logging.INFO)


def build_detector() -> PromptInjectionDetector:
    use_ml = os.getenv("PG_USE_ML", "1") == "1"
    return PromptInjectionDetector(classifier=load_default() if use_ml else None)


app = FastAPI(title="LLM Prompt Guard", version=__version__)
detector = build_detector()


class Message(BaseModel):
    text: str = Field(..., min_length=1, max_length=20_000)
    user_id: str = "anonymous"


def log_event(msg: Message, verdict: dict) -> None:
    security_log.info(json.dumps({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "prompt_injection",
        "user_id": msg.user_id,
        "action": verdict["action"],
        "risk_score": verdict["risk_score"],
        "categories": verdict["categories"],
        "rule_ids": [m["rule_id"] for m in verdict["matches"]],
        "input_preview": msg.text[:200],
    }, ensure_ascii=False))


def demo_bot(text: str) -> str:
    """Stand-in for the real LLM. Replace with your model call."""
    return f"(demo bot) You said: {text[:200]}"


@app.get("/health")
def health():
    return {"status": "ok", "ml_enabled": detector.classifier is not None}


@app.post("/analyze")
def analyze(msg: Message):
    verdict = detector.analyze(msg.text).to_dict()
    if verdict["action"] != Action.ALLOW.value:
        log_event(msg, verdict)
    return verdict


@app.post("/chat")
def chat(msg: Message):
    verdict = detector.analyze(msg.text).to_dict()
    if verdict["action"] != Action.ALLOW.value:
        log_event(msg, verdict)
    if verdict["action"] == Action.BLOCK.value:
        return {"blocked": True, "reply": None,
                "reason": verdict["categories"] or ["ml_classifier"],
                "risk_score": verdict["risk_score"]}
    return {"blocked": False, "reply": demo_bot(msg.text),
            "risk_score": verdict["risk_score"]}
