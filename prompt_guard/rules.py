"""Layer 1 — rule-based detection of known prompt-injection patterns.

Fast, explainable, no dependencies. Each rule has an id, a category
(mapped to common attack families) and a weight between 0 and 1.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    pattern: re.Pattern
    weight: float
    description: str


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    category: str
    weight: float
    description: str
    excerpt: str


def _r(p: str) -> re.Pattern:
    return re.compile(p, re.IGNORECASE | re.DOTALL)


RULES: list[Rule] = [
    # --- Instruction override -------------------------------------------
    Rule("PI-001", "instruction_override",
         _r(r"\b(ignore|disregard|forget|skip|override)\b.{0,40}\b(previous|prior|above|earlier|all|your|the)\b.{0,30}\b(instructions?|rules?|prompts?|directives?|guidelines?)"),
         0.9, "Asks the model to ignore its previous instructions"),
    Rule("PI-002", "instruction_override",
         _r(r"\b(ignore[sz]?|oublie[sz]?|ignorez)\b.{0,40}\b(instructions?|consignes?|règles?)\b.{0,30}\b(précédentes?|ci-dessus|antérieures?)"),
         0.9, "French variant of instruction override"),
    Rule("PI-003", "instruction_override",
         _r(r"\b(new|updated|real)\s+(instructions?|system\s+prompt|rules?)\s*[:\-]"),
         0.6, "Injects a 'new instructions' block"),

    # --- System prompt extraction ---------------------------------------
    Rule("PI-010", "prompt_leaking",
         _r(r"\b(reveal|show|print|display|repeat|output|leak|tell me)\b.{0,40}\b(system\s+prompt|initial\s+(prompt|instructions)|hidden\s+instructions|your\s+instructions)"),
         0.85, "Tries to extract the system prompt"),
    Rule("PI-011", "prompt_leaking",
         _r(r"\b(affiche|révèle|montre|répète)\b.{0,40}\b(prompt\s+système|instructions\s+(initiales|cachées|système))"),
         0.85, "French variant of system prompt extraction"),
    Rule("PI-012", "prompt_leaking",
         _r(r"\b(what|repeat)\b.{0,20}\b(words|text)\b.{0,20}\b(above|before)\b"),
         0.5, "Asks for the text placed before the user input"),

    # --- Role-play / jailbreak personas ---------------------------------
    Rule("PI-020", "jailbreak_roleplay",
         _r(r"\b(DAN|do anything now|developer mode|jailbreak(ed)?|god mode|unfiltered mode)\b"),
         0.85, "Known jailbreak persona keywords"),
    Rule("PI-021", "jailbreak_roleplay",
         _r(r"\b(you are|you're|act as|pretend (to be|you are)|from now on you are)\b.{0,60}\b(no (rules|restrictions|limits|filters)|without (any )?(restrictions|filters|limits|ethics)|unrestricted|uncensored)"),
         0.8, "Persona without restrictions"),
    Rule("PI-022", "jailbreak_roleplay",
         _r(r"\b(tu es|agis comme|fais comme si)\b.{0,60}\b(sans (aucune )?(restriction|règle|limite|filtre)s?)"),
         0.8, "French variant of unrestricted persona"),

    # --- Delimiter / context manipulation -------------------------------
    Rule("PI-030", "delimiter_injection",
         _r(r"(<\|?(im_start|im_end|system|endoftext)\|?>|\[/?(INST|SYS)\]|<</?SYS>>|###\s*(system|instruction))"),
         0.75, "Chat-template or special tokens in user input"),
    Rule("PI-031", "delimiter_injection",
         _r(r"\b(end of (user )?(input|prompt|conversation)|system\s*:\s)"),
         0.5, "Fake end-of-input or fake system turn"),

    # --- Obfuscation ----------------------------------------------------
    Rule("PI-040", "obfuscation",
         _r(r"\b(decode|base64|rot13|hex)\b.{0,40}\b(and|then)\b.{0,20}\b(follow|execute|run|obey)"),
         0.7, "Asks to decode then execute hidden content"),

    # --- Data exfiltration (indirect injection payloads) ----------------
    Rule("PI-050", "exfiltration",
         _r(r"!\[[^\]]*\]\(https?://[^)]*\?(q|data|d|c)=[^)]*\)"),
         0.7, "Markdown image used to exfiltrate data via URL"),
    Rule("PI-051", "exfiltration",
         _r(r"\b(send|forward|post|upload|email)\b.{0,40}\b(conversation|chat history|api key|password|credentials|secrets?)\b.{0,40}\b(to|at)\b"),
         0.7, "Asks to send sensitive data somewhere"),
]

_B64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"), None)


def normalize(text: str) -> str:
    """Normalize unicode (homoglyph/fullwidth tricks) and strip zero-width chars."""
    text = unicodedata.normalize("NFKC", text)
    return text.translate(_ZERO_WIDTH)


def _decoded_base64_chunks(text: str) -> list[str]:
    out = []
    for chunk in _B64_RE.findall(text):
        try:
            decoded = base64.b64decode(chunk, validate=True).decode("utf-8")
        except Exception:
            continue
        if decoded.isprintable():
            out.append(decoded)
    return out


def _excerpt(text: str, m: re.Match, width: int = 30) -> str:
    start, end = max(m.start() - width, 0), min(m.end() + width, len(text))
    return text[start:end].replace("\n", " ")


def scan(text: str) -> list[RuleMatch]:
    """Return every rule matching the text (or its base64-decoded payloads)."""
    clean = normalize(text)
    candidates = [(clean, False)] + [(d, True) for d in _decoded_base64_chunks(clean)]

    matches: dict[str, RuleMatch] = {}
    for candidate, from_b64 in candidates:
        for rule in RULES:
            if rule.id in matches:
                continue
            m = rule.pattern.search(candidate)
            if m:
                desc = rule.description + (" (hidden in base64)" if from_b64 else "")
                matches[rule.id] = RuleMatch(rule.id, rule.category, rule.weight,
                                             desc, _excerpt(candidate, m))

    if clean != text and _has_invisible_chars(text):
        matches["PI-041"] = RuleMatch("PI-041", "obfuscation", 0.4,
                                      "Zero-width characters used to hide content", "")
    return list(matches.values())


def _has_invisible_chars(text: str) -> bool:
    return any(ord(c) in _ZERO_WIDTH for c in text)


def rule_score(matches: list[RuleMatch]) -> float:
    """Combine weights as independent evidence: 1 - prod(1 - w)."""
    remaining = 1.0
    for m in matches:
        remaining *= 1.0 - m.weight
    return round(1.0 - remaining, 4)
