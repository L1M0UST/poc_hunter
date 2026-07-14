from __future__ import annotations

import json
import re
from typing import Any


THINK_RE = re.compile(r"<think\b[^>]*>.*?</think>", re.IGNORECASE | re.DOTALL)
OPEN_THINK_RE = re.compile(r"<think\b[^>]*>.*$", re.IGNORECASE | re.DOTALL)
THINK_TAG_RE = re.compile(r"</?think\b[^>]*>", re.IGNORECASE)


def strip_think_tags(text: str) -> str:
    cleaned = THINK_RE.sub("", text or "")
    cleaned = OPEN_THINK_RE.sub("", cleaned)
    cleaned = THINK_TAG_RE.sub("", cleaned)
    return cleaned.strip()


def clean_llm_text(text: str) -> str:
    cleaned = strip_think_tags(text)
    cleaned = re.sub(r"^```(?:json|text)?\s*", "", cleaned.strip(), flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```\s*$", "", cleaned.strip())
    return cleaned.strip()


def parse_json_object(raw_text: str) -> dict[str, Any] | None:
    text = clean_llm_text(str(raw_text or ""))

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None


def normalize_extraction_result(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        parsed = parse_json_object(value)
        return parsed or {"extractable": False, "reason": "invalid_json"}
    if not isinstance(value, dict):
        return {"extractable": False, "reason": "invalid_result"}

    if value.get("extractable") is not True:
        reason = clean_llm_text(str(value.get("reason", "") or "not_extractable"))
        return {"extractable": False, "reason": reason}

    signature = value.get("signature")
    if not isinstance(signature, dict):
        return {"extractable": False, "reason": "missing_signature"}

    normalized_signature = {
        str(key): clean_llm_text(str(val or ""))
        for key, val in signature.items()
    }
    return {"extractable": True, "signature": normalized_signature}
