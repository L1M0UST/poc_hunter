from __future__ import annotations

import json
import re
from typing import Any


THINK_RE = re.compile(r"<think>.*?</think>", re.IGNORECASE | re.DOTALL)


def strip_think_tags(text: str) -> str:
    return THINK_RE.sub("", text or "").strip()


def parse_json_object(raw_text: str) -> dict[str, Any] | None:
    text = strip_think_tags(str(raw_text or "")).strip()
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*```\s*$", "", text)

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
