from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx

from .task_builder import build_messages_from_task
from .text_utils import parse_json_object, strip_think_tags


def _chat_completions_url() -> str:
    explicit = os.getenv("OFFLINE_LLM_CHAT_COMPLETIONS_URL")
    if explicit:
        return explicit
    base_url = os.getenv("OFFLINE_LLM_BASE_URL", "http://127.0.0.1:8000/v1")
    return base_url.rstrip("/") + "/chat/completions"


def _headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    api_key = os.getenv("OFFLINE_LLM_API_KEY")
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def _extract_content(response_json: dict[str, Any]) -> str:
    choices = response_json.get("choices") or []
    if not choices:
        return ""
    message = choices[0].get("message") or {}
    return str(message.get("content") or "")


def extract_tasks(tasks_path: Path, output_path: Path, *, package_dir: Path | None = None) -> None:
    url = _chat_completions_url()
    model = os.getenv("OFFLINE_LLM_MODEL", "minmax2.7")
    timeout = float(os.getenv("OFFLINE_LLM_TIMEOUT", "180"))
    package_dir = package_dir or tasks_path.parent
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with (
        httpx.Client(timeout=timeout) as client,
        tasks_path.open("r", encoding="utf-8") as src,
        output_path.open("w", encoding="utf-8") as dst,
    ):
        for line in src:
            if not line.strip():
                continue
            task = json.loads(line)
            messages = task.get("messages") or build_messages_from_task(task, package_dir)
            payload = {
                "model": model,
                "messages": messages,
                "stream": False,
            }
            response = client.post(url, headers=_headers(), json=payload)
            response.raise_for_status()
            raw = _extract_content(response.json())
            parsed: dict[str, Any] | None = parse_json_object(raw)
            dst.write(
                json.dumps(
                    {
                        "task_id": task["task_id"],
                        "cve": task["cve"],
                        "source_urls": task.get("source_urls", []),
                        "raw_response": strip_think_tags(raw),
                        "parsed": parsed,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
