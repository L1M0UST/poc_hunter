from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PIPELINE_CONFIG = PROJECT_ROOT / "configs" / "pipeline.yaml"


def load_yaml(path: str | Path) -> dict[str, Any]:
    target = Path(path)
    if not target.is_absolute():
        target = PROJECT_ROOT / target
    if not target.exists():
        return {}
    return yaml.safe_load(target.read_text(encoding="utf-8")) or {}


def resolve_path(value: str | Path, *, base: Path = PROJECT_ROOT) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return base / path


def read_secret_file(path: str | Path | None) -> str:
    if not path:
        return ""
    target = resolve_path(path)
    if not target.exists():
        return ""
    return target.read_text(encoding="utf-8", errors="ignore").strip()


def github_token(config: dict[str, Any]) -> str:
    return (
        os.getenv("GITHUB_TOKEN")
        or read_secret_file((config.get("github") or {}).get("token_file"))
        or ""
    )
