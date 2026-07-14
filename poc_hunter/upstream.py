from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from md_processor.get_info import parse_cve_md


def load_records_from_json(path: Path) -> list[dict[str, str]]:
    return json.loads(path.read_text(encoding="utf-8"))


def fetch_upstream_markdown(url: str, timeout: float = 30.0) -> str:
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(url)
        response.raise_for_status()
        return response.text


def load_upstream_records(config: dict[str, Any], *, year: int | None = None) -> list[dict[str, str]]:
    source_cfg = config.get("source") or {}
    local_json = source_cfg.get("local_json")
    if local_json:
        path = Path(local_json)
        if not path.is_absolute():
            path = Path.cwd() / path
        if path.exists():
            return load_records_from_json(path)

    template = source_cfg.get(
        "upstream_raw_url",
        "https://raw.githubusercontent.com/ycdxsb/PocOrExp_in_Github/main/{year}",
    )
    min_year = int(source_cfg.get("min_year", 2026))
    current_year = datetime.now().year
    years = [year] if year else list(range(min_year, current_year + 1))
    if any(target_year < min_year for target_year in years):
        raise ValueError(f"Only CVE data from {min_year} and later is supported")

    records: list[dict[str, str]] = []
    for target_year in years:
        url = template.format(year=target_year)
        try:
            markdown = fetch_upstream_markdown(url)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                print(f"skip missing upstream year: {target_year}", file=sys.stderr)
                continue
            raise
        records.extend(
            {
                "cve_code": record.cve_code,
                "cve_description": record.cve_description,
                "cve_poc_relative_url": record.cve_poc_relative_url,
            }
            for record in parse_cve_md(markdown)
        )
    return records
