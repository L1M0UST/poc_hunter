from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

import clickhouse_connect

from .config import load_yaml
from .schema import EXPLOIT_SIGNATURE_COLUMNS, EXPLOIT_SIGNATURE_RESULT_KEYS


def _signature_row(item: dict[str, Any]) -> tuple[str, ...] | None:
    parsed = item.get("parsed") or {}
    if parsed.get("extractable") is not True:
        return None
    signature = parsed.get("signature") or {}
    source = ",".join(item.get("source_urls") or [])
    return tuple(
        [str(uuid.uuid4())]
        + [str(signature.get(key, "") or "") for key in EXPLOIT_SIGNATURE_RESULT_KEYS[:-1]]
        + [source, str(signature.get("description", "") or "")]
    )


def import_results(results_path: Path, ck_config_path: Path) -> int:
    cfg = load_yaml(ck_config_path).get("clickhouse", {})
    client = clickhouse_connect.get_client(
        host=cfg.get("host", "localhost"),
        port=cfg.get("port", 8123),
        username=cfg.get("username", "default"),
        password=cfg.get("password", ""),
        database=cfg.get("database", "default"),
        secure=cfg.get("secure", False),
    )
    table = cfg.get("table", "exploit_signature")
    rows: list[tuple[str, ...]] = []
    try:
        for line in results_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = _signature_row(json.loads(line))
            if row:
                rows.append(row)
        if rows:
            client.insert(table, rows, column_names=EXPLOIT_SIGNATURE_COLUMNS)
        return len(rows)
    finally:
        client.close()
