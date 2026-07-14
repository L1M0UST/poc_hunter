from __future__ import annotations

import json
import hashlib
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import clickhouse_connect

from .config import load_yaml, resolve_path
from .schema import EXPLOIT_SIGNATURE_COLUMNS, EXPLOIT_SIGNATURE_RESULT_KEYS
from .state import StateStore


def _signature_hash(signature: dict[str, Any], source: str) -> str:
    payload = {
        "signature": {key: str(signature.get(key, "") or "") for key in EXPLOIT_SIGNATURE_RESULT_KEYS},
        "source": source,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def _signature_row(item: dict[str, Any]) -> tuple[tuple[str, ...], str] | None:
    parsed = item.get("parsed") or {}
    if parsed.get("extractable") is not True:
        return None
    signature = parsed.get("signature") or {}
    source = ",".join(item.get("source_urls") or [])
    storage_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    row = tuple(
        [str(uuid.uuid4())]
        + [str(signature.get(key, "") or "") for key in EXPLOIT_SIGNATURE_RESULT_KEYS[:-1]]
        + [source, str(signature.get("description", "") or ""), storage_time]
    )
    return row, _signature_hash(signature, source)


def import_results(results_path: Path, ck_config_path: Path, *, state_path: Path | None = None) -> int:
    cfg = load_yaml(ck_config_path).get("clickhouse", {})
    pipeline_cfg = load_yaml("configs/pipeline.yaml")
    if state_path is None:
        state_path = resolve_path((pipeline_cfg.get("state") or {}).get("sqlite_path", "data/state/poc_hunter.sqlite"))
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
    imported_marks: list[tuple[str, str, str]] = []
    try:
        with StateStore(state_path) as state:
            for line in results_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                parsed_row = _signature_row(json.loads(line))
                if not parsed_row:
                    continue
                row, signature_hash = parsed_row
                if state.has_imported_signature(signature_hash):
                    continue
                rows.append(row)
                imported_marks.append((signature_hash, row[1], row[9]))
            if rows:
                client.insert(table, rows, column_names=EXPLOIT_SIGNATURE_COLUMNS)
                for signature_hash, related_cve, source in imported_marks:
                    state.mark_imported_signature(signature_hash, related_cve, source)
        return len(rows)
    finally:
        client.close()
