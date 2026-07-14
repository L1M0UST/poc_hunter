from __future__ import annotations

import tarfile
import hashlib
from pathlib import Path

from .ck_import import import_results
from .config import load_yaml, resolve_path
from .offline_extract import extract_tasks
from .state import StateStore


def _safe_extract(archive_path: Path, target_dir: Path) -> Path:
    target_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "r:gz") as tar:
        members = tar.getmembers()
        if not members:
            raise ValueError(f"empty archive: {archive_path}")
        root_name = members[0].name.split("/", 1)[0]
        target_root = (target_dir / root_name).resolve()
        base = target_dir.resolve()
        for member in members:
            member_target = (target_dir / member.name).resolve()
            try:
                member_target.relative_to(base)
            except ValueError:
                raise ValueError(f"unsafe archive member: {member.name}")
        tar.extractall(target_dir)
    return target_root


def process_inbox(
    *,
    inbox_dir: Path,
    work_dir: Path,
    results_dir: Path,
    ck_config_path: Path | None = None,
) -> list[Path]:
    results_dir.mkdir(parents=True, exist_ok=True)
    produced: list[Path] = []
    pipeline_cfg = load_yaml("configs/pipeline.yaml")
    state_path = resolve_path((pipeline_cfg.get("state") or {}).get("sqlite_path", "data/state/poc_hunter.sqlite"))
    with StateStore(state_path) as state:
        for archive_path in sorted(inbox_dir.glob("*.tar.gz")):
            archive_hash = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            if state.has_processed_archive(archive_hash):
                continue
            package_dir = _safe_extract(archive_path, work_dir)
            tasks_path = package_dir / "tasks.jsonl"
            if not tasks_path.exists():
                raise FileNotFoundError(f"tasks.jsonl not found in {package_dir}")
            result_path = results_dir / f"{archive_path.stem}.results.jsonl"
            extract_tasks(tasks_path, result_path, package_dir=package_dir)
            if ck_config_path:
                import_results(result_path, ck_config_path, state_path=state_path)
            state.mark_processed_archive(archive_hash, str(archive_path), str(result_path))
            produced.append(result_path)
    return produced


def process_inbox_from_config(config_path: Path, *, import_ck: bool = False) -> list[Path]:
    cfg = load_yaml(config_path)
    offline = cfg.get("offline") or {}
    ck_config = Path("configs/clickhouse_config.yaml") if import_ck else None
    return process_inbox(
        inbox_dir=resolve_path(offline.get("inbox_dir", "data/offline/inbox")),
        work_dir=resolve_path(offline.get("work_dir", "data/offline/work")),
        results_dir=resolve_path(offline.get("results_dir", "data/offline/results")),
        ck_config_path=ck_config,
    )
