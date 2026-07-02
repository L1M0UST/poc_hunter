from __future__ import annotations

import argparse
import json
from pathlib import Path

from .config import DEFAULT_PIPELINE_CONFIG, PROJECT_ROOT, load_yaml
from .schema import EXPLOIT_SIGNATURE_COLUMNS


def print_schema() -> None:
    cfg = load_yaml(PROJECT_ROOT / "configs" / "clickhouse_config.yaml").get("clickhouse", {})
    print(f"configured_table: {cfg.get('database', 'default')}.{cfg.get('table', 'exploit_signature')}")
    print("configured_insert_columns:")
    for col in EXPLOIT_SIGNATURE_COLUMNS:
        print(f"- {col}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="poc-hunter")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("schema")

    build = sub.add_parser("build-tasks")
    build.add_argument("--config", default=str(DEFAULT_PIPELINE_CONFIG))
    build.add_argument("--year", type=int)
    build.add_argument("--from-output", help="Use an existing cve_poc json instead of fetching upstream")
    build.add_argument("--limit", type=int)
    build.add_argument("--out-dir")

    sftp = sub.add_parser("sftp-push")
    sftp.add_argument("local_dir")
    sftp.add_argument("remote", help="user@host:/remote/path")
    sftp.add_argument("--port", type=int, default=22)
    sftp.add_argument("--identity-file")

    offline = sub.add_parser("offline-extract")
    offline.add_argument("tasks_jsonl")
    offline.add_argument("results_jsonl")

    ck = sub.add_parser("ck-import")
    ck.add_argument("results_jsonl")
    ck.add_argument("--ck-config", default="configs/clickhouse_config.yaml")

    args = parser.parse_args(argv)
    if args.command == "schema":
        print_schema()
    elif args.command == "build-tasks":
        from .task_builder import build_task_package
        from .upstream import load_records_from_json, load_upstream_records

        config = load_yaml(args.config)
        if args.from_output:
            records = load_records_from_json(Path(args.from_output))
        else:
            records = load_upstream_records(config, year=args.year)
        package_dir = build_task_package(
            records,
            config,
            out_dir=Path(args.out_dir) if args.out_dir else None,
            limit=args.limit,
        )
        manifest = json.loads((package_dir / "manifest.json").read_text(encoding="utf-8"))
        print(json.dumps(manifest, ensure_ascii=False, indent=2))
    elif args.command == "sftp-push":
        from .sftp_push import push_directory

        push_directory(Path(args.local_dir), args.remote, port=args.port, identity_file=args.identity_file)
    elif args.command == "offline-extract":
        from .offline_extract import extract_tasks

        extract_tasks(Path(args.tasks_jsonl), Path(args.results_jsonl))
    elif args.command == "ck-import":
        from .ck_import import import_results

        count = import_results(Path(args.results_jsonl), Path(args.ck_config))
        print(f"inserted_rows: {count}")
