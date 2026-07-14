from __future__ import annotations

import hashlib
import json
import tarfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import github_token, resolve_path
from .github_api import GitHubClient, is_probably_source_file, parse_github_repo
from .schema import EXPECTED_JSON_SHAPE
from .state import StateStore


RELEVANT_NAME_MARKERS = (
    "readme",
    "poc",
    "exp",
    "exploit",
    "cve",
    "payload",
    "scan",
    "scanner",
    "check",
    "main",
)

SYSTEM_PROMPT = """You are an exploit-signature extraction engineer.
Extract traffic-detection fields from public PoC, EXP, README, and CVE descriptions.
Return JSON only. If evidence is insufficient, return {"extractable": false, "reason": "..."}.
If extractable, return {"extractable": true, "signature": {...}} compatible with the target schema."""


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def _write_blob(package_dir: Path, content: str) -> dict[str, Any]:
    data = content.encode("utf-8", errors="ignore")
    content_sha = hashlib.sha256(data).hexdigest()
    rel_path = Path("evidence") / "blobs" / content_sha[:2] / content_sha
    target = package_dir / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        target.write_bytes(data)
    return {
        "content_sha256": content_sha,
        "content_path": rel_path.as_posix(),
        "content_bytes": len(data),
    }


def _select_files(tree: list[dict[str, Any]], *, max_files: int) -> list[dict[str, Any]]:
    candidates: list[tuple[int, dict[str, Any]]] = []
    for item in tree:
        path = item.get("path") or ""
        if not is_probably_source_file(path):
            continue
        name = Path(path).name.lower()
        score = 0
        if name.startswith("readme"):
            score += 100
        score += sum(20 for marker in RELEVANT_NAME_MARKERS if marker in name)
        score += sum(5 for marker in RELEVANT_NAME_MARKERS if marker in path.lower())
        if score <= 0:
            continue
        candidates.append((-score, item))
    candidates.sort(key=lambda pair: (pair[0], pair[1].get("path", "")))
    return [item for _, item in candidates[:max_files]]


def _build_user_prompt(cve: str, description: str, repos: list[dict[str, Any]]) -> str:
    payload = {
        "target_schema": EXPECTED_JSON_SHAPE,
        "cve": cve,
        "cve_description": description,
        "evidence_repos": repos,
        "rules": [
            "Prefer HTTP path, method, headers, body markers, response status, and response indicators.",
            "Do not invent missing fields. Return extractable=false if evidence is too weak.",
            "Use Chinese for description, while preserving product names, vulnerability classes, and endpoint names.",
            "Do not output source or storage_time. The import program fills them.",
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def build_messages_from_task(task: dict[str, Any], package_dir: Path) -> list[dict[str, str]]:
    repos: list[dict[str, Any]] = []
    for repo in task.get("evidence_repos") or []:
        selected_files = []
        for file_info in repo.get("selected_files") or []:
            content_path = package_dir / file_info["content_path"]
            selected_files.append(
                {
                    "path": file_info.get("path", ""),
                    "sha": file_info.get("sha", ""),
                    "content_sha256": file_info.get("content_sha256", ""),
                    "content": content_path.read_text(encoding="utf-8", errors="replace"),
                }
            )
        repos.append(
            {
                "url": repo.get("url", ""),
                "metadata": repo.get("metadata", {}),
                "selected_files": selected_files,
            }
        )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": _build_user_prompt(task.get("cve", ""), task.get("cve_description", ""), repos)},
    ]


def _collect_repo(
    client: GitHubClient,
    cve: str,
    description: str,
    url: str,
    *,
    max_files_per_repo: int,
    max_file_bytes: int,
    max_repo_bytes: int,
) -> dict[str, Any] | None:
    repo = parse_github_repo(url)
    if repo is None:
        return None
    metadata = client.repo_metadata(repo)
    branch = metadata.get("default_branch") or "main"
    tree = client.tree(repo, branch)
    selected = _select_files(tree, max_files=max_files_per_repo)

    total = 0
    files: list[dict[str, str]] = []
    for item in selected:
        path = item.get("path") or ""
        size = int(item.get("size") or 0)
        if size > max_file_bytes or total >= max_repo_bytes:
            continue
        content = client.raw_file(repo, branch, path, max_file_bytes)
        total += len(content.encode("utf-8", errors="ignore"))
        files.append(
            {
                "path": path,
                "sha": item.get("sha", ""),
                "content": content,
            }
        )

    if not files:
        return None
    commit_sha = metadata.get("pushed_at") or metadata.get("updated_at") or ""
    content_hash = _sha256_text(json.dumps(files, sort_keys=True, ensure_ascii=False))
    return {
        "cve": cve,
        "description": description,
        "repo_key": repo.key,
        "url": repo.url,
        "commit_sha": commit_sha,
        "content_hash": content_hash,
        "metadata": {
            "stars": metadata.get("stargazers_count", 0),
            "forks": metadata.get("forks_count", 0),
            "updated_at": metadata.get("updated_at", ""),
            "default_branch": branch,
            "description": metadata.get("description") or "",
        },
        "selected_files": files,
    }


def build_task_package(
    records: list[dict[str, str]],
    config: dict[str, Any],
    *,
    out_dir: Path | None = None,
    limit: int | None = None,
) -> Path:
    package_cfg = config.get("package") or {}
    github_cfg = config.get("github") or {}
    state_cfg = config.get("state") or {}

    max_files_per_repo = int(package_cfg.get("max_files_per_repo", 8))
    max_file_bytes = int(package_cfg.get("max_file_bytes", 120_000))
    max_repo_bytes = int(package_cfg.get("max_repo_bytes", 480_000))
    concurrency = int(github_cfg.get("concurrency", 8))

    run_id = datetime.now().strftime("%Y%m%d%H%M%S")
    target_dir = out_dir or resolve_path(package_cfg.get("outbox_dir", "data/outbox")) / run_id
    target_dir.mkdir(parents=True, exist_ok=True)

    state_path = resolve_path(state_cfg.get("sqlite_path", "data/state/poc_hunter.sqlite"))
    scoped_records = records[:limit] if limit else records

    repo_jobs = [
        (
            item.get("cve_code", "").upper(),
            item.get("cve_description", ""),
            item.get("cve_poc_relative_url", ""),
        )
        for item in scoped_records
        if item.get("cve_code") and item.get("cve_poc_relative_url")
    ]

    collected: list[dict[str, Any]] = []
    with GitHubClient(token=github_token(config), timeout=float(github_cfg.get("timeout", 30))) as client:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = [
                pool.submit(
                    _collect_repo,
                    client,
                    cve,
                    desc,
                    url,
                    max_files_per_repo=max_files_per_repo,
                    max_file_bytes=max_file_bytes,
                    max_repo_bytes=max_repo_bytes,
                )
                for cve, desc, url in repo_jobs
            ]
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception as exc:
                    print(f"collect failed: {exc}")
                    continue
                if result:
                    collected.append(result)

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    descriptions: dict[str, str] = {}
    for repo_info in collected:
        grouped[repo_info["cve"]].append(repo_info)
        descriptions[repo_info["cve"]] = repo_info["description"]

    tasks_path = target_dir / "tasks.jsonl"
    manifest_path = target_dir / "manifest.json"
    task_count = 0
    repo_count = 0
    blob_count = 0

    with StateStore(state_path) as state, tasks_path.open("w", encoding="utf-8") as out:
        for cve, repos in sorted(grouped.items()):
            evidence_repos = []
            repo_hash_parts = []
            source_urls = []
            for repo_info in repos:
                repo_count += 1
                state.upsert_repo(
                    repo_info["repo_key"],
                    cve,
                    repo_info["url"],
                    repo_info["commit_sha"],
                    repo_info["content_hash"],
                )
                source_urls.append(repo_info["url"])
                repo_hash_parts.append(f"{repo_info['repo_key']}:{repo_info['content_hash']}")
                selected_files = []
                for file_info in repo_info["selected_files"]:
                    blob_info = _write_blob(target_dir, file_info["content"])
                    if blob_info["content_bytes"]:
                        blob_count += 1
                    selected_files.append(
                        {
                            "path": file_info["path"],
                            "sha": file_info.get("sha", ""),
                            **blob_info,
                        }
                    )
                evidence_repos.append(
                    {
                        "url": repo_info["url"],
                        "metadata": repo_info["metadata"],
                        "selected_files": selected_files,
                    }
                )

            task_id = _sha256_text(cve + "|" + "|".join(sorted(repo_hash_parts)))
            if state.has_task(task_id):
                continue

            line = {
                "task_id": task_id,
                "cve": cve,
                "cve_description": descriptions.get(cve, ""),
                "source_urls": sorted(set(source_urls)),
                "evidence_repos": evidence_repos,
            }
            out.write(json.dumps(line, ensure_ascii=False) + "\n")
            state.mark_task(task_id, cve, str(tasks_path))
            task_count += 1

    manifest = {
        "package_format": "poc-hunter-task-package-v2",
        "run_id": run_id,
        "tasks_path": str(tasks_path),
        "records_seen": len(scoped_records),
        "repos_collected": repo_count,
        "tasks_created": task_count,
        "blob_files_written": blob_count,
        "source": "ycdxsb/PocOrExp_in_Github",
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    transfer_dir = resolve_path(package_cfg.get("transfer_dir", "data/transfer"))
    transfer_dir.mkdir(parents=True, exist_ok=True)
    archive_path = transfer_dir / f"poc_hunter_tasks_{run_id}.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(target_dir, arcname=target_dir.name)
    manifest["archive_path"] = str(archive_path)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return target_dir
