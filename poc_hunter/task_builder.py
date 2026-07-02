from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT, github_token, resolve_path
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


SYSTEM_PROMPT = """你是安全检测数据抽取工程师。你的任务是从公开 PoC/EXP/README/漏洞描述中提取可用于流量检测的 Exploit Signature。
只返回 JSON，不要返回解释。无法可靠提取时返回 {"extractable": false, "reason": "..."}。
可以提取时返回 {"extractable": true, "signature": {...}}，signature 字段必须兼容目标表结构。"""


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


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
            "优先提取 HTTP 路径、方法、Header、Body、响应状态码、响应内容指纹。",
            "不要编造不存在的字段；证据不足时 extractable=false。",
            "description 使用中文，保留必要英文产品名、漏洞类型和接口名。",
            "source 不需要输出，入库程序会使用 evidence_repos 的 URL。",
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


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
                evidence_repos.append(
                    {
                        "url": repo_info["url"],
                        "metadata": repo_info["metadata"],
                        "selected_files": repo_info["selected_files"],
                    }
                )

            task_id = _sha256_text(cve + "|" + "|".join(sorted(repo_hash_parts)))
            if state.has_task(task_id):
                continue

            line = {
                "task_id": task_id,
                "cve": cve,
                "source_urls": sorted(set(source_urls)),
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": _build_user_prompt(cve, descriptions.get(cve, ""), evidence_repos)},
                ],
            }
            out.write(json.dumps(line, ensure_ascii=False) + "\n")
            state.mark_task(task_id, cve, str(tasks_path))
            task_count += 1

    manifest = {
        "run_id": run_id,
        "tasks_path": str(tasks_path),
        "records_seen": len(scoped_records),
        "repos_collected": repo_count,
        "tasks_created": task_count,
        "source": "ycdxsb/PocOrExp_in_Github",
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return target_dir
