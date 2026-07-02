from __future__ import annotations

import sqlite3
from pathlib import Path


class StateStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._init_tables()

    def _init_tables(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS source_repos (
                repo_key TEXT PRIMARY KEY,
                cve TEXT NOT NULL,
                url TEXT NOT NULL,
                commit_sha TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS llm_tasks (
                task_id TEXT PRIMARY KEY,
                cve TEXT NOT NULL,
                package_path TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        self.conn.commit()

    def is_repo_unchanged(self, repo_key: str, commit_sha: str, content_hash: str) -> bool:
        row = self.conn.execute(
            "SELECT commit_sha, content_hash FROM source_repos WHERE repo_key = ?",
            (repo_key,),
        ).fetchone()
        return bool(row and row[0] == commit_sha and row[1] == content_hash)

    def upsert_repo(self, repo_key: str, cve: str, url: str, commit_sha: str, content_hash: str) -> None:
        self.conn.execute(
            """
            INSERT INTO source_repos(repo_key, cve, url, commit_sha, content_hash)
            VALUES(?, ?, ?, ?, ?)
            ON CONFLICT(repo_key) DO UPDATE SET
                cve = excluded.cve,
                url = excluded.url,
                commit_sha = excluded.commit_sha,
                content_hash = excluded.content_hash,
                updated_at = CURRENT_TIMESTAMP
            """,
            (repo_key, cve, url, commit_sha, content_hash),
        )
        self.conn.commit()

    def has_task(self, task_id: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM llm_tasks WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        return row is not None

    def mark_task(self, task_id: str, cve: str, package_path: str, status: str = "packaged") -> None:
        self.conn.execute(
            """
            INSERT INTO llm_tasks(task_id, cve, package_path, status)
            VALUES(?, ?, ?, ?)
            ON CONFLICT(task_id) DO UPDATE SET
                package_path = excluded.package_path,
                status = excluded.status
            """,
            (task_id, cve, package_path, status),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "StateStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
