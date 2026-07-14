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

            CREATE TABLE IF NOT EXISTS source_repo_state (
                cve_repo_key TEXT PRIMARY KEY,
                cve TEXT NOT NULL,
                repo_key TEXT NOT NULL,
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

            CREATE TABLE IF NOT EXISTS imported_signatures (
                signature_hash TEXT PRIMARY KEY,
                related_cve TEXT NOT NULL,
                source TEXT NOT NULL,
                imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS processed_archives (
                archive_hash TEXT PRIMARY KEY,
                archive_path TEXT NOT NULL,
                result_path TEXT NOT NULL,
                processed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        self.conn.commit()

    def is_repo_unchanged(self, repo_key: str, commit_sha: str, content_hash: str) -> bool:
        cve_repo_key = repo_key
        row = self.conn.execute(
            "SELECT commit_sha, content_hash FROM source_repo_state WHERE cve_repo_key = ?",
            (cve_repo_key,),
        ).fetchone()
        return bool(row and row[0] == commit_sha and row[1] == content_hash)

    def upsert_repo(self, repo_key: str, cve: str, url: str, commit_sha: str, content_hash: str) -> None:
        cve_repo_key = f"{cve}|{repo_key}"
        self.conn.execute(
            """
            INSERT INTO source_repo_state(cve_repo_key, cve, repo_key, url, commit_sha, content_hash)
            VALUES(?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_repo_key) DO UPDATE SET
                cve = excluded.cve,
                repo_key = excluded.repo_key,
                url = excluded.url,
                commit_sha = excluded.commit_sha,
                content_hash = excluded.content_hash,
                updated_at = CURRENT_TIMESTAMP
            """,
            (cve_repo_key, cve, repo_key, url, commit_sha, content_hash),
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

    def has_imported_signature(self, signature_hash: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM imported_signatures WHERE signature_hash = ?",
            (signature_hash,),
        ).fetchone()
        return row is not None

    def mark_imported_signature(self, signature_hash: str, related_cve: str, source: str) -> None:
        self.conn.execute(
            """
            INSERT OR IGNORE INTO imported_signatures(signature_hash, related_cve, source)
            VALUES(?, ?, ?)
            """,
            (signature_hash, related_cve, source),
        )
        self.conn.commit()

    def has_processed_archive(self, archive_hash: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM processed_archives WHERE archive_hash = ?",
            (archive_hash,),
        ).fetchone()
        return row is not None

    def mark_processed_archive(self, archive_hash: str, archive_path: str, result_path: str) -> None:
        self.conn.execute(
            """
            INSERT OR IGNORE INTO processed_archives(archive_hash, archive_path, result_path)
            VALUES(?, ?, ?)
            """,
            (archive_hash, archive_path, result_path),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "StateStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
