from __future__ import annotations

import base64
import re
import time
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import quote, urlparse

import httpx


REPO_RE = re.compile(r"^/([^/]+)/([^/]+)")


@dataclass(frozen=True)
class RepoRef:
    owner: str
    name: str

    @property
    def key(self) -> str:
        return f"{self.owner}/{self.name}".lower()

    @property
    def url(self) -> str:
        return f"https://github.com/{self.owner}/{self.name}"


def parse_github_repo(url: str) -> RepoRef | None:
    parsed = urlparse((url or "").strip())
    if parsed.netloc.lower() != "github.com":
        return None
    match = REPO_RE.match(parsed.path)
    if not match:
        return None
    repo = match.group(2).removesuffix(".git")
    return RepoRef(owner=match.group(1), name=repo)


class GitHubClient:
    def __init__(self, token: str = "", timeout: float = 30.0) -> None:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "poc-hunter",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self.client = httpx.Client(
            base_url="https://api.github.com",
            headers=headers,
            timeout=timeout,
            follow_redirects=True,
        )
        self.raw_client = httpx.Client(timeout=timeout, follow_redirects=True, headers={"User-Agent": "poc-hunter"})

    def _get(self, url: str, **kwargs: Any) -> httpx.Response:
        last_exc: Exception | None = None
        for attempt in range(3):
            try:
                response = self.client.get(url, **kwargs)
                response.raise_for_status()
                return response
            except (httpx.HTTPError, httpx.TransportError) as exc:
                last_exc = exc
                if attempt < 2:
                    time.sleep(1.5 * (attempt + 1))
        raise last_exc or RuntimeError(f"request failed: {url}")

    def _raw_get(self, url: str) -> httpx.Response:
        last_exc: Exception | None = None
        for attempt in range(3):
            try:
                response = self.raw_client.get(url)
                response.raise_for_status()
                return response
            except (httpx.HTTPError, httpx.TransportError) as exc:
                last_exc = exc
                if attempt < 2:
                    time.sleep(1.5 * (attempt + 1))
        raise last_exc or RuntimeError(f"request failed: {url}")

    def close(self) -> None:
        self.client.close()
        self.raw_client.close()

    def __enter__(self) -> "GitHubClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def repo_metadata(self, repo: RepoRef) -> dict[str, Any]:
        response = self._get(f"/repos/{repo.owner}/{repo.name}")
        return response.json()

    def tree(self, repo: RepoRef, branch: str) -> list[dict[str, Any]]:
        branch_ref = quote(branch, safe="")
        branch_response = self._get(f"/repos/{repo.owner}/{repo.name}/branches/{branch_ref}")
        branch_data = branch_response.json()
        tree_sha = branch_data["commit"]["commit"]["tree"]["sha"]
        response = self._get(f"/repos/{repo.owner}/{repo.name}/git/trees/{tree_sha}", params={"recursive": "1"})
        data = response.json()
        return [item for item in data.get("tree", []) if item.get("type") == "blob"]

    def raw_file(self, repo: RepoRef, branch: str, path: str, max_bytes: int) -> str:
        encoded = quote(path, safe="/")
        url = f"https://raw.githubusercontent.com/{repo.owner}/{repo.name}/{quote(branch, safe='')}/{encoded}"
        response = self._raw_get(url)
        content = response.content[:max_bytes]
        return content.decode("utf-8", errors="replace")

    def contents_file(self, repo: RepoRef, branch: str, path: str) -> str:
        encoded = quote(path, safe="/")
        response = self._get(f"/repos/{repo.owner}/{repo.name}/contents/{encoded}", params={"ref": branch})
        data = response.json()
        return base64.b64decode(data["content"]).decode("utf-8", errors="replace")


def is_probably_source_file(path: str) -> bool:
    posix = PurePosixPath(path)
    lowered = path.lower()
    if any(part in {"node_modules", ".git", "vendor", "dist", "build", "__pycache__"} for part in posix.parts):
        return False
    if lowered.endswith((".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".tar", ".gz", ".jar", ".exe", ".dll")):
        return False
    if posix.name in {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}:
        return False
    return posix.suffix.lower() in {
        ".md",
        ".txt",
        ".py",
        ".go",
        ".js",
        ".ts",
        ".rb",
        ".php",
        ".java",
        ".c",
        ".cpp",
        ".cs",
        ".sh",
        ".ps1",
        ".yaml",
        ".yml",
        ".json",
        ".http",
        ".nse",
        "",
    }
