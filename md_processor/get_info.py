## from md get | cve_code | cve_description | cve_poc_relative_url | cve_poc_content | cve_poc_fork | cve_poc_star
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional
from urllib.parse import urlparse


@dataclass(frozen=True)
class CvePocRecord:
    cve_code: str
    cve_description: str
    cve_poc_relative_url: str


_CVE_HEADER_RE = re.compile(r"^##\s+(CVE-\d{4}-\d+)\s*$", re.IGNORECASE)
_MD_LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\((https?://[^)\s]+)\)")
_BARE_URL_RE = re.compile(r"(https?://\S+)")

def _url_to_relative(url: str) -> str:
    return url.strip()

def _extract_poc_urls(line: str) -> List[str]:
    urls = _MD_LINK_RE.findall(line)
    if not urls:
        urls = _BARE_URL_RE.findall(line)

    cleaned: List[str] = []
    for u in urls:
        u = u.rstrip(")].,;")
        low = u.lower()
        if "img.shields.io" in low or "shields.io/github" in low:
            continue
        cleaned.append(u)
    return cleaned


def parse_cve_md(content: str) -> List[CvePocRecord]:
    records: List[CvePocRecord] = []
    current_cve: Optional[str] = None
    description_lines: List[str] = []

    def flush_block(poc_lines: Iterable[str]) -> None:
        nonlocal current_cve, description_lines, records
        if not current_cve:
            return
        description = " ".join([ln.strip() for ln in description_lines if ln.strip()]).strip()
        for poc_line in poc_lines:
            for url in _extract_poc_urls(poc_line):
                records.append(
                    CvePocRecord(
                        cve_code=current_cve,
                        cve_description=description,
                        cve_poc_relative_url=_url_to_relative(url),
                    )
                )

    pending_poc_lines: List[str] = []

    for raw_line in content.splitlines():
        line = raw_line.rstrip("\n")
        header_match = _CVE_HEADER_RE.match(line.strip())
        if header_match:
            flush_block(pending_poc_lines)
            pending_poc_lines = []
            current_cve = header_match.group(1).upper()
            description_lines = []
            continue

        if current_cve is None:
            continue

        stripped = line.strip()
        if stripped.startswith("## "):
            flush_block(pending_poc_lines)
            pending_poc_lines = []
            current_cve = None
            description_lines = []
            continue

        if stripped.startswith("-"):
            pending_poc_lines.append(stripped)
            continue

        if pending_poc_lines:
            continue

        if stripped:
            description_lines.append(stripped)

    flush_block(pending_poc_lines)
    return records


def parse_cve_md_file(md_path: str | Path) -> List[dict]:
    md_path = Path(md_path)
    content = md_path.read_text(encoding="utf-8", errors="ignore")
    records = parse_cve_md(content)
    return [
        {
            "cve_code": r.cve_code,
            "cve_description": r.cve_description,
            "cve_poc_relative_url": r.cve_poc_relative_url,
        }
        for r in records
    ]


def write_records_json(records: List[dict], output_path: str | Path) -> None:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(records, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
