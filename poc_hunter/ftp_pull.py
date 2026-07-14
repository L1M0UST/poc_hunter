from __future__ import annotations

from ftplib import FTP
from pathlib import Path


def pull_archives(
    *,
    host: str,
    username: str,
    password: str,
    remote_dir: str,
    local_dir: Path,
    port: int = 21,
    suffix: str = ".tar.gz",
    timeout: float = 60,
) -> list[Path]:
    local_dir.mkdir(parents=True, exist_ok=True)
    downloaded: list[Path] = []
    with FTP() as ftp:
        ftp.connect(host, port, timeout=timeout)
        ftp.login(username, password)
        ftp.cwd(remote_dir)
        names = [name for name in ftp.nlst() if name.endswith(suffix)]
        for name in names:
            target = local_dir / Path(name).name
            tmp = target.with_suffix(target.suffix + ".part")
            with tmp.open("wb") as out:
                ftp.retrbinary(f"RETR {name}", out.write)
            tmp.replace(target)
            ftp.delete(name)
            downloaded.append(target)
    return downloaded
