from __future__ import annotations

import argparse
import subprocess
import tempfile
from pathlib import Path


def _split_remote(remote: str) -> tuple[str, str]:
    if ":" not in remote:
        raise ValueError("remote must look like user@host:/remote/path")
    target, remote_path = remote.split(":", 1)
    if not target or not remote_path:
        raise ValueError("remote must look like user@host:/remote/path")
    return target, remote_path


def push_directory(local_dir: Path, remote: str, *, port: int = 22, identity_file: str | None = None) -> None:
    local_path = local_dir.resolve()
    if not local_path.exists():
        raise FileNotFoundError(f"local path does not exist: {local_path}")

    target, remote_path = _split_remote(remote)
    if local_path.is_file():
        batch_lines = [f"put {local_path} {remote_path}"]
    else:
        batch_lines = [f"mkdir {remote_path}", f"cd {remote_path}"]
        for path in sorted(local_path.rglob("*")):
            if path.is_dir():
                rel = path.relative_to(local_path).as_posix()
                batch_lines.append(f"mkdir {rel}")
            else:
                rel = path.relative_to(local_path).as_posix()
                batch_lines.append(f"put {path} {rel}")

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".sftp") as batch:
        batch.write("\n".join(batch_lines) + "\n")
        batch_path = Path(batch.name)

    cmd = ["sftp", "-P", str(port)]
    if identity_file:
        cmd.extend(["-i", identity_file])
    cmd.extend(["-b", str(batch_path), target])

    try:
        subprocess.run(cmd, check=True)
    finally:
        batch_path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("local_dir")
    parser.add_argument("remote", help="user@host:/remote/path")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--identity-file")
    args = parser.parse_args(argv)
    push_directory(Path(args.local_dir), args.remote, port=args.port, identity_file=args.identity_file)


if __name__ == "__main__":
    main()
