#!/usr/bin/env python3
"""Read-only local file permission and integrity inventory."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path


def digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def audit(root: Path, include_hash: bool, max_bytes: int) -> dict:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("scan path must be a directory")
    findings, inventory, skipped = [], [], 0
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not (Path(base) / d).is_symlink())
        for name in sorted(files):
            path = Path(base) / name
            rel = path.relative_to(root).as_posix()
            try:
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    inventory.append({"path": rel, "type": "symlink", "size": info.st_size})
                    continue
                item = {"path": rel, "type": "file" if stat.S_ISREG(info.st_mode) else "other", "size": info.st_size}
                if os.name == "posix" and info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                    modes = []
                    if info.st_mode & stat.S_IWGRP: modes.append("group-writable")
                    if info.st_mode & stat.S_IWOTH: modes.append("other-writable")
                    findings.append({"path": rel, "severity": "medium", "issues": modes,
                                     "mode": oct(stat.S_IMODE(info.st_mode))})
                if include_hash and stat.S_ISREG(info.st_mode):
                    if info.st_size > max_bytes:
                        skipped += 1
                        item["hash_skipped"] = "file exceeds max-bytes"
                    else:
                        item["sha256"] = digest_file(path)
                inventory.append(item)
            except (OSError, PermissionError) as exc:
                findings.append({"path": rel, "severity": "info", "issues": [f"unreadable: {exc.__class__.__name__}"]})
    return {"tool": "secure-config-audit", "generated_at": datetime.now(timezone.utc).isoformat(),
            "root": str(root), "platform": os.name, "findings": findings,
            "inventory": inventory, "hashes_skipped": skipped}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="authorized local directory to inspect")
    parser.add_argument("--hash", action="store_true", help="include SHA-256 hashes for files")
    parser.add_argument("--max-bytes", type=int, default=10_000_000, help="maximum size to hash (default: 10 MB)")
    parser.add_argument("--json", type=Path, dest="json_path", help="write JSON report to this path")
    args = parser.parse_args()
    if args.max_bytes < 0:
        parser.error("--max-bytes must be non-negative")
    try:
        result = audit(args.path, args.hash, args.max_bytes)
        rendered = json.dumps(result, indent=2, ensure_ascii=False)
        if args.json_path:
            args.json_path.write_text(rendered + "\n", encoding="utf-8")
        print(f"Scanned {len(result['inventory'])} entries; {len(result['findings'])} findings; "
              f"{result['hashes_skipped']} hashes skipped.")
        if args.json_path: print(f"Report: {args.json_path}")
        return 1 if result["findings"] else 0
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
