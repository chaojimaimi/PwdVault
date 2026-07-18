#!/usr/bin/env python3
"""Create a deterministic, self-contained browser extension ZIP."""

from __future__ import annotations

import argparse
import stat
import zipfile
from pathlib import Path


FIXED_TIMESTAMP = (2026, 1, 1, 0, 0, 0)


def package(source: Path, output: Path) -> None:
    source = source.resolve()
    if not (source / "manifest.json").is_file():
        raise ValueError(f"manifest.json missing from {source}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_symlink():
                raise ValueError(f"refusing to package symlink: {path}")
            if not path.is_file():
                continue
            info = zipfile.ZipInfo(path.relative_to(source).as_posix(), FIXED_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(
                info,
                path.read_bytes(),
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    package(args.source, args.output)
    print(f"packaged {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
