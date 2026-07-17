#!/usr/bin/env python3
"""Validate that every local file referenced by an extension manifest exists.

The checker intentionally rejects symlinks: release archives must be
self-contained regular files on every supported platform.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path


def manifest_references(manifest: dict) -> set[str]:
    references: set[str] = set()

    background = manifest.get("background", {})
    if worker := background.get("service_worker"):
        references.add(worker)
    references.update(background.get("scripts", []))

    for content_script in manifest.get("content_scripts", []):
        references.update(content_script.get("js", []))
        references.update(content_script.get("css", []))

    action = manifest.get("action", {})
    if popup := action.get("default_popup"):
        references.add(popup)

    for icon_map in (manifest.get("icons", {}), action.get("default_icon", {})):
        references.update(icon_map.values())

    return references


IMPORT_PATTERN = re.compile(r"\bimport\s+(?:[^'\"]+?\s+from\s+)?['\"]([^'\"]+)['\"]")


def include_module_dependencies(root: Path, references: set[str]) -> set[str]:
    expanded = set(references)
    pending = list(references)
    while pending:
        reference = pending.pop()
        if not reference.endswith((".js", ".mjs")):
            continue
        module_path = root / reference
        try:
            source = module_path.read_text(encoding="utf-8")
        except OSError:
            continue
        for imported in IMPORT_PATTERN.findall(source):
            if not imported.startswith("."):
                continue
            dependency = (Path(reference).parent / imported).as_posix()
            normalized = Path(os.path.normpath(dependency)).as_posix()
            if normalized not in expanded:
                expanded.add(normalized)
                pending.append(normalized)
    return expanded


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} <extension-root>", file=sys.stderr)
        return 2

    root = Path(sys.argv[1]).resolve()
    manifest_path = root / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"invalid manifest {manifest_path}: {error}", file=sys.stderr)
        return 1

    references = include_module_dependencies(root, manifest_references(manifest))
    failures: list[str] = []
    for reference in sorted(references):
        candidate = root / reference
        normalized = Path(os.path.abspath(candidate))
        if root != normalized and root not in normalized.parents:
            failures.append(f"reference escapes extension root: {reference}")
        elif candidate.is_symlink():
            failures.append(f"reference is a symlink: {reference}")
        elif not candidate.is_file():
            failures.append(f"reference is not a regular file: {reference}")

    for path in root.rglob("*"):
        if path.is_symlink():
            failures.append(f"package contains symlink: {path.relative_to(root)}")

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1

    print(f"validated {len(references)} manifest/module references")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
