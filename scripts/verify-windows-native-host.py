#!/usr/bin/env python3
"""Release gate for the bundled Windows Native Messaging host.

The host must be an x86-64 console PE and must not depend on the separately
installed Microsoft VC++ runtime. The desktop executable can start on a clean
Windows installation while a dynamically-linked host dies in the loader,
which Chrome/Firefox surface only as a generic Native Messaging error.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


PE_SIGNATURE = b"PE\0\0"
IMAGE_FILE_MACHINE_AMD64 = 0x8664
PE32_PLUS_MAGIC = 0x20B
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
BANNED_RUNTIME_IMPORTS = (
    b"vcruntime140.dll",
    b"vcruntime140_1.dll",
    b"msvcp140.dll",
    b"msvcp140_1.dll",
    b"msvcp140_2.dll",
)


def read_u16(data: bytes, offset: int, label: str) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise ValueError(f"truncated PE while reading {label}")
    return struct.unpack_from("<H", data, offset)[0]


def verify(path: Path) -> None:
    data = path.read_bytes()
    if len(data) < 4096:
        raise ValueError(f"host is unexpectedly small ({len(data)} bytes)")
    if data[:2] != b"MZ":
        raise ValueError("host is not a PE executable (missing MZ header)")
    if len(data) < 0x40:
        raise ValueError("truncated DOS header")

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset : pe_offset + 4] != PE_SIGNATURE:
        raise ValueError("host has an invalid PE signature")

    machine = read_u16(data, pe_offset + 4, "COFF machine")
    if machine != IMAGE_FILE_MACHINE_AMD64:
        raise ValueError(f"host machine is 0x{machine:04x}, expected x86-64")

    optional_header = pe_offset + 24
    magic = read_u16(data, optional_header, "optional-header magic")
    if magic != PE32_PLUS_MAGIC:
        raise ValueError(f"host is not PE32+ (magic 0x{magic:04x})")

    subsystem = read_u16(data, optional_header + 68, "subsystem")
    if subsystem != IMAGE_SUBSYSTEM_WINDOWS_CUI:
        raise ValueError(
            f"host subsystem is {subsystem}, expected console/stdio subsystem 3"
        )

    lower = data.lower()
    imported = [name.decode("ascii") for name in BANNED_RUNTIME_IMPORTS if name in lower]
    if imported:
        raise ValueError(
            "host depends on external Microsoft VC++ runtime: " + ", ".join(imported)
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("host", type=Path, help="path to pwdvault-native.exe")
    args = parser.parse_args()

    try:
        verify(args.host)
    except (OSError, ValueError) as error:
        print(f"Windows native host verification: FAIL: {error}")
        return 1

    print(f"Windows native host verification: PASS: {args.host}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
