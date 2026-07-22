#!/usr/bin/env python3
"""Verify that packaged PNG icons have transparent corners without Pillow."""

from __future__ import annotations

import struct
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def paeth(left: int, above: int, upper_left: int) -> int:
    estimate = left + above - upper_left
    left_distance = abs(estimate - left)
    above_distance = abs(estimate - above)
    upper_left_distance = abs(estimate - upper_left)
    if left_distance <= above_distance and left_distance <= upper_left_distance:
        return left
    if above_distance <= upper_left_distance:
        return above
    return upper_left


def rgba_rows(path: Path) -> tuple[int, int, list[bytes]]:
    data = path.read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")

    offset = 8
    compressed = bytearray()
    width = height = 0
    while offset < len(data):
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        kind = data[offset + 4 : offset + 8]
        payload = data[offset + 8 : offset + 8 + length]
        offset += 12 + length
        if kind == b"IHDR":
            width, height, depth, color, compression, filtering, interlace = struct.unpack(
                ">IIBBBBB", payload
            )
            if (depth, color, compression, filtering, interlace) != (8, 6, 0, 0, 0):
                raise ValueError("expected non-interlaced 8-bit RGBA PNG")
        elif kind == b"IDAT":
            compressed.extend(payload)
        elif kind == b"IEND":
            break

    raw = zlib.decompress(compressed)
    stride = width * 4
    rows: list[bytes] = []
    previous = bytearray(stride)
    cursor = 0
    for _ in range(height):
        filter_type = raw[cursor]
        cursor += 1
        encoded = raw[cursor : cursor + stride]
        cursor += stride
        decoded = bytearray(stride)
        for index, value in enumerate(encoded):
            left = decoded[index - 4] if index >= 4 else 0
            above = previous[index]
            upper_left = previous[index - 4] if index >= 4 else 0
            if filter_type == 0:
                decoded[index] = value
            elif filter_type == 1:
                decoded[index] = (value + left) & 0xFF
            elif filter_type == 2:
                decoded[index] = (value + above) & 0xFF
            elif filter_type == 3:
                decoded[index] = (value + ((left + above) // 2)) & 0xFF
            elif filter_type == 4:
                decoded[index] = (value + paeth(left, above, upper_left)) & 0xFF
            else:
                raise ValueError(f"unsupported PNG filter {filter_type}")
        rows.append(bytes(decoded))
        previous = decoded
    return width, height, rows


def alpha_at(rows: list[bytes], x: int, y: int) -> int:
    return rows[y][x * 4 + 3]


def verify(path: Path) -> None:
    width, height, rows = rgba_rows(path)
    corners = (
        alpha_at(rows, 0, 0),
        alpha_at(rows, width - 1, 0),
        alpha_at(rows, 0, height - 1),
        alpha_at(rows, width - 1, height - 1),
    )
    center = alpha_at(rows, width // 2, height // 2)
    if corners != (0, 0, 0, 0):
        raise ValueError(f"opaque corner alpha values: {corners}")
    if center != 255:
        raise ValueError(f"icon center must remain opaque, got alpha={center}")


def main() -> int:
    icons = sorted((ROOT / "src-tauri" / "icons").glob("*.png"))
    icons += sorted((ROOT / "extensions" / "chrome" / "icons").glob("*.png"))
    failures: list[str] = []
    for icon in icons:
        try:
            verify(icon)
            print(f"PASS {icon.relative_to(ROOT)}")
        except (OSError, ValueError, zlib.error) as error:
            failures.append(f"{icon.relative_to(ROOT)}: {error}")
    if failures:
        print("Icon transparency verification: FAIL")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(f"Icon transparency verification: PASS ({len(icons)} PNG files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
