#!/usr/bin/env python3
"""Remove the legacy white icon matte and rebuild desktop/browser assets.

The existing artwork was composited onto white before export. Only the four
rounded-corner regions are processed; the lock body and all interior white
details remain byte-for-byte unchanged in the 512px master.
"""

from __future__ import annotations

import math
import shutil
import subprocess
import tempfile
from pathlib import Path

from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
TAURI_ICONS = ROOT / "src-tauri" / "icons"
MASTER = TAURI_ICONS / "icon.png"
CHROME_ICONS = ROOT / "extensions" / "chrome" / "icons"
CORNER_RADIUS = 96
TAURI_OUTPUTS = (
    "32x32.png",
    "128x128.png",
    "128x128@2x.png",
    "Square30x30Logo.png",
    "Square44x44Logo.png",
    "Square71x71Logo.png",
    "Square89x89Logo.png",
    "Square107x107Logo.png",
    "Square142x142Logo.png",
    "Square150x150Logo.png",
    "Square284x284Logo.png",
    "Square310x310Logo.png",
    "StoreLogo.png",
    "icon.icns",
    "icon.ico",
    "icon.png",
)


def normalize_corner_pixels(path: Path) -> None:
    """Remove tiny alpha residues introduced by downsampling at image corners."""
    if path.suffix.lower() != ".png":
        return

    with Image.open(path) as source:
        image = source.convert("RGBA")
    width, height = image.size
    for coordinate in ((0, 0), (width - 1, 0), (0, height - 1), (width - 1, height - 1)):
        image.putpixel(coordinate, (0, 0, 0, 0))
    image.save(path, optimize=True)


def remove_corner_matte(source: Image.Image) -> Image.Image:
    image = source.convert("RGBA")
    width, height = image.size
    if (width, height) != (512, 512):
        raise ValueError(f"expected 512x512 master, got {width}x{height}")

    # Already-corrected masters are left unchanged, making regeneration safe
    # to repeat without turning transparent black corners opaque.
    corner_alpha = [
        image.getpixel((0, 0))[3],
        image.getpixel((width - 1, 0))[3],
        image.getpixel((0, height - 1))[3],
        image.getpixel((width - 1, height - 1))[3],
    ]
    if corner_alpha == [0, 0, 0, 0]:
        return image

    centers = (
        (CORNER_RADIUS, CORNER_RADIUS),
        (width - 1 - CORNER_RADIUS, CORNER_RADIUS),
        (CORNER_RADIUS, height - 1 - CORNER_RADIUS),
        (width - 1 - CORNER_RADIUS, height - 1 - CORNER_RADIUS),
    )
    result = image.copy()
    output: list[tuple[int, int, int, int]] = []

    for y in range(height):
        for x in range(width):
            red, green, blue, _ = image.getpixel((x, y))
            alpha = 255
            center: tuple[int, int] | None = None
            if x < CORNER_RADIUS and y < CORNER_RADIUS:
                center = centers[0]
            elif x > width - 1 - CORNER_RADIUS and y < CORNER_RADIUS:
                center = centers[1]
            elif x < CORNER_RADIUS and y > height - 1 - CORNER_RADIUS:
                center = centers[2]
            elif x > width - 1 - CORNER_RADIUS and y > height - 1 - CORNER_RADIUS:
                center = centers[3]

            if center and math.hypot(x - center[0], y - center[1]) > 84:
                # Convert the border-connected white matte to alpha. Values
                # above 220 are genuine dark/teal artwork and stay opaque.
                raw_alpha = 255 - min(red, green, blue)
                if raw_alpha <= 3:
                    alpha = 0
                elif raw_alpha >= 220:
                    alpha = 255
                else:
                    alpha = round((raw_alpha - 3) * 255 / 217)

                if alpha == 0:
                    red = green = blue = 0
                elif alpha < 255:
                    fraction = alpha / 255
                    red = round((red - 255 * (1 - fraction)) / fraction)
                    green = round((green - 255 * (1 - fraction)) / fraction)
                    blue = round((blue - 255 * (1 - fraction)) / fraction)
                    red = max(0, min(255, red))
                    green = max(0, min(255, green))
                    blue = max(0, min(255, blue))

            output.append((red, green, blue, alpha))

    result.putdata(output)
    return result


def main() -> None:
    corrected = remove_corner_matte(Image.open(MASTER))

    with tempfile.TemporaryDirectory(prefix="pwdvault-icons-") as directory:
        temp = Path(directory)
        corrected_master = temp / "pwdvault-icon-transparent.png"
        generated = temp / "tauri"
        corrected.save(corrected_master)

        subprocess.run(
            ["pnpm", "tauri", "icon", str(corrected_master), "--output", str(generated)],
            cwd=ROOT,
            check=True,
        )
        for name in TAURI_OUTPUTS:
            destination = TAURI_ICONS / name
            shutil.copy2(generated / name, destination)
            normalize_corner_pixels(destination)

    CHROME_ICONS.mkdir(parents=True, exist_ok=True)
    for size in (16, 32, 48, 128):
        resized = corrected.resize((size, size), Image.Resampling.LANCZOS)
        destination = CHROME_ICONS / f"icon{size}.png"
        resized.save(destination, optimize=True)
        normalize_corner_pixels(destination)

    print("Regenerated transparent desktop and browser icons.")


if __name__ == "__main__":
    main()
