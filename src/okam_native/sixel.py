"""Fast sixel encoding for live video previews.

Each frame gets its own palette from Pillow's fast octree quantizer (a few
milliseconds in C), so muted camera colours keep their hue. Each six-row band
is then encoded with numpy: one ``bincount`` builds every colour's sixel row
at once and a regular expression run-length encodes the band in C.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import numpy as np
from PIL import Image

_RUN = re.compile(rb"(.)\1{3,}")


@dataclass(frozen=True)
class Palette:
    """Adaptive palette size (2-256 colours) and optional Floyd-Steinberg dithering."""

    colours: int = 256
    dither: bool = False

    def __post_init__(self):
        if not 2 <= self.colours <= 256:
            raise ValueError("a sixel palette has 2 to 256 colours")


DEFAULT_PALETTE = Palette()


def _run(match: re.Match) -> bytes:
    return b"!%d%c" % (len(match.group(0)), match.group(1)[0])


def quantize(rgb: np.ndarray, palette: Palette = DEFAULT_PALETTE) -> tuple[np.ndarray, np.ndarray]:
    """Palette indices ``(height, width)`` and palette RGB rows ``(colours, 3)``."""
    dither = Image.Dither.FLOYDSTEINBERG if palette.dither else Image.Dither.NONE
    indexed = Image.fromarray(rgb).quantize(colors=palette.colours, method=Image.Quantize.FASTOCTREE,
                                            dither=dither)
    index = np.asarray(indexed, dtype=np.int64)
    colours = int(index.max()) + 1
    table = np.array(indexed.getpalette()[:colours * 3], dtype=np.int64).reshape(colours, 3)
    return index, table


def encode(rgb: np.ndarray, palette: Palette = DEFAULT_PALETTE) -> bytes:
    """Encode an ``(height, width, 3)`` uint8 RGB array as one sixel image.

    The height is trimmed to a multiple of six so the image never extends a
    partial band below its pane.
    """
    if rgb.ndim != 3 or rgb.shape[2] != 3:
        raise ValueError("expected an RGB image")
    height, width = rgb.shape[0] - rgb.shape[0] % 6, rgb.shape[1]
    if not height or not width:
        raise ValueError("image is too small for sixel output")
    index, table = quantize(np.ascontiguousarray(rgb[:height], dtype=np.uint8), palette)
    percent = (table * 100 + 127) // 255
    definitions = b"".join(b"#%d;2;%d;%d;%d" % (i, r, g, b) for i, (r, g, b) in enumerate(percent.tolist()))
    colours = len(table)
    bit_weights = np.repeat(1 << np.arange(6), width)
    columns = np.tile(np.arange(width), 6)
    parts = [b'\x1bP0;1;0q"1;1;%d;%d' % (width, height), definitions]
    for top in range(0, height, 6):
        band_index = index[top:top + 6].ravel()
        present = np.flatnonzero(np.bincount(band_index, minlength=colours))
        # Compact the band's colours so there are only as many rows as colours used.
        compact = np.zeros(colours, dtype=np.int64)
        compact[present] = np.arange(len(present))
        bits = np.bincount(compact[band_index] * width + columns, weights=bit_weights,
                           minlength=len(present) * width)
        rows = (bits.reshape(len(present), width) + 63).astype(np.uint8)
        # One regex pass per band: '#', digits and '$' never form runs with sixel data.
        band = b"$".join(b"#%d%s" % (colour, row.tobytes().rstrip(b"?"))
                         for colour, row in zip(present.tolist(), rows))
        parts.append(_RUN.sub(_run, band) + b"-")
    parts.append(b"\x1b\\")
    return b"".join(parts)
