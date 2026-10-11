"""Fast sixel encoder round trip through a minimal sixel decoder."""
import re
import time

import numpy as np
import pytest

from okam_native.sixel import Palette, encode, quantize


def decode(data: bytes):
    """Decode a sixel image into an (height, width, 3) array of palette percentages."""
    assert data.startswith(b"\x1bP0;1;0q") and data.endswith(b"\x1b\\")
    body = data[len(b"\x1bP0;1;0q"):-2]
    raster = re.match(rb'"1;1;(\d+);(\d+)', body)
    width, height = int(raster.group(1)), int(raster.group(2))
    body = body[raster.end():]
    palette, image = {}, np.full((height, width, 3), -1)
    colour, x, top, i = 0, 0, 0, 0
    while i < len(body):
        char = body[i:i + 1]
        if char == b"#":
            match = re.match(rb"#(\d+)(?:;2;(\d+);(\d+);(\d+))?", body[i:])
            colour = int(match.group(1))
            if match.group(2):
                palette[colour] = tuple(int(v) for v in match.group(2, 3, 4))
            i += match.end()
            continue
        if char == b"$":
            x = 0
        elif char == b"-":
            x, top = 0, top + 6
        else:
            count = 1
            if char == b"!":
                match = re.match(rb"!(\d+)", body[i:])
                count, i = int(match.group(1)), i + match.end()
                char = body[i:i + 1]
            bits = char[0] - 63
            for _ in range(count):
                for row in range(6):
                    if bits >> row & 1:
                        image[top + row, x] = palette[colour]
                x += 1
        i += 1
    return image


def test_round_trip_reproduces_the_quantized_frame():
    rng = np.random.default_rng(7)
    rgb = rng.integers(0, 256, size=(13, 17, 3), dtype=np.uint8)
    rgb[:, 5:12] = (250, 10, 10)  # a run, to exercise run-length encoding
    image = decode(encode(rgb, Palette(colours=32)))
    assert image.shape == (12, 17, 3)  # trimmed to whole six-row bands
    index, table = quantize(rgb[:12].copy(), Palette(colours=32))
    assert (image == (table[index] * 100 + 127) // 255).all()


def test_muted_colours_keep_their_hue():
    muted = np.zeros((12, 40, 3), dtype=np.uint8)
    muted[:, :20] = (95, 115, 80)    # dull foliage green
    muted[:, 20:] = (150, 140, 120)  # dusty path
    image = decode(encode(muted))
    assert image[0, 0, 1] > image[0, 0, 0] > image[0, 0, 2]  # still green-dominant
    assert image[0, 30, 0] > image[0, 30, 2]  # path stays warm, not grey or purple


@pytest.mark.parametrize("palette", [Palette(), Palette(colours=64), Palette(dither=True)])
def test_greys_stay_neutral(palette):
    ramp = np.repeat(np.arange(256, dtype=np.uint8), 3).reshape(1, 256, 3).repeat(6, axis=0)
    image = decode(encode(ramp, palette))
    assert (np.abs(image[..., 0] - image[..., 1]) <= 1).all() and (np.abs(image[..., 1] - image[..., 2]) <= 1).all()


@pytest.mark.parametrize("colours", [1, 257])
def test_palette_size_is_bounded(colours):
    with pytest.raises(ValueError):
        Palette(colours=colours)


def test_runs_are_compressed_and_blank_tails_dropped():
    rgb = np.zeros((6, 200, 3), dtype=np.uint8)
    data = encode(rgb)
    assert b"!200~" in data and len(data) < 200


@pytest.mark.parametrize("shape", [(5, 10, 3), (6, 0, 3), (6, 6, 4)])
def test_rejects_images_it_cannot_encode(shape):
    with pytest.raises(ValueError):
        encode(np.zeros(shape, dtype=np.uint8))


def test_preview_frame_encodes_fast_enough_for_live_video():
    rng = np.random.default_rng(1)
    smooth = rng.integers(0, 256, size=(36, 64, 3)).repeat(10, axis=0).repeat(10, axis=1).astype(np.uint8)
    start = time.perf_counter()
    encode(smooth)
    assert time.perf_counter() - start < 1.0
