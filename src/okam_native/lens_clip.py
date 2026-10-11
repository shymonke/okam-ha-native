"""Per-lens clip files from framed VP worker output.

A dual-lens camera interleaves two independent H.264 streams in one session,
so each lens is written to its own file. MP4 output and verification use the
optional ``av`` package (``pip install okam-native[cli]``).
"""
from __future__ import annotations

import os
import tempfile
import time
from fractions import Fraction
from pathlib import Path

from .cs2 import inspect_h264

TIME_BASE = Fraction(1, 90000)


class ClipError(Exception):
    """A user-facing clip failure without private input."""


def _av():
    try:
        import av
    except ImportError:
        raise ClipError("MP4 files and clip checks need the av package (pip install av)") from None
    return av


def lens_path(output: Path, lens: int, *, single: bool) -> Path:
    return output if single else output.with_name(f"{output.stem}-lens{lens}{output.suffix}")


class LensRecorder:
    """Collect one lens's frames, starting at its first keyframe."""

    def __init__(self, lens: int, path: Path):
        self.lens = lens
        self.path = path
        self.mp4 = path.suffix.lower() == ".mp4"
        if self.mp4:
            handle, name = tempfile.mkstemp(suffix=".h264")
            os.close(handle)  # Windows keeps an open handle's file locked.
            self.raw_path = Path(name)
        else:
            self.raw_path = path
        # Exclusive creation protects an existing file from accidental overwrite.
        self._raw = open(self.raw_path, "wb" if self.mp4 else "xb")
        self.frames = 0
        self.bytes = 0
        self.first = self.last = None

    def add(self, payload: bytes, *, clock=time.monotonic) -> None:
        if not self.frames and not inspect_h264(payload)[1]:
            return  # A decoder cannot start before the lens's first keyframe.
        self._raw.write(payload)
        now = clock()
        self.first = now if self.first is None else self.first
        self.last = now
        self.frames += 1
        self.bytes += len(payload)

    def finish(self) -> dict[str, object]:
        self._raw.close()
        try:
            if not self.frames:
                self.raw_path.unlink(missing_ok=True)
                return {"lens": self.lens, "saved": False, "frames": 0}
            span = (self.last - self.first) if self.frames > 1 else 0
            fps = round(min(60.0, max(1.0, (self.frames - 1) / span)) if span else 10.0, 2)
            if self.mp4:
                remux_to_mp4(self.raw_path, self.path, fps)
            decoded = count_decoded_frames(self.path)
        finally:
            if self.mp4:
                self.raw_path.unlink(missing_ok=True)
        return {"lens": self.lens, "saved": True, "file": str(self.path), "frames": self.frames,
                "decoded_frames": decoded, "fps": fps, "seconds": round(self.frames / fps, 1),
                "h264_bytes": self.bytes}


def remux_to_mp4(raw: Path, output: Path, fps: float) -> None:
    """Copy raw H.264 into MP4 with constant-rate timestamps (no re-encode)."""
    av = _av()
    if output.exists():
        raise ClipError("output file already exists")
    step = max(1, round(90000 / fps))
    with av.open(str(raw), format="h264") as source, av.open(str(output), "w", format="mp4") as sink:
        stream = sink.add_stream_from_template(source.streams.video[0])
        stream.time_base = TIME_BASE
        index = 0
        for packet in source.demux(video=0):
            if packet.size == 0:
                continue
            packet.stream = stream
            packet.pts = packet.dts = index * step
            packet.duration = step
            packet.time_base = TIME_BASE
            sink.mux(packet)
            index += 1


def count_decoded_frames(path: Path) -> int:
    """Decode a saved clip; a clip that saved bytes but no pictures is a failure."""
    av = _av()
    frames = 0
    options = {"format": "h264"} if path.suffix.lower() == ".h264" else {}
    with av.open(str(path), **options) as container:
        for packet in container.demux(video=0):
            try:
                frames += len(packet.decode())
            except av.error.InvalidDataError:
                continue
    return frames
