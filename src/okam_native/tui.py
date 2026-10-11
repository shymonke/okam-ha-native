"""Terminal viewer for VP cameras: every lens live, with recording and snapshots.

The camera is reached through the native worker (no vendor client). Video is
drawn with ``textual-image``: sixel or the kitty protocol where the terminal
supports it (Windows Terminal 1.22+), Unicode half-blocks elsewhere. Needs the
``cli`` extra (``av``, ``textual``, ``textual-image``).
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .lens_clip import ClipError, LensRecorder
from .vp import VPError
from .vp_helper import read_lens_records

LENSES = (0, 1)
REFRESH_SECONDS = 1 / 6
# Back-off between automatic reconnects; reset after a session that delivered video.
RETRY_SECONDS = (5, 10, 20, 30)
# Terminal preview presets: maximum pixel width and sixel palette. Recordings
# and snapshots always keep the camera's full resolution.
QUALITY = {
    "low": (480, dict(colours=64)),
    "medium": (640, dict(colours=256)),
    "high": (960, dict(colours=256, dither=True)),
}


@dataclass
class LensFeed:
    """Decoder and latest picture for one lens; fields are guarded by the stream lock."""

    lens: int
    decoder: object = None
    latest: object = None
    sequence: int = 0
    frames: int = 0
    bytes: int = 0
    times: list = field(default_factory=list)

    def fps(self, now: float) -> float:
        recent = [t for t in self.times if now - t <= 3]
        return (len(recent) - 1) / (recent[-1] - recent[0]) if len(recent) > 2 else 0.0


class CameraStream:
    """Run one worker session in a thread and keep each lens decoded."""

    def __init__(self, starter, *, clock=time.monotonic, failure=None, retry=True):
        import av
        self._av = av
        self._starter = starter
        self._clock = clock
        self._failure = failure
        self._lock = threading.Lock()
        self._thread = None
        self._process = None
        self._stopping = False
        self._retry = retry
        self._wake = threading.Event()
        self.feeds: dict[int, LensFeed] = {}
        self.state = "idle"
        self.detail = ""
        self.recorders: dict[int, LensRecorder] | None = None
        self.record_base: Path | None = None
        self.record_started = 0.0

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            self.retry_now()
            return
        self._stopping = False
        self.state, self.detail = "connecting", ""
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def retry_now(self) -> None:
        """Skip the remaining back-off before the next reconnect."""
        self._wake.set()

    def _run(self) -> None:
        failures = 0
        while not self._stopping:
            delivered = self._session()
            if self._stopping or not self._retry:
                break
            failures = 0 if delivered else failures + 1
            delay = RETRY_SECONDS[min(max(failures, 1), len(RETRY_SECONDS)) - 1]
            reason = self.detail
            deadline = self._clock() + delay
            self._wake.clear()
            while not self._stopping and self._clock() < deadline:
                self.state = "retrying"
                self.detail = f"in {max(1, round(deadline - self._clock()))} s; last: {reason}"
                if self._wake.wait(.5):
                    break
            if not self._stopping:
                self.state, self.detail = "connecting", ""

    def _session(self) -> bool:
        """Run one worker session; return whether any video arrived."""
        frames_before = sum(feed.frames for feed in self.feeds.values())
        self._process = None
        try:
            self._process = self._starter()
            for lens, payload in read_lens_records(self._process.stdout):
                self._handle(lens, payload)
                if self._stopping:
                    break
        except (VPError, OSError, ValueError) as error:
            self.detail = type(error).__name__
        finally:
            self._stop_process()
            if not self._stopping:
                self.state = "ended"
                if self._failure and self._process is not None:
                    self.detail = self._failure(self._process)
        return sum(feed.frames for feed in self.feeds.values()) > frames_before

    def _handle(self, lens: int, payload: bytes) -> None:
        now = self._clock()
        with self._lock:
            feed = self.feeds.get(lens)
            if feed is None:
                feed = self.feeds[lens] = LensFeed(lens, self._av.CodecContext.create("h264", "r"))
            feed.frames += 1
            feed.bytes += len(payload)
            feed.times = [t for t in feed.times if now - t <= 3] + [now]
            if self.recorders is not None:
                recorder = self.recorders.get(lens)
                if recorder is None:
                    recorder = self.recorders[lens] = LensRecorder(
                        lens, self.record_base.with_name(f"{self.record_base.name}-lens{lens}.mp4"))
                recorder.add(payload, clock=self._clock)
            self.state = "live"
        try:
            pictures = feed.decoder.decode(self._av.Packet(payload))
        except self._av.error.InvalidDataError:
            return  # Frames before the lens's first keyframe cannot be decoded.
        if pictures:
            with self._lock:
                feed.latest = pictures[-1]
                feed.sequence += 1

    def latest(self, lens: int):
        with self._lock:
            feed = self.feeds.get(lens)
            return (feed.latest, feed.sequence) if feed else (None, 0)

    def summary(self) -> str:
        now = self._clock()
        with self._lock:
            parts = [f"lens{f.lens} {f.fps(now):.1f} fps" for f in sorted(self.feeds.values(), key=lambda f: f.lens)]
            rate = sum(f.bytes for f in self.feeds.values())
        text = " · ".join([self.state + (f" ({self.detail})" if self.detail else "")] + parts)
        if self.recorders is not None:
            text += f" · REC {int(now - self.record_started)} s"
        return text + (f" · {rate / 1e6:.1f} MB received" if rate else "")

    def start_recording(self, base: Path) -> None:
        with self._lock:
            if self.recorders is None:
                self.record_base, self.recorders, self.record_started = base, {}, self._clock()

    def stop_recording(self) -> list[dict[str, object]]:
        with self._lock:
            recorders, self.recorders = self.recorders or {}, None
        try:
            return [recorders[lens].finish() for lens in sorted(recorders)]
        except ClipError as error:
            return [{"saved": False, "error": str(error)}]

    def snapshot(self, base: Path) -> list[Path]:
        saved = []
        for lens in sorted(self.feeds):
            picture, _ = self.latest(lens)
            if picture is not None:
                path = base.with_name(f"{base.name}-lens{lens}.jpg")
                picture.to_image().save(path, quality=92)
                saved.append(path)
        return saved

    def _stop_process(self) -> None:
        process = self._process
        if process is not None and process.poll() is None:
            from .direct_cli import _stop
            _stop(process)

    def stop(self) -> None:
        self._stopping = True
        self.state = "stopped"
        self._wake.set()
        self._stop_process()
        if self._thread is not None:
            self._thread.join(timeout=15)


def fit_picture(width: int, height: int, cols: int, rows: int, cell: tuple[int, int],
                max_width: int | None = None):
    """Scale a picture into a pane, keeping its aspect ratio.

    Returns pixel width and height (height a multiple of six, for whole sixel
    bands) and the column/row offsets that centre it in the pane.
    """
    cell_w, cell_h = cell
    scale = min(cols * cell_w / width, rows * cell_h / height, 1.0,
                (max_width / width) if max_width else 1.0)
    pixel_w = max(2, int(width * scale) // 2 * 2)
    pixel_h = max(6, int(height * scale) // 6 * 6)
    col_offset = max(0, (cols * cell_w - pixel_w) // 2 // cell_w)
    row_offset = max(0, (rows * cell_h - pixel_h) // 2 // cell_h)
    return pixel_w, pixel_h, col_offset, row_offset


def sixel_at(rgb, col: int, row: int, palette: dict | None = None) -> str:
    """A sixel image drawn at a screen cell without disturbing the cursor.

    Top-level so it can run in a worker process."""
    from .sixel import Palette, encode
    data = encode(rgb, Palette(**(palette or {})))
    return f"\x1b7\x1b[{row + 1};{col + 1}H" + data.decode("ascii") + "\x1b8"


def encoder_pool():
    """A pool for sixel encoding: one process per lens where processes can start.

    Spawn, not fork: forking while the UI and stream threads run can deadlock.
    Some hosts (for example a headless test driver that replaced the standard
    streams) cannot start processes; threads are the slower fallback.
    """
    import multiprocessing
    from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
    from concurrent.futures.process import BrokenProcessPool
    pool = None
    try:
        pool = ProcessPoolExecutor(max_workers=len(LENSES), mp_context=multiprocessing.get_context("spawn"))
        pool.submit(int).result(timeout=60)
        return pool
    except (OSError, ValueError, BrokenProcessPool, TimeoutError):
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=True)
        return ThreadPoolExecutor(max_workers=len(LENSES))


def _terminal_graphics() -> tuple[bool, tuple[int, int]]:
    from textual_image._terminal import probe_terminal
    capabilities = probe_terminal()
    return capabilities.sixel, (capabilities.cell_size.width, capabilities.cell_size.height)


def build_app(stream: CameraStream, camera: str, output_dir: Path, *, graphics=None,
              quality: str = "medium"):
    """Build the viewer. Sixel terminals get in-place frames drawn by a
    background painter (no erase, so no flicker); others use textual-image."""
    from textual.app import App, ComposeResult
    from textual.containers import Horizontal
    from textual.widgets import Footer, Header, Static
    from textual_image.widget import Image

    use_sixel, cell = graphics if graphics is not None else _terminal_graphics()
    panes = {}
    shown = dict.fromkeys(LENSES, 0)
    geometry: dict[int, tuple[int, int, int, int]] = {}
    painting = threading.Event()
    if quality not in QUALITY:
        raise ValueError("quality must be one of " + ", ".join(QUALITY))
    settings = {"quality": quality}

    class OkamTui(App):
        TITLE = f"O-KAM · {camera}"
        BINDINGS = [("r", "record", "Record"), ("s", "snapshot", "Snapshot"),
                    ("1", "solo(0)", "Lens 0"), ("2", "solo(1)", "Lens 1"), ("b", "both", "Both"),
                    ("v", "quality", "Quality"), ("c", "reconnect", "Reconnect"), ("q", "quit", "Quit")]
        CSS = ("#status { height: auto; max-height: 3; padding: 0 1; } Horizontal { height: 1fr; } "
               ".lens { width: 1fr; height: 1fr; border: round $accent; }")

        def compose(self) -> ComposeResult:
            yield Header()
            yield Static("connecting...", id="status", markup=False)
            with Horizontal():
                for lens in LENSES:
                    pane = Static("", id=f"lens{lens}", classes="lens") if use_sixel else \
                        Image(id=f"lens{lens}", classes="lens")
                    pane.border_title = f"lens {lens}"
                    panes[lens] = pane
                    yield pane
            yield Footer()

        def on_mount(self) -> None:
            stream.start()
            self.set_interval(REFRESH_SECONDS, self.refresh_frames)
            if use_sixel:
                painting.set()
                threading.Thread(target=self._paint_loop, daemon=True).start()

        def refresh_frames(self) -> None:
            text = stream.summary() + (f" · {settings['quality']} preview" if use_sixel else "")
            self.query_one("#status", Static).update(text)
            if use_sixel:
                # The painter thread reads pane positions captured on the UI thread.
                for lens, pane in panes.items():
                    region = pane.content_region
                    geometry[lens] = (region.x, region.y, region.width, region.height) \
                        if pane.display and region.width > 0 and region.height > 0 else None
                return
            for lens, pane in panes.items():
                picture, sequence = stream.latest(lens)
                if picture is None or sequence == shown[lens] or not pane.display:
                    continue
                shown[lens] = sequence
                width, height = self._pixel_size(pane, picture)
                pane.image = picture.reformat(width=width, height=height, format="rgb24").to_image()

        def _paint_loop(self) -> None:
            with encoder_pool() as pool:
                while painting.is_set():
                    started = time.monotonic()
                    max_width, palette = QUALITY[settings["quality"]]
                    jobs = []
                    for lens in LENSES:
                        place = geometry.get(lens)
                        picture, sequence = stream.latest(lens)
                        if place is None or picture is None or sequence == shown[lens]:
                            continue
                        shown[lens] = sequence
                        x, y, cols, rows = place
                        width, height, dx, dy = fit_picture(picture.width, picture.height, cols, rows,
                                                            cell, max_width)
                        rgb = picture.reformat(width=width, height=height, format="rgb24").to_ndarray()
                        jobs.append(pool.submit(sixel_at, rgb, x + dx, y + dy, palette))
                    for job in jobs:
                        frame = job.result()
                        if not painting.is_set():
                            return
                        try:
                            self.call_from_thread(self._write_terminal, frame)
                        except RuntimeError:
                            return  # The app is shutting down.
                    time.sleep(max(0.0, REFRESH_SECONDS - (time.monotonic() - started)))

        def _write_terminal(self, data: str) -> None:
            driver = self._driver
            if driver is not None and painting.is_set():
                driver.write(data)
                driver.flush()

        def on_resize(self, _event) -> None:
            for lens in LENSES:
                shown[lens] = 0  # Repaint at the new geometry.

        @staticmethod
        def _pixel_size(pane, picture) -> tuple[int, int]:
            from textual_image.widget import get_cell_size
            cell = get_cell_size()
            box_w = max(16, pane.content_size.width * cell.width)
            box_h = max(9, pane.content_size.height * cell.height)
            scale = min(box_w / picture.width, box_h / picture.height, 1.0)
            return max(2, int(picture.width * scale) // 2 * 2), max(2, int(picture.height * scale) // 2 * 2)

        def _base(self, kind: str) -> Path:
            output_dir.mkdir(parents=True, exist_ok=True)
            return output_dir / f"{camera_slug}-{kind}-{time.strftime('%Y%m%d-%H%M%S')}"

        def action_record(self) -> None:
            if stream.recorders is None:
                stream.start_recording(self._base("clip"))
                self.notify("Recording every lens")
            else:
                self.notify("Saving and checking the recording...")
                self.run_worker(self._finish_recording, thread=True)

        def _finish_recording(self) -> None:
            results = stream.stop_recording()
            saved = [r for r in results if r.get("saved")]
            message = ", ".join(f"lens{r['lens']}: {r['seconds']} s, {r['decoded_frames']} frames"
                                for r in saved) or "nothing was recorded"
            self.call_from_thread(self.notify, message, timeout=8)

        def action_snapshot(self) -> None:
            paths = stream.snapshot(self._base("snapshot"))
            self.notify(f"Saved {len(paths)} snapshot(s) in {output_dir}" if paths else "No picture yet")

        def action_solo(self, lens: int) -> None:
            for item, pane in panes.items():
                pane.display = item == lens
                shown[item] = 0  # Redraw at the new pane size.

        def action_both(self) -> None:
            for item, pane in panes.items():
                pane.display = True
                shown[item] = 0

        def action_quality(self) -> None:
            names = list(QUALITY)
            settings["quality"] = names[(names.index(settings["quality"]) + 1) % len(names)]
            self.refresh()  # Clear the old, possibly larger, preview.
            for lens in LENSES:
                shown[lens] = 0
            self.notify(f"Preview quality: {settings['quality']}")

        def action_reconnect(self) -> None:
            if stream.state in ("ended", "stopped", "retrying"):
                stream.start()
                self.notify("Reconnecting now")

        def on_unmount(self) -> None:
            painting.clear()
            if stream.recorders is not None:
                stream.stop_recording()
            stream.stop()

    from .direct_cli import camera_alias
    camera_slug = camera_alias(camera)
    return OkamTui()


def run(starter, camera: str, output_dir: Path, *, failure=None, quality: str = "medium") -> dict[str, object]:
    """Run the viewer until the user quits."""
    stream = CameraStream(starter, failure=failure)
    build_app(stream, camera, output_dir, quality=quality).run()
    return {"stopped": True}
