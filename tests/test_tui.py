"""Terminal viewer stream handling and key bindings with a fake worker."""
import asyncio
import io
import json
import time

import pytest

pytest.importorskip("av")
pytest.importorskip("textual")
pytest.importorskip("textual_image")

from okam_native import tui  # noqa: E402
from okam_native.vp_helper import encode_lens_record  # noqa: E402
from test_direct_cli import Process, _encoded_frames  # noqa: E402


def _worker(frames_per_lens=12):
    lens0, lens1 = _encoded_frames(frames_per_lens, 30), _encoded_frames(frames_per_lens, 220)
    data = b"".join(encode_lens_record(lens, frame)
                    for pair in zip(((0, f) for f in lens0), ((1, f) for f in lens1)) for lens, frame in pair)
    return Process(data=data)


def _wait(condition, timeout=10):
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(.02)


def test_stream_decodes_each_lens_and_reports_the_end():
    process = _worker()
    process.stderr = io.BytesIO(json.dumps({"failure_stage": "read_media", "failure": "x"}).encode() + b"\n")
    from okam_native.direct_cli import worker_failure
    stream = tui.CameraStream(lambda: process, failure=worker_failure, retry=False)
    stream.start()
    _wait(lambda: stream.state == "ended")
    for lens in (0, 1):
        picture, sequence = stream.latest(lens)
        assert picture is not None and (picture.width, picture.height) == (64, 48) and sequence > 0
    assert "no video within 30 seconds" in stream.detail
    assert "lens0" in stream.summary() and "lens1" in stream.summary()


def test_stream_records_and_snapshots_every_lens(tmp_path):
    process = _worker()
    gate = []

    class SlowStdout(io.BytesIO):
        def read(self, size=-1):
            if not gate:
                gate.append(1)
                stream.start_recording(tmp_path / "rec")
            return super().read(size)

    process.stdout = SlowStdout(process.stdout.getvalue())
    stream = tui.CameraStream(lambda: process, retry=False)
    stream.start()
    _wait(lambda: stream.state == "ended")
    results = stream.stop_recording()
    assert [r["lens"] for r in results] == [0, 1]
    assert all(r["saved"] and r["decoded_frames"] == 12 for r in results)
    assert sorted(p.name for p in stream.snapshot(tmp_path / "snap")) == ["snap-lens0.jpg", "snap-lens1.jpg"]


def test_app_keys_toggle_lenses_and_record(tmp_path):
    class FakeStream:
        def __init__(self):
            self.recorders = None
            self.state = "live"
            self.started = self.stopped = False
            self.recorded = []

        def start(self):
            self.started = True

        def stop(self):
            self.stopped = True

        def latest(self, lens):
            return None, 0

        def summary(self):
            return "live · lens0 12.0 fps"

        def start_recording(self, base):
            self.recorders = {}
            self.recorded.append(base)

        def stop_recording(self):
            self.recorders = None
            return [{"saved": True, "lens": 0, "seconds": 1.0, "decoded_frames": 12}]

        def snapshot(self, base):
            return []

    stream = FakeStream()
    app = tui.build_app(stream, "Parking Lot", tmp_path)

    async def drive():
        async with app.run_test() as pilot:
            await pilot.pause(.3)
            assert "12.0 fps" in str(app.query_one("#status").render())
            await pilot.press("2")
            assert [app.query_one(f"#lens{lens}").display for lens in (0, 1)] == [False, True]
            await pilot.press("b", "r")
            assert stream.recorded and stream.recorded[0].name.startswith("parking-lot-clip-")
            await pilot.press("r")
            await pilot.pause(.3)
            assert stream.recorders is None
            await pilot.press("q")

    asyncio.run(drive())
    assert stream.started and stream.stopped


def test_app_draws_decoded_frames_into_each_lens_pane(tmp_path):
    stream = tui.CameraStream(lambda: _worker(30))
    app = tui.build_app(stream, "Parking", tmp_path)

    async def drive():
        async with app.run_test(size=(120, 40)) as pilot:
            for _ in range(50):
                await pilot.pause(.1)
                if all(app.query_one(f"#lens{lens}").image is not None for lens in (0, 1)):
                    break
            assert all(app.query_one(f"#lens{lens}").image is not None for lens in (0, 1))
            await pilot.press("q")

    asyncio.run(drive())


def test_status_line_shows_worker_detail_brackets_literally(tmp_path):
    class Ended:
        recorders = None
        state = "ended"

        def start(self): pass
        def stop(self): pass
        def latest(self, lens): return None, 0
        def summary(self): return "ended (no video [stage=connect, connected=no, code=x])"

    app = tui.build_app(Ended(), "Parking", tmp_path)

    async def drive():
        async with app.run_test() as pilot:
            await pilot.pause(.3)
            assert "[stage=connect" in str(app.query_one("#status").render())
            await pilot.press("q")

    asyncio.run(drive())


def test_stream_reconnects_by_itself_after_a_failed_connect():
    from okam_native.direct_cli import worker_failure
    from test_direct_cli import _failed_process

    class FastClock:
        now = 0.0

        def __call__(self):
            FastClock.now += 1.0
            return FastClock.now

    processes = iter([_failed_process("connect"), _worker()])
    stream = tui.CameraStream(lambda: next(processes, _worker()), failure=worker_failure, clock=FastClock())
    seen = []
    stream.start()
    _wait(lambda: seen.append(stream.state) or stream.latest(1)[0] is not None)
    stream.stop()
    assert "retrying" in seen


def test_fit_picture_keeps_aspect_and_centres_in_the_pane():
    width, height, dx, dy = tui.fit_picture(1920, 1080, cols=90, rows=40, cell=(10, 20))
    assert (width, height) == (900, 504) and abs(width / height - 16 / 9) < .02
    assert dx == 0 and dy == (800 - 504) // 2 // 20
    width, height, dx, dy = tui.fit_picture(1920, 1080, cols=200, rows=20, cell=(10, 20))
    assert height <= 400 and height % 6 == 0 and dx > 0


def test_sixel_frames_are_drawn_in_place_at_the_pane():
    import numpy as np
    frame = tui.sixel_at(np.zeros((6, 4, 3), dtype=np.uint8), col=5, row=2)
    assert frame.startswith("\x1b7\x1b[3;6H\x1bP") and frame.endswith("\x1b\\\x1b8")


def test_sixel_painter_draws_each_lens_without_erasing(tmp_path):
    stream = tui.CameraStream(lambda: _worker(30), retry=False)
    app = tui.build_app(stream, "Parking", tmp_path, graphics=(True, (10, 20)))
    writes = []
    app._write_terminal = writes.append

    async def drive():
        async with app.run_test(size=(120, 40)) as pilot:
            for _ in range(60):
                await pilot.pause(.1)
                if {w[:20] for w in writes} and len({w.split("H", 1)[0] for w in writes}) >= 2:
                    break
            await pilot.press("q")

    asyncio.run(drive())
    positions = {w.split("H", 1)[0] for w in writes}
    assert len(positions) == 2  # one placement per lens pane
    assert all(w.startswith("\x1b7\x1b[") and "\x1bP" in w for w in writes)


def test_fit_picture_respects_the_quality_width_cap():
    width, height, _, _ = tui.fit_picture(1920, 1080, cols=200, rows=60, cell=(10, 20), max_width=640)
    assert width == 640 and height == 360


def test_quality_key_cycles_presets(tmp_path):
    stream = tui.CameraStream(lambda: _worker(30), retry=False)
    app = tui.build_app(stream, "Parking", tmp_path, graphics=(True, (10, 20)), quality="low")
    app._write_terminal = lambda _data: None

    async def drive():
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(.3)
            assert "low preview" in str(app.query_one("#status").render())
            await pilot.press("v")
            await pilot.pause(.3)
            assert "medium preview" in str(app.query_one("#status").render())
            await pilot.press("q")

    asyncio.run(drive())


def test_unknown_quality_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        tui.build_app(tui.CameraStream(lambda: None), "Parking", tmp_path, graphics=(True, (10, 20)),
                      quality="ultra")


def test_encoder_pool_falls_back_to_threads_when_processes_cannot_start(monkeypatch):
    import concurrent.futures
    from concurrent.futures import ThreadPoolExecutor

    class Broken:
        def __init__(self, *args, **kwargs):
            raise ValueError("bad value(s) in fds_to_keep")

    monkeypatch.setattr(concurrent.futures, "ProcessPoolExecutor", Broken)
    with tui.encoder_pool() as pool:
        assert isinstance(pool, ThreadPoolExecutor) and pool.submit(int, "7").result() == 7
