import queue
import subprocess
import threading
import time

from okam_native.session import NativeStreamSession


class BlockingPipe:
    def __init__(self) -> None:
        self.chunks: queue.Queue[bytes | None] = queue.Queue()

    def read(self, _size: int = -1) -> bytes:
        value = self.chunks.get(timeout=3)
        return b"" if value is None else value


class FakeProcess:
    def __init__(self) -> None:
        self.stdout = BlockingPipe()
        self.stderr = BlockingPipe()
        self._done = threading.Event()
        self.returncode = None

    def poll(self):
        return self.returncode

    def terminate(self) -> None:
        self.returncode = 0
        self.stderr.chunks.put(b'{"disconnected":true}\n')
        self.stderr.chunks.put(None)
        self.stdout.chunks.put(None)
        self._done.set()

    def kill(self) -> None:
        self.terminate()

    def wait(self, timeout=None):
        if not self._done.wait(timeout):
            raise subprocess.TimeoutExpired("fake", timeout)
        return self.returncode


def test_session_default_keeps_camera_warm_for_two_minutes() -> None:
    session = NativeStreamSession(lambda: FakeProcess())  # type: ignore[arg-type]
    assert session.idle_timeout == 120.0


def test_session_reuses_process_and_stops_after_last_viewer() -> None:
    process = FakeProcess()
    starts = []

    def start():
        starts.append(True)
        return process

    session = NativeStreamSession(start, idle_timeout=0.02)  # type: ignore[arg-type]
    first = session.acquire()
    second = session.acquire()
    assert len(starts) == 1
    assert session.status().viewers == 2
    assert session.status().media_ready is False

    process.stdout.chunks.put(b"\x00\x00\x00\x01h264")
    deadline = time.monotonic() + 2
    while not session.status().media_ready and time.monotonic() < deadline:
        time.sleep(0.01)
    assert session.status().media_ready is True

    first.close()
    assert process.poll() is None
    second.close()
    deadline = time.monotonic() + 2
    while session.status().running and time.monotonic() < deadline:
        time.sleep(0.01)

    assert process.poll() == 0
    deadline = time.monotonic() + 2
    while session.status().clean_disconnect is None and time.monotonic() < deadline:
        time.sleep(0.01)
    assert session.status().clean_disconnect is True


def _unit(kind: int, body: bytes = b"\x00") -> bytes:
    return b"\x00\x00\x01" + bytes([kind]) + body


def test_new_viewer_starts_on_a_decodable_boundary() -> None:
    # Without a cached keyframe a viewer waits for the camera's next one,
    # which is the entire delay when opening a live view.
    session = NativeStreamSession(lambda: FakeProcess())  # type: ignore[arg-type]
    sps, pps, idr = _unit(7, b"sps"), _unit(8, b"pps"), _unit(5, b"idr")
    session._note_media(sps + pps + idr + _unit(1, b"inter") + _unit(1, b"tail"))

    assert session._preamble() == sps + pps + idr


def test_media_units_are_reassembled_across_chunk_boundaries() -> None:
    session = NativeStreamSession(lambda: FakeProcess())  # type: ignore[arg-type]
    stream = _unit(7, b"sps") + _unit(8, b"pps") + _unit(5, b"idr") + _unit(1, b"x")
    for index in range(0, len(stream), 3):
        session._note_media(stream[index : index + 3])

    assert session._preamble() == _unit(7, b"sps") + _unit(8, b"pps") + _unit(5, b"idr")


def test_only_the_newest_keyframe_is_kept() -> None:
    session = NativeStreamSession(lambda: FakeProcess())  # type: ignore[arg-type]
    session._note_media(_unit(7) + _unit(8) + _unit(5, b"old") + _unit(1))
    session._note_media(_unit(5, b"new") + _unit(1) + _unit(1))

    assert session._preamble().endswith(_unit(5, b"new"))
    assert b"old" not in session._preamble()


def test_later_viewer_receives_the_preamble_before_live_media() -> None:
    session = NativeStreamSession(lambda: FakeProcess())  # type: ignore[arg-type]
    first = session.acquire()
    # Media observed while the first viewer is watching.
    session._note_media(_unit(7, b"sps") + _unit(8, b"pps") + _unit(5, b"idr") + _unit(1))
    second = session.acquire()
    try:
        assert next(iter(second)) == session._preamble()
    finally:
        second.close()
        first.close()
        session.close()


def test_restarting_the_helper_discards_stale_media_units() -> None:
    # A new helper means a new encoder state, so a cached keyframe from the
    # previous session must not be handed to the next viewer.
    session = NativeStreamSession(lambda: FakeProcess())  # type: ignore[arg-type]
    session._note_media(_unit(7) + _unit(8) + _unit(5, b"idr") + _unit(1))
    assert session._preamble() != b""

    subscription = session.acquire()
    try:
        assert session._preamble() == b""
    finally:
        subscription.close()
        session.close()


def test_no_preamble_is_sent_before_parameter_sets_are_seen() -> None:
    session = NativeStreamSession(lambda: FakeProcess())  # type: ignore[arg-type]
    session._note_media(_unit(1, b"inter") + _unit(1, b"more"))

    assert session._preamble() == b""


def _wait_for(predicate, timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.01)
    return predicate()


def test_always_on_starts_without_a_viewer_and_ignores_idle_timeout() -> None:
    process = FakeProcess()
    session = NativeStreamSession(
        lambda: process, idle_timeout=0.01, always_on=True  # type: ignore[arg-type]
    )
    session.start_always_on()
    assert session.status().running is True

    viewer = session.acquire()
    viewer.close()
    time.sleep(0.1)
    assert process.poll() is None
    session.close()
    assert process.poll() == 0


def test_always_on_restarts_the_helper_after_it_ends() -> None:
    processes: list[FakeProcess] = []

    def start():
        processes.append(FakeProcess())
        return processes[-1]

    session = NativeStreamSession(
        start, always_on=True, retry_delay=0.01  # type: ignore[arg-type]
    )
    session.start_always_on()
    processes[0].stdout.chunks.put(b"\x00\x00\x00\x01h264")
    assert _wait_for(lambda: session.status().media_ready)

    processes[0].terminate()
    assert _wait_for(lambda: len(processes) == 2 and session.status().running)
    session.close()


class RecordingTimer:
    """Records requested retry delays instead of waiting on the clock."""

    delays: list[float] = []

    def __init__(self, delay: float, _callback) -> None:
        RecordingTimer.delays.append(delay)
        self.daemon = False

    def start(self) -> None:
        pass

    def cancel(self) -> None:
        pass


def _failing_start():
    from okam_native.p2p import P2PError

    raise P2PError("camera unavailable")


def test_always_on_backs_off_when_the_start_keeps_failing(monkeypatch) -> None:
    import okam_native.session as session_module

    RecordingTimer.delays = []
    monkeypatch.setattr(session_module.threading, "Timer", RecordingTimer)
    session = NativeStreamSession(
        _failing_start, always_on=True, retry_delay=5.0, max_retry_delay=30.0
    )
    for _ in range(5):
        session.start_always_on()
    assert session.status().last_error == "native_stream_start_failed"
    assert RecordingTimer.delays == [5.0, 10.0, 20.0, 30.0, 30.0]


def test_always_on_backoff_stays_capped_after_many_failures(monkeypatch) -> None:
    import okam_native.session as session_module

    RecordingTimer.delays = []
    monkeypatch.setattr(session_module.threading, "Timer", RecordingTimer)
    session = NativeStreamSession(_failing_start, always_on=True)
    for _ in range(1100):
        session.start_always_on()
    assert RecordingTimer.delays[-1] == 300.0


def test_viewer_waits_for_a_pending_always_on_retry(monkeypatch) -> None:
    import okam_native.session as session_module

    monkeypatch.setattr(session_module.threading, "Timer", RecordingTimer)
    attempts = []

    def start():
        attempts.append(True)
        return _failing_start()

    session = NativeStreamSession(start, always_on=True)  # type: ignore[arg-type]
    session.start_always_on()
    viewer = session.acquire()
    assert len(attempts) == 1
    assert session.status().viewers == 1
    viewer.close()


def test_on_demand_session_does_not_start_without_a_viewer() -> None:
    starts = []
    session = NativeStreamSession(lambda: starts.append(True))  # type: ignore[arg-type]
    session.start_always_on()
    assert starts == []


def _lens_record(lens: int, payload: bytes) -> list[bytes]:
    # BlockingPipe returns one queued item per read, so the header and payload
    # are queued separately to match the record reader's exact reads.
    import struct

    return [struct.pack(">BI", lens, len(payload)), payload]


def test_framed_session_splits_lenses_and_reports_new_ones() -> None:
    process = FakeProcess()
    seen: list[int] = []
    session = NativeStreamSession(
        lambda: process, framed=True, on_lenses=seen.append  # type: ignore[arg-type]
    )
    lens0 = session.acquire(0)
    for part in _lens_record(0, b"\x00\x00\x01\x65zero") + _lens_record(1, b"\x00\x00\x01\x65one"):
        process.stdout.chunks.put(part)
    deadline = time.monotonic() + 2
    while session.lenses < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert session.lenses == 2
    assert session.status().lenses == 2
    assert seen == [2]

    lens1 = session.acquire(1)
    for part in _lens_record(1, b"\x00\x00\x01\x41one-b") + _lens_record(0, b"\x00\x00\x01\x41zero-b"):
        process.stdout.chunks.put(part)

    first = iter(lens0)
    assert next(first) == b"\x00\x00\x01\x65zero"
    assert next(first) == b"\x00\x00\x01\x41zero-b"
    assert next(iter(lens1)) == b"\x00\x00\x01\x41one-b"
    lens0.close()
    lens1.close()
    session.close()


def test_session_refuses_a_lens_the_camera_has_not_shown() -> None:
    import pytest

    from okam_native.p2p import P2PError

    session = NativeStreamSession(lambda: FakeProcess(), framed=True, lenses=1)  # type: ignore[arg-type]
    with pytest.raises(P2PError):
        session.acquire(1)
    session.close()
