"""Reference-counted on-demand native H.264 stream session."""

from __future__ import annotations

import json
import queue
import subprocess
import threading
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from .p2p import MAX_RESPONSE_BYTES, P2PError, _jpeg_dimensions
from .vp_helper import read_lens_records


StreamStarter = Callable[[], subprocess.Popen[bytes]]
LensObserver = Callable[[int], None]
_END = object()
ANNEX_B_START = b"\x00\x00\x01"
# A keyframe access unit plus its parameter sets. Anything larger is treated as
# unparsable rather than buffered indefinitely.
MAX_PREAMBLE_BYTES = 1024 * 1024
MAX_SCAN_BYTES = 4 * 1024 * 1024
# Always-on reconnect backoff: the first retry after a helper exit, and the cap
# reached by doubling while the camera keeps failing before any media.
ALWAYS_ON_RETRY_SECONDS = 5.0
ALWAYS_ON_MAX_RETRY_SECONDS = 300.0
# Longest wait for the next media chunk, covering camera wake-up and connect.
MEDIA_WAIT_SECONDS = 90.0


@dataclass(frozen=True)
class SessionStatus:
    running: bool
    viewers: int
    clean_disconnect: bool | None
    last_error: str | None
    media_ready: bool = False
    lenses: int = 1


class _LensMedia:
    """Parameter sets and newest keyframe of one lens's H.264 stream."""

    def __init__(self) -> None:
        self.scan = bytearray()
        self.sps = b""
        self.pps = b""
        self.keyframe = b""


class StreamSubscription:
    def __init__(
        self,
        owner: "NativeStreamSession",
        subscription_id: str,
        chunks: queue.Queue[bytes | object],
    ) -> None:
        self._owner = owner
        self._subscription_id = subscription_id
        self._chunks = chunks
        self._closed = False

    def __iter__(self) -> Iterator[bytes]:
        while not self._closed:
            try:
                # Bounded: a stalled stream must free its viewer and handler.
                chunk = self._chunks.get(timeout=MEDIA_WAIT_SECONDS)
            except queue.Empty:
                # Keep waiting through an always-on reconnect backoff; end
                # only when no helper is expected to deliver media.
                if self._owner.retry_pending():
                    continue
                return
            if chunk is _END:
                return
            assert isinstance(chunk, bytes)
            yield chunk

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                self._chunks.put_nowait(_END)
            except queue.Full:
                try:
                    self._chunks.get_nowait()
                    self._chunks.put_nowait(_END)
                except (queue.Empty, queue.Full):
                    pass
            self._owner.release(self._subscription_id)


class NativeStreamSession:
    def __init__(
        self,
        starter: StreamStarter,
        *,
        idle_timeout: float = 120.0,
        always_on: bool = False,
        retry_delay: float = ALWAYS_ON_RETRY_SECONDS,
        max_retry_delay: float = ALWAYS_ON_MAX_RETRY_SECONDS,
        framed: bool = False,
        lenses: int = 1,
        on_lenses: LensObserver | None = None,
    ) -> None:
        self._starter = starter
        # A framed helper interleaves lens-tagged records from every lens of
        # a multi-lens camera in one connection; each viewer picks one lens.
        self.framed = framed
        self._lenses = max(1, lenses)
        self._on_lenses = on_lenses
        self.idle_timeout = idle_timeout
        # Always-on keeps one helper running without viewers, for recorders
        # such as Frigate, and restarts it with backoff when it ends.
        self.always_on = always_on
        self._retry_delay = retry_delay
        self._max_retry_delay = max_retry_delay
        self._retry_timer: threading.Timer | None = None
        self._failures = 0
        self._lock = threading.RLock()
        self._process: subprocess.Popen[bytes] | None = None
        self._subscribers: dict[str, tuple[int, queue.Queue[bytes | object]]] = {}
        self._idle_timer: threading.Timer | None = None
        self._stderr = bytearray()
        self._clean_disconnect: bool | None = None
        self._last_error: str | None = None
        self._media_ready = False
        self._media: dict[int, _LensMedia] = {}
        self._detached: subprocess.Popen[bytes] | None = None
        self._closed = False

    @property
    def lenses(self) -> int:
        with self._lock:
            return self._lenses

    def acquire(self, lens: int = 0) -> StreamSubscription:
        with self._lock:
            if self._closed:
                raise P2PError("native stream session is closed")
            if not 0 <= lens < self._lenses:
                raise P2PError("native stream lens is unavailable")
            if self._idle_timer is not None:
                self._idle_timer.cancel()
                self._idle_timer = None
            # While an always-on retry is pending, the viewer waits for it rather
            # than bypassing the backoff with an immediate camera wake.
            retry_pending = self.always_on and self._retry_timer is not None
            if not retry_pending and (
                self._process is None or self._process.poll() is not None
            ):
                self._start_locked()
            subscription_id = uuid.uuid4().hex
            chunks: queue.Queue[bytes | object] = queue.Queue(maxsize=32)
            # Start the viewer on a decodable boundary. Without this it waits
            # for the camera's next keyframe, which is the whole open latency.
            preamble = self._preamble(lens)
            if preamble:
                chunks.put_nowait(preamble)
            self._subscribers[subscription_id] = (lens, chunks)
            return StreamSubscription(self, subscription_id, chunks)

    def release(self, subscription_id: str) -> None:
        with self._lock:
            self._subscribers.pop(subscription_id, None)
            if self.always_on:
                return
            if not self._subscribers and self._process is not None and not self._closed:
                if self._idle_timer is not None:
                    self._idle_timer.cancel()
                self._idle_timer = threading.Timer(self.idle_timeout, self._stop_if_idle)
                self._idle_timer.daemon = True
                self._idle_timer.start()

    def snapshot(
        self, ffmpeg: str, *, lens: int = 0, timeout: float = 90.0
    ) -> tuple[bytes, int, int]:
        subscription = self.acquire(lens)
        decoder: subprocess.Popen[bytes] | None = None
        writer: threading.Thread | None = None
        try:
            decoder = subprocess.Popen(
                [
                    ffmpeg,
                    "-hide_banner",
                    "-loglevel",
                    "error",
                    "-f",
                    "h264",
                    "-i",
                    "pipe:0",
                    "-frames:v",
                    "1",
                    "-f",
                    "image2pipe",
                    "-c:v",
                    "mjpeg",
                    "-q:v",
                    "3",
                    "pipe:1",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            assert decoder.stdin is not None
            decoder_input = decoder.stdin
            decoder.stdin = None

            def feed() -> None:
                try:
                    for chunk in subscription:
                        decoder_input.write(chunk)
                except (BrokenPipeError, OSError):
                    pass
                finally:
                    try:
                        decoder_input.close()
                    except OSError:
                        pass

            writer = threading.Thread(target=feed, daemon=True)
            writer.start()
            jpeg, _stderr = decoder.communicate(timeout=timeout)
            if decoder.returncode != 0:
                raise P2PError("native on-demand snapshot decoder failed")
            width, height = _jpeg_dimensions(jpeg)
            return jpeg, width, height
        except P2PError:
            raise
        except (OSError, subprocess.SubprocessError):
            raise P2PError("native on-demand snapshot failed") from None
        finally:
            subscription.close()
            if decoder is not None and decoder.poll() is None:
                decoder.kill()
                decoder.wait(timeout=5)
            if writer is not None:
                writer.join(timeout=5)

    def _note_media(self, chunk: bytes, lens: int = 0) -> None:
        """Remember the parameter sets and newest keyframe from the stream.

        Chunks are arbitrary reads rather than NAL-aligned, so units are
        reassembled across boundaries before being classified.
        """

        media = self._media.setdefault(lens, _LensMedia())
        scan = media.scan
        scan.extend(chunk)
        if len(scan) > MAX_SCAN_BYTES:
            del scan[: len(scan) - MAX_SCAN_BYTES]
        starts = []
        position = scan.find(ANNEX_B_START)
        while position >= 0:
            starts.append(position)
            position = scan.find(ANNEX_B_START, position + len(ANNEX_B_START))
        if len(starts) < 2:
            return
        for begin, end in zip(starts, starts[1:]):
            self._record_unit(media, bytes(scan[begin:end]))
        # Keep the trailing unit: it is still incomplete.
        del scan[: starts[-1]]

    @staticmethod
    def _record_unit(media: _LensMedia, unit: bytes) -> None:
        if len(unit) <= len(ANNEX_B_START) or len(unit) > MAX_PREAMBLE_BYTES:
            return
        kind = unit[len(ANNEX_B_START)] & 0x1F
        if kind == 7:
            media.sps = unit
        elif kind == 8:
            media.pps = unit
        elif kind == 5:
            media.keyframe = unit

    def _preamble(self, lens: int = 0) -> bytes:
        """The bytes a new viewer needs before live data makes sense."""

        media = self._media.get(lens)
        if media is None or not media.sps or not media.pps:
            return b""
        preamble = media.sps + media.pps + media.keyframe
        return preamble if len(preamble) <= MAX_PREAMBLE_BYTES else b""

    def retry_pending(self) -> bool:
        with self._lock:
            return self.always_on and self._retry_timer is not None and not self._closed

    def status(self) -> SessionStatus:
        with self._lock:
            return SessionStatus(
                running=self._process is not None and self._process.poll() is None,
                viewers=len(self._subscribers),
                clean_disconnect=self._clean_disconnect,
                last_error=self._last_error,
                media_ready=self._media_ready,
                lenses=self._lenses,
            )

    def start_always_on(self) -> None:
        """Start the helper without a viewer; failures retry with backoff."""

        with self._lock:
            self._retry_timer = None
            if self._closed or not self.always_on:
                return
            if self._process is not None and self._process.poll() is None:
                return
            try:
                self._start_locked()
            except (P2PError, OSError, subprocess.SubprocessError):
                self._last_error = "native_stream_start_failed"
                self._schedule_retry_locked(media_seen=False)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            if self._idle_timer is not None:
                self._idle_timer.cancel()
                self._idle_timer = None
            if self._retry_timer is not None:
                self._retry_timer.cancel()
                self._retry_timer = None
            process = self._process
        self._terminate(process)

    def _start_locked(self) -> None:
        self._stderr.clear()
        self._clean_disconnect = None
        self._last_error = None
        self._media_ready = False
        # A new helper means a new encoder state, so cached units are stale.
        self._media.clear()
        process = self._starter()
        if process.stdout is None or process.stderr is None:
            process.kill()
            process.wait(timeout=5)
            raise P2PError("native stream helper pipes are unavailable")
        self._process = process
        stderr_thread = threading.Thread(
            target=self._drain_stderr, args=(process,), daemon=True
        )
        stderr_thread.start()
        threading.Thread(
            target=self._pump, args=(process, stderr_thread), daemon=True
        ).start()

    def _pump(
        self, process: subprocess.Popen[bytes], stderr_thread: threading.Thread
    ) -> None:
        assert process.stdout is not None
        try:
            for lens, chunk in self._read_media(process):
                with self._lock:
                    if self._process is not process:
                        # Replaced or detached: its media must not reach the
                        # next generation's viewers or preamble.
                        break
                    self._media_ready = True
                    self._note_media(chunk, lens)
                    grew = lens >= self._lenses
                    if grew:
                        self._lenses = lens + 1
                    subscribers = tuple(
                        chunks
                        for wanted, chunks in self._subscribers.values()
                        if wanted == lens
                    )
                if grew and self._on_lenses is not None:
                    self._on_lenses(lens + 1)
                for chunks in subscribers:
                    try:
                        chunks.put_nowait(chunk)
                    except queue.Full:
                        try:
                            chunks.get_nowait()
                            chunks.put_nowait(chunk)
                        except (queue.Empty, queue.Full):
                            pass
        except P2PError:
            # A malformed framed record ends this helper run like an exit.
            self._terminate(process)
        finally:
            process.wait()
            stderr_thread.join(timeout=2)
            with self._lock:
                # Only the current generation may end its viewers. A viewer
                # can already have started a replacement helper (or idle stop
                # detached this one); its subscribers belong to that one.
                current = self._process is process
                subscribers: tuple[queue.Queue[bytes | object], ...] = ()
                if current or self._process is None and self._detached is process:
                    subscribers = tuple(chunks for _lens, chunks in self._subscribers.values())
                    self._subscribers.clear()
                    self._parse_summary_locked(process.returncode)
                if current:
                    self._process = None
                    if self.always_on and not self._closed:
                        self._schedule_retry_locked(media_seen=self._media_ready)
                if self._detached is process:
                    self._detached = None
            for chunks in subscribers:
                try:
                    chunks.put_nowait(_END)
                except queue.Full:
                    try:
                        chunks.get_nowait()
                        chunks.put_nowait(_END)
                    except (queue.Empty, queue.Full):
                        pass

    def _read_media(
        self, process: subprocess.Popen[bytes]
    ) -> Iterator[tuple[int, bytes]]:
        assert process.stdout is not None
        if self.framed:
            yield from read_lens_records(process.stdout)
            return
        while True:
            chunk = process.stdout.read(64 * 1024)
            if not chunk:
                return
            yield 0, chunk

    def _drain_stderr(self, process: subprocess.Popen[bytes]) -> None:
        assert process.stderr is not None
        while True:
            chunk = process.stderr.read(4096)
            if not chunk:
                return
            with self._lock:
                # A detached helper may log only while nothing replaced it.
                if not (
                    self._process is process
                    or (self._process is None and self._detached is process)
                ):
                    continue
                remaining = MAX_RESPONSE_BYTES - len(self._stderr)
                if remaining > 0:
                    self._stderr.extend(chunk[:remaining])

    def _parse_summary_locked(self, returncode: int) -> None:
        payload = None
        for line in reversed(bytes(self._stderr).splitlines()):
            try:
                candidate = json.loads(line.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError):
                continue
            if isinstance(candidate, dict) and "disconnected" in candidate:
                payload = candidate
                break
        if payload is not None and isinstance(payload.get("disconnected"), bool):
            self._clean_disconnect = payload["disconnected"]
        if returncode != 0:
            self._last_error = "native_stream_ended"

    def _schedule_retry_locked(self, *, media_seen: bool) -> None:
        # A run that delivered media proves the path works, so retry promptly;
        # repeated failures before media back off to spare the camera.
        self._failures = 0 if media_seen else min(self._failures + 1, 32)
        delay = min(
            self._retry_delay * (2 ** max(self._failures - 1, 0)),
            self._max_retry_delay,
        )
        if self._retry_timer is not None:
            self._retry_timer.cancel()
        self._retry_timer = threading.Timer(delay, self.start_always_on)
        self._retry_timer.daemon = True
        self._retry_timer.start()

    def _stop_if_idle(self) -> None:
        with self._lock:
            self._idle_timer = None
            if self._subscribers or self._closed or self.always_on:
                return
            process = self._process
            # Detach under the lock, so a viewer arriving while this helper
            # terminates starts a fresh one instead of joining a dying one.
            self._process = None
            self._detached = process
        self._terminate(process)

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes] | None) -> None:
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
