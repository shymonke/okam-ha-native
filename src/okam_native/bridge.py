"""Authenticated HTTP compatibility API for the native O-KAM bridge."""

from __future__ import annotations

import hmac
import json
import re
import secrets
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlsplit

from .p2p import P2PError
from .session import NativeStreamSession


MAX_REQUEST_BYTES = 4096
STREAM_CHUNK_BYTES = 32 * 1024
# Browser viewing: a few frames per second at a reduced width is plenty to
# watch and keeps the re-encode cheap on small Home Assistant hosts.
MJPEG_FPS = 5
MJPEG_WIDTH = 1280
MJPEG_BOUNDARY = "okamframe"
MAX_JPEG_BYTES = 4 * 1024 * 1024
# A client going away mid-request is normal here: the supervisor polls the
# bridge, and media consumers disconnect whenever a view closes.
_EXPECTED_DISCONNECTS = (
    BrokenPipeError,
    ConnectionAbortedError,
    ConnectionResetError,
    TimeoutError,
)
HOST_PATTERN = re.compile(r"^(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(?::[0-9]{1,5})?$")


# Concurrency bounds: each connection is a thread and each media stream an
# FFmpeg process, so both are capped to protect small Home Assistant hosts.
MAX_CONNECTIONS = 48
MAX_MEDIA_STREAMS = 8
SOCKET_TIMEOUT_SECONDS = 60
# A media stream whose FFmpeg emits nothing for this long is stopped.
OUTPUT_STALL_SECONDS = 120
_MEDIA_SLOTS = threading.BoundedSemaphore(MAX_MEDIA_STREAMS)


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    """An HTTP server that does not report a dropped client as a crash.

    The default handler prints a full traceback and the peer address whenever a
    client disconnects mid-request. The supervisor polls this bridge and closes
    connections abruptly, which filled the app log with alarming
    ConnectionResetError tracebacks for entirely normal behaviour.
    """

    daemon_threads = True

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._connections = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def process_request(self, request: object, client_address: object) -> None:
        if not self._connections.acquire(blocking=False):
            # Over the limit: drop the connection instead of adding a thread.
            self.shutdown_request(request)  # type: ignore[arg-type]
            return
        try:
            super().process_request(request, client_address)  # type: ignore[arg-type]
        except BaseException:
            self._connections.release()
            raise

    def process_request_thread(self, request: object, client_address: object) -> None:
        try:
            super().process_request_thread(request, client_address)  # type: ignore[misc]
        finally:
            self._connections.release()

    def handle_error(self, request: object, client_address: object) -> None:
        error = sys.exc_info()[1]
        if isinstance(error, _EXPECTED_DISCONNECTS):
            return
        # Type only: the peer address is never logged.
        print(
            f"bridge_request_failed error={type(error).__name__}",
            file=sys.stderr,
            flush=True,
        )


class CameraBridge:
    """One camera exposed through a reference-counted native stream session."""

    def __init__(
        self,
        *,
        camera_id: str,
        camera_name: str,
        api_token: str,
        session: NativeStreamSession,
        ffmpeg: str,
        guest_tokens: dict[str, str] | None = None,
    ) -> None:
        self.camera_id = camera_id
        self.camera_name = camera_name
        self._api_token = api_token
        # Named read-only tokens for people outside Home Assistant; removing
        # one from the app options revokes it without touching Home Assistant.
        self._guest_tokens = dict(guest_tokens or {})
        self.session = session
        self.ffmpeg = ffmpeg

    def _accepted(self, write: bool) -> list[str]:
        return [self._api_token] if write else [self._api_token, *self._guest_tokens.values()]

    def principal(self, authorization: str | None, *, write: bool = False) -> str | None:
        """The accepted token presented in ``authorization``, if any.

        Values are compared as UTF-8 bytes: ``hmac.compare_digest`` rejects
        non-ASCII strings, which would turn one odd token into a failure for
        every request. Every candidate is compared so timing reveals nothing.
        """

        if not isinstance(authorization, str):
            return None
        presented = authorization.encode("utf-8", "replace")
        matched = None
        for token in self._accepted(write):
            if hmac.compare_digest(presented, f"Bearer {token}".encode("utf-8", "replace")):
                matched = token
        return matched

    def authenticated(self, authorization: str | None, *, write: bool = False) -> bool:
        """Accept the main token, or a guest token for read-only requests."""

        return self.principal(authorization, write=write) is not None

    def _stream_token_for(self, token: str) -> str:
        # Derived rather than random: Home Assistant caches stream URLs, and a
        # per-start random value broke them after every bridge restart. Each
        # principal gets its own value, so revoking a guest token also revokes
        # the stream URLs it obtained.
        digest = hmac.new(
            token.encode("utf-8", "replace"),
            f"okam-stream:{self.camera_id}".encode("utf-8"),
            "sha256",
        ).digest()
        return secrets_safe(digest)

    def stream_authenticated(self, token: str | None) -> bool:
        if not isinstance(token, str):
            return False
        presented = token.encode("utf-8", "replace")
        results = [
            hmac.compare_digest(presented, self._stream_token_for(candidate).encode("ascii"))
            for candidate in self._accepted(False)
        ]
        return any(results)

    def stream_url(
        self, host: str | None, lens: int = 0, authorization: str | None = None
    ) -> str:
        safe_host = host if isinstance(host, str) and HOST_PATTERN.fullmatch(host) else "127.0.0.1:8099"
        camera = quote(self.camera_id, safe="")
        principal = self.principal(authorization) or self._api_token
        token = quote(self._stream_token_for(principal), safe="")
        suffix = f"&lens={lens}" if lens else ""
        return f"http://{safe_host}/api/cameras/{camera}/stream.ts?token={token}{suffix}"

    def status(self) -> dict[str, object]:
        session = self.session.status()
        if session.running:
            state = "streaming" if session.media_ready else "waking"
        else:
            state = "idle"
        return {
            "camera_id": self.camera_id,
            "name": self.camera_name,
            "online": True,
            "state": state,
            "viewers": session.viewers,
            "media_ready": session.media_ready,
            "idle_timeout_seconds": int(self.session.idle_timeout),
            "always_on": self.session.always_on,
            "battery_percent": None,
            "signal_dbm": None,
            "last_event": None,
            "pir_motion": None,
            "charging": None,
            "clean_disconnect": session.clean_disconnect,
            "last_error": session.last_error,
            "lenses": session.lenses,
        }


StatusProvider = Callable[[], dict[str, object]]
BridgeProvider = Callable[[], dict[str, CameraBridge]]
CAMERA_PREFIX = "/api/cameras/"


def camera_id_from_path(path: str) -> str | None:
    """Return the camera identifier from an /api/cameras/<id>/... request path."""

    if not path.startswith(CAMERA_PREFIX):
        return None
    segment = path[len(CAMERA_PREFIX):].split("/", 1)[0]
    if not segment:
        return None
    return unquote(segment)


def multipart_jpeg(
    chunks: Iterator[bytes], *, fps: float = MJPEG_FPS, clock: Callable[[], float] = time.monotonic
) -> Iterator[bytes]:
    """Turn a stream of concatenated JPEGs into rate-limited multipart parts."""

    buffer = bytearray()
    interval = 1.0 / fps
    last = -interval
    for chunk in chunks:
        buffer.extend(chunk)
        while True:
            start = buffer.find(b"\xff\xd8")
            if start < 0:
                # A start marker may be split across reads: keep a trailing 0xff.
                keep = buffer[-1:] == b"\xff"
                buffer.clear()
                if keep:
                    buffer.extend(b"\xff")
                break
            end = buffer.find(b"\xff\xd9", start + 2)
            if end < 0:
                del buffer[:start]
                if len(buffer) > MAX_JPEG_BYTES:
                    buffer.clear()
                break
            image = bytes(buffer[start:end + 2])
            del buffer[:end + 2]
            now = clock()
            if now - last < interval:
                continue
            last = now
            yield (
                f"--{MJPEG_BOUNDARY}\r\nContent-Type: image/jpeg\r\n"
                f"Content-Length: {len(image)}\r\n\r\n"
            ).encode("ascii") + image + b"\r\n"


def viewer_page(bridges: dict[str, "CameraBridge"], token: str) -> bytes:
    """A minimal page showing every lens of every camera as live MJPEG."""

    from html import escape

    safe_token = quote(token, safe="")
    tiles = []
    for bridge in bridges.values():
        camera = quote(bridge.camera_id, safe="")
        for lens in range(bridge.session.lenses):
            label = escape(f"{bridge.camera_name} – lens {lens + 1}")
            source = f"/api/cameras/{camera}/stream.mjpeg?lens={lens}&token={safe_token}"
            snapshot = f"/api/cameras/{camera}/snapshot.jpg?lens={lens}&token={safe_token}"
            tiles.append(
                f'<figure><img src="{source}" alt="{label}">'
                f'<figcaption>{label} · <a href="{snapshot}" target="_blank">snapshot</a>'
                "</figcaption></figure>"
            )
    body = "".join(tiles) or "<p>No cameras are ready.</p>"
    page = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<title>O-KAM cameras</title><style>"
        "body{margin:0;background:#111;color:#ddd;font:14px system-ui,sans-serif}"
        "main{display:grid;gap:8px;padding:8px;grid-template-columns:repeat(auto-fit,minmax(420px,1fr))}"
        "figure{margin:0}img{width:100%;background:#000;display:block}"
        "figcaption{padding:4px 2px}a{color:#8cf}"
        "</style></head><body><main>" + body + "</main>"
        "<p style='padding:0 8px;color:#888'>The first picture can take up to 30 seconds "
        "if the camera was idle.</p></body></html>"
    )
    return page.encode("utf-8")


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    """Terminate, then kill, without letting a slow exit raise."""

    if process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass


def secrets_safe(digest: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def lens_from_query(query: str) -> int | None:
    """The requested lens index; absent means lens 0, malformed means None."""

    values = parse_qs(query).get("lens")
    if not values:
        return 0
    value = values[0]
    return int(value) if value.isdigit() and len(value) == 1 else None


def make_handler(
    status_provider: StatusProvider, bridge_provider: BridgeProvider
) -> type[BaseHTTPRequestHandler]:
    """Build an isolated request handler bound to the supplied runtime providers."""

    class BridgeHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        # Socket deadline: a stalled reader or writer frees its thread.
        timeout = SOCKET_TIMEOUT_SECONDS

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            parsed = urlsplit(self.path)
            if parsed.path == "/health":
                self._json(200, {"service": "okam-native", "status": "ok"})
                return
            if parsed.path == "/ready":
                payload = status_provider()
                ready = bool(payload.get("loader_ready")) and (
                    bool(payload.get("configuration_required"))
                    or bool(payload.get("camera_ready"))
                    or (
                        bool(payload.get("account_ready"))
                        and (
                            not payload.get("connect_test_enabled")
                            or bool(payload.get("p2p_ready"))
                        )
                        and (
                            not payload.get("auth_test_enabled")
                            or bool(payload.get("camera_authenticated"))
                        )
                        and (
                            not payload.get("stream_test_enabled")
                            or bool(payload.get("h264_ready"))
                        )
                        and (
                            not payload.get("snapshot_test_enabled")
                            or bool(payload.get("snapshot_ready"))
                        )
                    )
                )
                self._json(200 if ready else 503, payload)
                return

            bridges = self._bridges()
            if not bridges:
                self._json(503, {"error": "bridge_not_ready"})
                return
            # Browsers cannot send headers, so read-only requests may carry
            # the token in the link instead (?token=...).
            link_token = parse_qs(parsed.query).get("token", [None])[0]
            authorization = self.headers.get("Authorization") or (
                f"Bearer {link_token}" if link_token else None
            )
            if parsed.path in ("/view", "/view/"):
                if not link_token or not any(
                    bridge.authenticated(authorization) for bridge in bridges.values()
                ):
                    self._json(401, {"error": "unauthorized"})
                    return
                page = viewer_page(bridges, link_token)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Length", str(len(page)))
                self.end_headers()
                self.wfile.write(page)
                return
            if parsed.path == "/api/devices":
                if not any(bridge.authenticated(authorization) for bridge in bridges.values()):
                    self._json(401, {"error": "unauthorized"})
                    return
                self._json(
                    200,
                    [
                        {
                            "camera_id": bridge.camera_id,
                            "name": bridge.camera_name,
                            "lenses": bridge.session.lenses,
                        }
                        for bridge in bridges.values()
                    ],
                )
                return
            camera_id = camera_id_from_path(parsed.path)
            bridge = bridges.get(camera_id) if camera_id else None
            if bridge is None:
                self._json(404, {"error": "not_found"})
                return
            camera_prefix = f"/api/cameras/{quote(bridge.camera_id, safe='')}"
            lens = lens_from_query(parsed.query)
            if parsed.path in (
                f"{camera_prefix}/stream.h264",
                f"{camera_prefix}/stream.ts",
            ):
                token = parse_qs(parsed.query).get("token", [None])[0]
                if not bridge.stream_authenticated(token):
                    self._json(401, {"error": "unauthorized"})
                    return
                if lens is None:
                    self._json(400, {"error": "invalid_lens"})
                elif parsed.path.endswith("/stream.ts"):
                    self._muxed_stream(bridge, lens)
                else:
                    self._raw_stream(bridge, lens)
                return
            if not bridge.authenticated(authorization):
                self._json(401, {"error": "unauthorized"})
                return
            if parsed.path == f"{camera_prefix}/status":
                self._json(200, bridge.status())
            elif lens is None:
                self._json(400, {"error": "invalid_lens"})
            elif parsed.path == f"{camera_prefix}/snapshot.jpg":
                self._snapshot(bridge, lens)
            elif parsed.path == f"{camera_prefix}/stream.mjpeg":
                self._mjpeg_stream(bridge, lens)
            elif parsed.path == f"{camera_prefix}/stream/source":
                self._json(
                    200,
                    {"stream_url": bridge.stream_url(self.headers.get("Host"), lens, authorization)},
                )
            else:
                self._json(404, {"error": "not_found"})

        def do_PATCH(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            bridge = self._authorized_bridge()
            if bridge is None:
                return
            camera_prefix = f"/api/cameras/{quote(bridge.camera_id, safe='')}"
            if urlsplit(self.path).path != f"{camera_prefix}/config":
                self._json(404, {"error": "not_found"})
                return
            body = self._request_json()
            if body is None:
                return
            idle_timeout = body.get("idle_timeout_seconds")
            if not isinstance(idle_timeout, int) or not 10 <= idle_timeout <= 600:
                self._json(400, {"error": "invalid_idle_timeout"})
                return
            bridge.session.idle_timeout = float(idle_timeout)
            self._json(200, {"idle_timeout_seconds": idle_timeout})

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            bridge = self._authorized_bridge()
            if bridge is None:
                return
            camera_prefix = f"/api/cameras/{quote(bridge.camera_id, safe='')}"
            path = urlsplit(self.path).path
            if path == f"{camera_prefix}/stream/start":
                if self._request_json() is None:
                    return
                self._json(
                    200,
                    {
                        "stream_url": bridge.stream_url(
                            self.headers.get("Host"), 0, self.headers.get("Authorization")
                        )
                    },
                )
            elif path == f"{camera_prefix}/stream/stop":
                if self._request_json() is None:
                    return
                self._json(200, {"stopped": True})
            else:
                self._json(404, {"error": "not_found"})

        def _bridges(self) -> dict[str, CameraBridge]:
            return bridge_provider() or {}

        def _authorized_bridge(self) -> CameraBridge | None:
            # Changes (PATCH/POST) require the main token, never a guest token.
            bridges = self._bridges()
            if not bridges:
                self._json(503, {"error": "bridge_not_ready"})
                return None
            camera_id = camera_id_from_path(urlsplit(self.path).path)
            bridge = bridges.get(camera_id) if camera_id else None
            if bridge is None:
                self._json(404, {"error": "not_found"})
                return None
            if not bridge.authenticated(self.headers.get("Authorization"), write=True):
                self._json(401, {"error": "unauthorized"})
                return None
            return bridge

        def _snapshot(self, bridge: CameraBridge, lens: int = 0) -> None:
            try:
                jpeg, _width, _height = bridge.session.snapshot(bridge.ffmpeg, lens=lens)
            except P2PError:
                self._json(503, {"error": "snapshot_unavailable"})
                return
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(jpeg)))
            self.end_headers()
            self.wfile.write(jpeg)

        def _raw_stream(self, bridge: CameraBridge, lens: int = 0) -> None:
            try:
                subscription = bridge.session.acquire(lens)
            except P2PError:
                self._json(503, {"error": "stream_unavailable"})
                return
            try:
                self.send_response(200)
                self.send_header("Content-Type", "video/h264")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                for chunk in subscription:
                    self.wfile.write(chunk)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionError, OSError):
                pass
            finally:
                subscription.close()

        def _muxed_stream(self, bridge: CameraBridge, lens: int = 0) -> None:
            """Serve the live stream as MPEG-TS.

            A raw Annex-B elementary stream carries no timestamps, and Home
            Assistant's stream worker rejects it with "No dts in N consecutive
            packets", so live view never produces segments. Muxing to MPEG-TS
            with wall-clock timestamps gives it what it needs, without
            re-encoding.
            """

            self._ffmpeg_stream(
                bridge,
                lens,
                [
                    "-fflags", "+genpts",
                    "-use_wallclock_as_timestamps", "1",
                    "-f", "h264",
                    "-i", "pipe:0",
                    "-c:v", "copy",
                    "-f", "mpegts",
                    "-muxdelay", "0",
                    "-muxpreload", "0",
                    "pipe:1",
                ],
                "video/mp2t",
            )

        def _mjpeg_stream(self, bridge: CameraBridge, lens: int = 0) -> None:
            """Serve the live stream as MJPEG, which browsers show in an <img>.

            Chrome cannot play H.264 elementary streams or MPEG-TS directly;
            a multipart JPEG stream needs no player. The bundled minimal
            FFmpeg has the JPEG encoder and scaler but no multipart muxer or
            fps filter, so frames are framed and rate-limited here.
            """

            self._ffmpeg_stream(
                bridge,
                lens,
                [
                    "-f", "h264",
                    "-i", "pipe:0",
                    "-vf", f"scale='min({MJPEG_WIDTH},iw)':-2",
                    "-q:v", "6",
                    "-f", "image2pipe",
                    "-c:v", "mjpeg",
                    "pipe:1",
                ],
                f"multipart/x-mixed-replace;boundary={MJPEG_BOUNDARY}",
                multipart_jpeg,
            )

        def _ffmpeg_stream(
            self,
            bridge: CameraBridge,
            lens: int,
            arguments: list[str],
            content_type: str,
            frame: Callable[[Iterator[bytes]], Iterator[bytes]] | None = None,
        ) -> None:
            if not _MEDIA_SLOTS.acquire(blocking=False):
                self._json(503, {"error": "too_many_streams"})
                return
            # The slot is released unconditionally, whatever fails below.
            try:
                self._run_ffmpeg_stream(bridge, lens, arguments, content_type, frame)
            finally:
                _MEDIA_SLOTS.release()

        def _run_ffmpeg_stream(
            self,
            bridge: CameraBridge,
            lens: int,
            arguments: list[str],
            content_type: str,
            frame: Callable[[Iterator[bytes]], Iterator[bytes]] | None,
        ) -> None:
            try:
                subscription = bridge.session.acquire(lens)
            except P2PError:
                self._json(503, {"error": "stream_unavailable"})
                return
            muxer: subprocess.Popen[bytes] | None = None
            writer: threading.Thread | None = None
            watchdog: threading.Thread | None = None
            finished = threading.Event()
            # Everything after acquisition shares one cleanup scope, so a
            # client that disconnects while headers are sent (for example
            # while the camera wakes) never leaks the subscription or FFmpeg.
            try:
                try:
                    muxer = subprocess.Popen(
                        [bridge.ffmpeg, "-hide_banner", "-loglevel", "error", *arguments],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        bufsize=0,
                    )
                except (OSError, subprocess.SubprocessError):
                    self._json(503, {"error": "stream_unavailable"})
                    return
                assert muxer.stdin is not None and muxer.stdout is not None
                muxer_input = muxer.stdin
                running = muxer
                last_output = [time.monotonic()]

                def feed() -> None:
                    try:
                        for chunk in subscription:
                            muxer_input.write(chunk)
                            muxer_input.flush()
                    except (BrokenPipeError, ConnectionError, OSError, ValueError):
                        pass
                    finally:
                        try:
                            muxer_input.close()
                        except OSError:
                            pass

                def watch() -> None:
                    # FFmpeg can consume input yet emit nothing; a pipe read
                    # has no deadline, so stop it when output stalls.
                    while not finished.wait(5):
                        if time.monotonic() - last_output[0] > OUTPUT_STALL_SECONDS:
                            _stop_process(running)
                            return

                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                writer = threading.Thread(target=feed, daemon=True)
                writer.start()
                watchdog = threading.Thread(target=watch, daemon=True)
                watchdog.start()
                output = iter(lambda: muxer.stdout.read(STREAM_CHUNK_BYTES), b"")  # type: ignore[union-attr]
                for piece in frame(output) if frame else output:
                    last_output[0] = time.monotonic()
                    self.wfile.write(piece)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionError, OSError):
                pass
            finally:
                finished.set()
                try:
                    subscription.close()
                finally:
                    if muxer is not None:
                        _stop_process(muxer)
                    for thread in (writer, watchdog):
                        if thread is not None:
                            thread.join(timeout=2)

        def _request_json(self) -> dict[str, object] | None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if not 0 < length <= MAX_REQUEST_BYTES:
                self._json(400, {"error": "invalid_request"})
                return None
            try:
                value = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError):
                self._json(400, {"error": "invalid_request"})
                return None
            if not isinstance(value, dict):
                self._json(400, {"error": "invalid_request"})
                return None
            return value

        def _json(self, status: int, payload: object) -> None:
            body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    return BridgeHandler
