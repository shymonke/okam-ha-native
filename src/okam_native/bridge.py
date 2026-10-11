"""Authenticated HTTP compatibility API for the native O-KAM bridge."""

from __future__ import annotations

import hmac
import json
import re
import secrets
import subprocess
import sys
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlsplit

from .p2p import P2PError
from .session import NativeStreamSession


MAX_REQUEST_BYTES = 4096
STREAM_CHUNK_BYTES = 32 * 1024
# A client going away mid-request is normal here: the supervisor polls the
# bridge, and media consumers disconnect whenever a view closes.
_EXPECTED_DISCONNECTS = (
    BrokenPipeError,
    ConnectionAbortedError,
    ConnectionResetError,
    TimeoutError,
)
HOST_PATTERN = re.compile(r"^(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(?::[0-9]{1,5})?$")


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    """An HTTP server that does not report a dropped client as a crash.

    The default handler prints a full traceback and the peer address whenever a
    client disconnects mid-request. The supervisor polls this bridge and closes
    connections abruptly, which filled the app log with alarming
    ConnectionResetError tracebacks for entirely normal behaviour.
    """

    daemon_threads = True

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
        self._stream_token = secrets.token_urlsafe(32)
        self.session = session
        self.ffmpeg = ffmpeg

    def authenticated(self, authorization: str | None, *, write: bool = False) -> bool:
        """Accept the main token, or a guest token for read-only requests."""

        if not isinstance(authorization, str):
            return False
        accepted = [self._api_token] if write else [self._api_token, *self._guest_tokens.values()]
        # Compare against every candidate so timing does not reveal which matched.
        results = [hmac.compare_digest(authorization, f"Bearer {token}") for token in accepted]
        return any(results)

    def stream_authenticated(self, token: str | None) -> bool:
        return isinstance(token, str) and hmac.compare_digest(token, self._stream_token)

    def stream_url(self, host: str | None, lens: int = 0) -> str:
        safe_host = host if isinstance(host, str) and HOST_PATTERN.fullmatch(host) else "127.0.0.1:8099"
        camera = quote(self.camera_id, safe="")
        token = quote(self._stream_token, safe="")
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
            if parsed.path == "/api/devices":
                if not self._authenticated_any(bridges):
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
            if not bridge.authenticated(self.headers.get("Authorization")):
                self._json(401, {"error": "unauthorized"})
                return
            if parsed.path == f"{camera_prefix}/status":
                self._json(200, bridge.status())
            elif lens is None:
                self._json(400, {"error": "invalid_lens"})
            elif parsed.path == f"{camera_prefix}/snapshot.jpg":
                self._snapshot(bridge, lens)
            elif parsed.path == f"{camera_prefix}/stream/source":
                self._json(
                    200,
                    {"stream_url": bridge.stream_url(self.headers.get("Host"), lens)},
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
                self._json(200, {"stream_url": bridge.stream_url(self.headers.get("Host"))})
            elif path == f"{camera_prefix}/stream/stop":
                if self._request_json() is None:
                    return
                self._json(200, {"stopped": True})
            else:
                self._json(404, {"error": "not_found"})

        def _bridges(self) -> dict[str, CameraBridge]:
            return bridge_provider() or {}

        def _authenticated_any(self, bridges: dict[str, CameraBridge]) -> bool:
            authorization = self.headers.get("Authorization")
            return any(
                bridge.authenticated(authorization) for bridge in bridges.values()
            )

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
            self.send_response(200)
            self.send_header("Content-Type", "video/h264")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            try:
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

            try:
                subscription = bridge.session.acquire(lens)
            except P2PError:
                self._json(503, {"error": "stream_unavailable"})
                return
            muxer: subprocess.Popen[bytes] | None = None
            writer: threading.Thread | None = None
            try:
                muxer = subprocess.Popen(
                    [
                        bridge.ffmpeg,
                        "-hide_banner",
                        "-loglevel", "error",
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
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    bufsize=0,
                )
            except (OSError, subprocess.SubprocessError):
                subscription.close()
                self._json(503, {"error": "stream_unavailable"})
                return
            assert muxer.stdin is not None and muxer.stdout is not None

            def feed() -> None:
                try:
                    for chunk in subscription:
                        muxer.stdin.write(chunk)  # type: ignore[union-attr]
                        muxer.stdin.flush()  # type: ignore[union-attr]
                except (BrokenPipeError, ConnectionError, OSError, ValueError):
                    pass
                finally:
                    try:
                        muxer.stdin.close()  # type: ignore[union-attr]
                    except OSError:
                        pass

            self.send_response(200)
            self.send_header("Content-Type", "video/mp2t")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            try:
                writer = threading.Thread(target=feed, daemon=True)
                writer.start()
                while True:
                    piece = muxer.stdout.read(STREAM_CHUNK_BYTES)
                    if not piece:
                        break
                    self.wfile.write(piece)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionError, OSError):
                pass
            finally:
                subscription.close()
                if muxer.poll() is None:
                    muxer.terminate()
                    try:
                        muxer.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        muxer.kill()
                        muxer.wait(timeout=5)
                if writer is not None:
                    writer.join(timeout=2)

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
