import http.client
import json
import threading
from http.server import ThreadingHTTPServer
from urllib.parse import urlsplit

from okam_native.bridge import CameraBridge, QuietThreadingHTTPServer, make_handler
from okam_native.session import SessionStatus


class FakeSubscription:
    def __init__(self) -> None:
        self.closed = False

    def __iter__(self):
        yield b"\x00\x00\x00\x01h264"

    def close(self) -> None:
        self.closed = True


class FakeSession:
    idle_timeout = 30.0
    always_on = False

    def __init__(self, lenses: int = 1) -> None:
        self.subscription = FakeSubscription()
        self.running = False
        self.media_ready = False
        self.lenses = lenses
        self.lens_requests: list[int] = []

    def status(self) -> SessionStatus:
        return SessionStatus(self.running, 0, True, None, self.media_ready, self.lenses)

    def snapshot(self, _ffmpeg: str, *, lens: int = 0):
        self.lens_requests.append(lens)
        return b"\xff\xd8jpeg\xff\xd9", 2304, 1296

    def acquire(self, lens: int = 0) -> FakeSubscription:
        self.lens_requests.append(lens)
        return self.subscription


def request(server, method: str, path: str, *, token: str | None = None, body=None):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    headers = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    encoded = None
    if body is not None:
        encoded = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    connection.request(method, path, body=encoded, headers=headers)
    response = connection.getresponse()
    payload = response.read()
    connection.close()
    return response.status, response.getheader("Content-Type"), payload


def test_bridge_api_is_authenticated_and_exposes_native_camera() -> None:
    session = FakeSession()
    bridge = CameraBridge(
        camera_id="cabin",
        camera_name="Cabin",
        api_token="safe-api-token-123",
        session=session,  # type: ignore[arg-type]
        ffmpeg="/usr/bin/ffmpeg",
    )
    status = {
        "loader_ready": True,
        "account_ready": True,
        "camera_ready": True,
        "configuration_required": False,
    }
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), make_handler(lambda: status, lambda: {"cabin": bridge})
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert request(server, "GET", "/health")[0] == 200
        assert request(server, "GET", "/api/devices")[0] == 401
        code, _, payload = request(
            server, "GET", "/api/devices", token="safe-api-token-123"
        )
        assert code == 200
        assert json.loads(payload) == [{"camera_id": "cabin", "lenses": 1, "name": "Cabin"}]

        code, _, payload = request(
            server,
            "GET",
            "/api/cameras/cabin/stream/source",
            token="safe-api-token-123",
        )
        assert code == 200
        stream_url = json.loads(payload)["stream_url"]
        assert "safe-api-token-123" not in stream_url
        parsed = urlsplit(stream_url)
        # The advertised source is MPEG-TS: a raw elementary stream carries no
        # timestamps and Home Assistant's stream worker rejects it.
        assert parsed.path.endswith("/stream.ts")
        raw_path = parsed.path.replace("/stream.ts", "/stream.h264")
        code, content_type, payload = request(server, "GET", raw_path + "?" + parsed.query)
        assert code == 200
        assert content_type == "video/h264"
        assert payload.endswith(b"h264")
        assert session.subscription.closed is True

        # The muxed endpoint degrades rather than hanging when the muxer is
        # unavailable, and it never leaks the subscription.
        code, _content_type, _payload = request(
            server, "GET", parsed.path + "?" + parsed.query
        )
        assert code == 503
        assert session.subscription.closed is True

        code, content_type, payload = request(
            server,
            "GET",
            "/api/cameras/cabin/snapshot.jpg",
            token="safe-api-token-123",
        )
        assert code == 200
        assert content_type == "image/jpeg"
        assert payload.startswith(b"\xff\xd8")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_bridge_idle_timeout_is_bounded() -> None:
    session = FakeSession()
    bridge = CameraBridge(
        camera_id="cabin",
        camera_name="Cabin",
        api_token="safe-api-token-123",
        session=session,  # type: ignore[arg-type]
        ffmpeg="ffmpeg",
    )
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        make_handler(lambda: {"loader_ready": True, "camera_ready": True}, lambda: {"cabin": bridge}),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        code, _, _ = request(
            server,
            "PATCH",
            "/api/cameras/cabin/config",
            token="safe-api-token-123",
            body={"idle_timeout_seconds": 45},
        )
        assert code == 200
        assert session.idle_timeout == 45.0
        code, _, _ = request(
            server,
            "PATCH",
            "/api/cameras/cabin/config",
            token="safe-api-token-123",
            body={"idle_timeout_seconds": 1},
        )
        assert code == 400
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_bridge_reports_idle_waking_and_streaming_states() -> None:
    session = FakeSession()
    bridge = CameraBridge(
        camera_id="cabin",
        camera_name="Cabin",
        api_token="safe-api-token-123",
        session=session,  # type: ignore[arg-type]
        ffmpeg="ffmpeg",
    )

    assert bridge.status()["state"] == "idle"
    assert bridge.status()["media_ready"] is False
    assert bridge.status()["idle_timeout_seconds"] == 30
    session.running = True
    assert bridge.status()["state"] == "waking"
    session.media_ready = True
    assert bridge.status()["state"] == "streaming"


def test_dropped_clients_do_not_report_a_crash(capsys) -> None:
    # The supervisor polls the bridge and closes connections abruptly. The
    # default handler prints a traceback and the peer address for each one.
    server = object.__new__(QuietThreadingHTTPServer)
    peer = ("172.30.32.2", 47536)

    for benign in (ConnectionResetError, BrokenPipeError, TimeoutError):
        try:
            raise benign("client went away")
        except benign:
            server.handle_error(object(), peer)
    assert capsys.readouterr().err == ""

    try:
        raise ValueError("a real fault")
    except ValueError:
        server.handle_error(object(), peer)
    captured = capsys.readouterr().err
    assert "bridge_request_failed error=ValueError" in captured
    assert "172.30.32.2" not in captured
    assert "Traceback" not in captured


def _multi_camera_server():
    cabin = CameraBridge(
        camera_id="cabin",
        camera_name="Cabin",
        api_token="safe-api-token-123",
        session=FakeSession(),  # type: ignore[arg-type]
        ffmpeg="ffmpeg",
    )
    gate = CameraBridge(
        camera_id="gate",
        camera_name="Gate",
        api_token="safe-api-token-123",
        session=FakeSession(),  # type: ignore[arg-type]
        ffmpeg="ffmpeg",
    )
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        make_handler(
            lambda: {"loader_ready": True, "camera_ready": True},
            lambda: {"cabin": cabin, "gate": gate},
        ),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, cabin, gate


def test_bridge_serves_several_cameras_from_one_registry() -> None:
    server, thread, cabin, gate = _multi_camera_server()
    try:
        # Auth is required for the device list and for every camera route.
        assert request(server, "GET", "/api/devices")[0] == 401
        assert (
            request(server, "GET", "/api/cameras/cabin/status", token="wrong")[0]
            == 401
        )

        code, _, payload = request(
            server, "GET", "/api/devices", token="safe-api-token-123"
        )
        assert code == 200
        assert json.loads(payload) == [
            {"camera_id": "cabin", "lenses": 1, "name": "Cabin"},
            {"camera_id": "gate", "lenses": 1, "name": "Gate"},
        ]

        # Each camera resolves to its own bridge, never to another one.
        for camera_id in ("cabin", "gate"):
            code, _, payload = request(
                server,
                "GET",
                f"/api/cameras/{camera_id}/status",
                token="safe-api-token-123",
            )
            assert code == 200
            assert json.loads(payload)["camera_id"] == camera_id

        code, _, _ = request(
            server, "GET", "/api/cameras/shed/status", token="safe-api-token-123"
        )
        assert code == 404

        # A stream token is scoped to the camera that issued it.
        code, _, payload = request(
            server,
            "GET",
            "/api/cameras/gate/stream/source",
            token="safe-api-token-123",
        )
        assert code == 200
        parsed = urlsplit(json.loads(payload)["stream_url"])
        assert parsed.path.startswith("/api/cameras/gate/")
        query = parsed.query
        # The advertised source is MPEG-TS; the raw elementary stream is what
        # this test can consume without a real muxer.
        raw_path = parsed.path.replace("/stream.ts", "/stream.h264")
        assert request(server, "GET", f"{raw_path}?{query}")[0] == 200
        assert (
            request(server, "GET", f"/api/cameras/cabin/stream.h264?{query}")[0]
            == 401
        )

        # Only the requested camera's idle timeout changes.
        code, _, _ = request(
            server,
            "PATCH",
            "/api/cameras/gate/config",
            token="safe-api-token-123",
            body={"idle_timeout_seconds": 45},
        )
        assert code == 200
        assert gate.session.idle_timeout == 45.0
        assert cabin.session.idle_timeout == FakeSession.idle_timeout
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_bridge_routes_the_requested_lens_and_rejects_malformed_ones() -> None:
    session = FakeSession(lenses=2)
    bridge = CameraBridge(
        camera_id="cabin",
        camera_name="Cabin",
        api_token="safe-api-token-123",
        session=session,  # type: ignore[arg-type]
        ffmpeg="/usr/bin/ffmpeg",
    )
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), make_handler(lambda: {}, lambda: {"cabin": bridge})
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        token = "safe-api-token-123"
        code, _, payload = request(server, "GET", "/api/cameras/cabin/status", token=token)
        assert code == 200 and json.loads(payload)["lenses"] == 2

        code, _, _ = request(server, "GET", "/api/cameras/cabin/snapshot.jpg?lens=1", token=token)
        assert code == 200
        code, _, _ = request(server, "GET", "/api/cameras/cabin/snapshot.jpg", token=token)
        assert code == 200
        assert session.lens_requests == [1, 0]

        code, _, payload = request(
            server, "GET", "/api/cameras/cabin/stream/source?lens=1", token=token
        )
        assert code == 200 and json.loads(payload)["stream_url"].endswith("&lens=1")
        code, _, payload = request(
            server, "GET", "/api/cameras/cabin/stream/source", token=token
        )
        assert "lens=" not in json.loads(payload)["stream_url"]

        for bad in ("x", "-1", "12"):
            code, _, _ = request(
                server, "GET", f"/api/cameras/cabin/snapshot.jpg?lens={bad}", token=token
            )
            assert code == 400, bad
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_guest_tokens_can_view_but_not_change_settings() -> None:
    session = FakeSession()
    bridge = CameraBridge(
        camera_id="cabin",
        camera_name="Cabin",
        api_token="safe-api-token-123",
        session=session,  # type: ignore[arg-type]
        ffmpeg="/usr/bin/ffmpeg",
        guest_tokens={"friend": "guest-token-abcdefgh"},
    )
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), make_handler(lambda: {}, lambda: {"cabin": bridge})
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        guest = "guest-token-abcdefgh"
        assert request(server, "GET", "/api/devices", token=guest)[0] == 200
        assert request(server, "GET", "/api/cameras/cabin/status", token=guest)[0] == 200
        assert request(server, "GET", "/api/cameras/cabin/snapshot.jpg", token=guest)[0] == 200
        assert request(server, "GET", "/api/cameras/cabin/stream/source", token=guest)[0] == 200
        code, _, _ = request(
            server, "PATCH", "/api/cameras/cabin/config", token=guest,
            body={"idle_timeout_seconds": 60},
        )
        assert code == 401
        code, _, _ = request(
            server, "PATCH", "/api/cameras/cabin/config", token="safe-api-token-123",
            body={"idle_timeout_seconds": 60},
        )
        assert code == 200
        assert request(server, "GET", "/api/devices", token="revoked-token-xyz")[0] == 401
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_browser_viewer_and_links_accept_a_token_for_viewing_only() -> None:
    session = FakeSession(lenses=2)
    bridge = CameraBridge(
        camera_id="cabin",
        camera_name="Cabin",
        api_token="safe-api-token-123",
        session=session,  # type: ignore[arg-type]
        ffmpeg="/nonexistent/ffmpeg",
        guest_tokens={"friend": "guest-token-abcdefgh"},
    )
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), make_handler(lambda: {}, lambda: {"cabin": bridge})
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert request(server, "GET", "/view")[0] == 401
        assert request(server, "GET", "/view?token=wrong-token-123")[0] == 401
        code, headers, page = request(server, "GET", "/view?token=guest-token-abcdefgh")
        assert code == 200
        html = page.decode("utf-8")
        assert html.count("<img ") == 2
        assert "/api/cameras/cabin/stream.mjpeg?lens=1&amp;token=guest-token-abcdefgh" in html or (
            "/api/cameras/cabin/stream.mjpeg?lens=1&token=guest-token-abcdefgh" in html
        )
        code, _, _ = request(
            server, "GET", "/api/cameras/cabin/snapshot.jpg?lens=1&token=guest-token-abcdefgh"
        )
        assert code == 200 and session.lens_requests[-1] == 1
        assert request(server, "GET", "/api/devices?token=guest-token-abcdefgh")[0] == 200
        # A link token never authorizes changes.
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        body = json.dumps({"idle_timeout_seconds": 60})
        connection.request(
            "PATCH", "/api/cameras/cabin/config?token=safe-api-token-123", body=body,
            headers={"Content-Type": "application/json"},
        )
        assert connection.getresponse().status == 401
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_multipart_jpeg_frames_split_chunks_and_limit_the_rate() -> None:
    from okam_native.bridge import multipart_jpeg

    jpeg = b"\xff\xd8body\xff\xd9"
    stream = b"junk" + jpeg * 4
    chunks = [stream[:7], stream[7:19], stream[19:]]
    times = iter([0.0, 0.1, 0.25, 0.5])
    parts = list(multipart_jpeg(iter(chunks), fps=5, clock=lambda: next(times)))
    # Frames at 0.0, 0.25 and 0.5 s pass a 5 fps limit; the one at 0.1 s is dropped.
    assert len(parts) == 3
    assert parts[0].startswith(b"--okamframe\r\nContent-Type: image/jpeg\r\n")
    assert parts[0].endswith(jpeg + b"\r\n")


def _bridge(**kwargs) -> CameraBridge:
    return CameraBridge(
        camera_id="cabin",
        camera_name="Cabin",
        api_token=kwargs.pop("api_token", "safe-api-token-123"),
        session=FakeSession(),  # type: ignore[arg-type]
        ffmpeg="/nonexistent/ffmpeg",
        **kwargs,
    )


def test_stream_urls_survive_restarts_and_die_with_their_token() -> None:
    from urllib.parse import parse_qs, urlsplit

    def stream_token(url: str) -> str:
        return parse_qs(urlsplit(url).query)["token"][0]

    first = _bridge(guest_tokens={"friend": "guest-token-abcdefgh"})
    restarted = _bridge(guest_tokens={"friend": "guest-token-abcdefgh"})
    main_url = first.stream_url("bridge:8099")
    # A restarted bridge accepts the URL Home Assistant cached earlier.
    assert restarted.stream_authenticated(stream_token(main_url))

    guest_url = first.stream_url("bridge:8099", 0, "Bearer guest-token-abcdefgh")
    assert stream_token(guest_url) != stream_token(main_url)
    revoked = _bridge(guest_tokens={})
    assert not revoked.stream_authenticated(stream_token(guest_url))
    assert revoked.stream_authenticated(stream_token(main_url))
    assert not _bridge(api_token="rotated-api-token-456").stream_authenticated(stream_token(main_url))


def test_non_ascii_tokens_never_break_authentication() -> None:
    bridge = _bridge(guest_tokens={"odd": "guest-token-ééééé"})
    assert bridge.authenticated("Bearer safe-api-token-123")
    assert not bridge.authenticated("Bearer ünicode-token-value")
    assert not bridge.stream_authenticated("ünicode")


def test_multipart_jpeg_keeps_a_start_marker_split_across_reads() -> None:
    from okam_native.bridge import multipart_jpeg

    jpeg = b"\xff\xd8body\xff\xd9"
    for split in range(1, len(jpeg)):
        parts = list(multipart_jpeg(iter([b"xx" + jpeg[:split], jpeg[split:]]), fps=1000))
        assert len(parts) == 1, split


def test_media_slots_are_released_even_when_acquisition_fails_unexpectedly() -> None:
    import okam_native.bridge as bridge_module

    class Exploding(FakeSession):
        def acquire(self, lens: int = 0):
            raise OSError("unexpected")

    bridge = CameraBridge(
        camera_id="cabin", camera_name="Cabin", api_token="safe-api-token-123",
        session=Exploding(), ffmpeg="/nonexistent/ffmpeg",  # type: ignore[arg-type]
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(lambda: {}, lambda: {"cabin": bridge}))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for _ in range(bridge_module.MAX_MEDIA_STREAMS + 2):
            try:
                request(server, "GET", "/api/cameras/cabin/stream.mjpeg?token=safe-api-token-123")
            except Exception:
                pass
        # Every slot came back: a fresh acquire still succeeds.
        assert bridge_module._MEDIA_SLOTS.acquire(blocking=False)
        bridge_module._MEDIA_SLOTS.release()
        acquired = 0
        while bridge_module._MEDIA_SLOTS.acquire(blocking=False):
            acquired += 1
        for _ in range(acquired):
            bridge_module._MEDIA_SLOTS.release()
        assert acquired == bridge_module.MAX_MEDIA_STREAMS
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
