"""Exercise CLI requests against an actual local HTTP server."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from okam_native.cli import main


@pytest.fixture
def endpoint(monkeypatch):
    calls = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append((self.path, self.headers.get("Authorization")))
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/leaked")
                self.end_headers()
                return
            if self.path == "/api/devices":
                value = [{"camera_id": "sample alias", "name": "Test camera"}]
            else:
                value = {"state": "idle"}
            data = (b"\xff\xd8test\xff\xd9" if self.path.endswith("snapshot.jpg")
                    else json.dumps(value).encode())
            self.send_response(200)
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("OKAM_API_TOKEN", "test-local-token")
    monkeypatch.setenv("OKAM_BRIDGE_URL", f"http://127.0.0.1:{server.server_port}")
    yield calls
    server.shutdown()
    server.server_close()
    thread.join()


def test_all_status_authenticates_and_encodes_alias(endpoint, capsys):
    assert main(["status"]) == 0
    assert json.loads(capsys.readouterr().out) == [{"state": "idle"}]
    assert endpoint == [("/api/devices", "Bearer test-local-token"),
                        ("/api/cameras/sample%20alias/status", "Bearer test-local-token")]


def test_snapshot_does_not_overwrite(endpoint, tmp_path, capsys):
    target = tmp_path / "image.jpg"
    assert main(["snapshot", "sample alias", str(target)]) == 0
    assert target.read_bytes() == b"\xff\xd8test\xff\xd9"
    target.write_bytes(b"original")
    assert main(["snapshot", "sample alias", str(target)]) == 1
    assert target.read_bytes() == b"original"


def test_missing_token_and_invalid_timeout_make_no_request(endpoint, monkeypatch, capsys):
    monkeypatch.delenv("OKAM_API_TOKEN")
    assert main(["devices"]) == 1
    assert main(["configure", "sample", "--idle-timeout", "0"]) == 1
    assert endpoint == []
    assert "test-local-token" not in capsys.readouterr().err


def test_redirect_is_not_followed(endpoint, monkeypatch):
    from okam_native.cli import request
    from urllib.error import HTTPError
    import os
    with pytest.raises(HTTPError):
        request(os.environ["OKAM_BRIDGE_URL"], "test-local-token", "/redirect")
    assert endpoint == [("/redirect", "Bearer test-local-token")]
