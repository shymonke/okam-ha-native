"""Direct camera CLI commands with synthetic inputs and fakes only."""
import io
import json
import threading
import urllib.request
from pathlib import Path

import pytest

from okam_native import direct_cli
from okam_native.account import AccountDevice
from okam_native.cli import main, run_direct
from okam_native.vp_helper import encode_lens_record
from test_vp import record
from test_vp_credentials import SALT, encrypt_password

SECURITY = encrypt_password(b"Abc123def456ghi", "123456789")


class Client:
    user_id = "123456789"
    login_token = "tok"

    def enumerate(self, email, password):
        assert email == "user@example.com" and password == "secret"
        return [AccountDevice(uid="VP1", name="Parking Lot", device_password="", security=SECURITY),
                AccountDevice(uid="CS1", name="Gate", device_password="pw")]


class Resolution:
    def native_connection_input(self):
        return "TEST%%" + record()


def resolver(_uid):
    return Resolution()


def test_login_prompts_for_password_and_finds_cameras_by_alias_or_name():
    client, devices = direct_cli.login(None, client_factory=Client, prompt=lambda _: "user@example.com",
                                       secret_prompt=lambda _: "secret", saved=lambda: None)
    assert direct_cli.find_camera(devices, "parking-lot").uid == "VP1"
    assert direct_cli.find_camera(devices, "Gate").uid == "CS1"
    with pytest.raises(direct_cli.CliError, match="not found"):
        direct_cli.find_camera(devices, "missing")


def test_camera_list_hides_secrets_unless_requested():
    client, devices = Client(), Client().enumerate("user@example.com", "secret")
    plain = direct_cli.list_cameras(client, devices, show_secrets=False, salt=None, resolver=resolver)
    assert plain == [{"name": "Parking Lot", "alias": "parking-lot", "transport": "VP"},
                     {"name": "Gate", "alias": "gate", "transport": "CS2"}]
    shown = direct_cli.list_cameras(client, devices, show_secrets=True, salt=SALT, resolver=resolver)
    assert shown[0]["camera_password"] == "Abc123def456ghi"
    assert shown[0]["connection"].startswith("TEST%%DAS-")
    assert "camera_password" not in shown[1]


def test_salt_is_read_from_file_or_prompt(tmp_path):
    path = tmp_path / "salt.txt"
    path.write_text(SALT + "\n", encoding="ascii")
    assert direct_cli.read_salt(path) == SALT
    assert direct_cli.read_salt(None, secret_prompt=lambda _: SALT, saved=lambda: None) == SALT
    with pytest.raises(direct_cli.CliError):
        direct_cli.read_salt(None, secret_prompt=lambda _: "", saved=lambda: None)


def test_cs2_cameras_are_refused_for_streaming():
    device = AccountDevice(uid="CS1", name="Gate", device_password="pw")
    with pytest.raises(direct_cli.CliError, match="VP cameras only"):
        direct_cli.vp_inputs(Client(), device, SALT, resolver=resolver)


class Process:
    def __init__(self, data=b"\x00\x00\x00\x01" + b"v" * 100):
        self.stdout = io.BytesIO(data)
        self.returncode = None
        self.terminated = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = 0

    def wait(self, timeout=None):
        return 0


def _encoded_frames(count, shade):
    """Real H.264 access units (first one a keyframe) from a tiny synthetic picture."""
    av = pytest.importorskip("av")
    codec = av.CodecContext.create("libx264", "w")
    codec.width, codec.height, codec.pix_fmt = 64, 48, "yuv420p"
    codec.options = {"g": "1000", "bf": "0", "tune": "zerolatency"}
    frames = []
    for index in range(count):
        picture = av.VideoFrame(64, 48, "yuv420p")
        for plane in picture.planes:
            plane.update(bytes([(shade + index * 3) % 256]) * plane.buffer_size)
        frames += [bytes(packet) for packet in codec.encode(picture)]
    frames += [bytes(packet) for packet in codec.encode(None)]
    return frames


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        self.now += 0.05
        return self.now


def _framed(records):
    return b"".join(encode_lens_record(lens, payload) for lens, payload in records)


def _two_lens_process():
    lens0, lens1 = _encoded_frames(20, 40), _encoded_frames(20, 200)
    # A lens-1 P-frame before its first keyframe must be dropped.
    records = [(1, lens1[3])] + [item for pair in zip(((0, f) for f in lens0), ((1, f) for f in lens1))
                                 for item in pair]
    return Process(data=_framed(records))


@pytest.mark.parametrize("suffix", [".h264", ".mp4"])
def test_clip_writes_each_lens_to_its_own_decodable_file(tmp_path, suffix):
    process = _two_lens_process()
    result = direct_cli.record_clip(lambda: process, tmp_path / f"clip{suffix}", 60, clock=Clock())
    assert process.terminated and result["saved"]
    assert [item["lens"] for item in result["lenses"]] == [0, 1]
    for item in result["lenses"]:
        path = Path(item["file"])
        assert path.name == f"clip-lens{item['lens']}{suffix}" and path.exists()
        assert item["frames"] == 20 and item["decoded_frames"] == 20
    assert sorted(path.name for path in tmp_path.iterdir()) == [f"clip-lens0{suffix}", f"clip-lens1{suffix}"]


def test_clip_one_lens_writes_the_exact_output(tmp_path):
    output = tmp_path / "parking.mp4"
    result = direct_cli.record_clip(lambda: _two_lens_process(), output, 60, lens=1, clock=Clock())
    assert [item["lens"] for item in result["lenses"]] == [1]
    assert output.exists() and result["lenses"][0]["decoded_frames"] == 20


def test_clip_timer_starts_at_the_first_frame(tmp_path):
    frames = _encoded_frames(30, 90)
    process = Process(data=_framed((0, frame) for frame in frames))
    # 0.05 s per clock read; a 1 s clip keeps only the first few frames.
    result = direct_cli.record_clip(lambda: process, tmp_path / "clip.h264", 1, lens=0, clock=Clock(),
                                    startup_timeout=0.2)
    assert 0 < result["lenses"][0]["frames"] < 30


@pytest.mark.parametrize("name, seconds, message", [
    ("clip.h264", 0, "1 to 600"), ("clip.mkv", 5, ".h264 or .mp4"),
])
def test_clip_rejects_bad_requests_before_streaming(tmp_path, name, seconds, message):
    started = []
    with pytest.raises(direct_cli.CliError, match=message):
        direct_cli.record_clip(lambda: started.append(1), tmp_path / name, seconds)
    assert not started


def test_clip_refuses_to_overwrite_any_lens_file(tmp_path):
    (tmp_path / "clip-lens1.mp4").write_bytes(b"keep")
    with pytest.raises(direct_cli.CliError, match="already exists"):
        direct_cli.record_clip(lambda: pytest.fail("must not start"), tmp_path / "clip.mp4", 5)
    assert (tmp_path / "clip-lens1.mp4").read_bytes() == b"keep"


def test_grab_saves_snapshot_without_overwriting(tmp_path):
    class Session:
        def __init__(self, starter, idle_timeout):
            self.closed = False

        def snapshot(self, ffmpeg):
            return b"\xff\xd8jpeg\xff\xd9", 640, 360

        def close(self):
            self.closed = True

    output = tmp_path / "frame.jpg"
    assert direct_cli.grab_jpeg(lambda: None, output, which=lambda _: "ffmpeg",
                                session_factory=Session)["width"] == 640
    with pytest.raises(direct_cli.CliError, match="already exists"):
        direct_cli.grab_jpeg(lambda: None, output, which=lambda _: "ffmpeg", session_factory=Session)


def test_serve_streams_h264_and_stops_cleanly():
    class Subscription:
        def __iter__(self):
            yield b"\x00\x00\x00\x01live"

        def close(self):
            pass

    class Session:
        closed = False

        def __init__(self, starter, idle_timeout):
            pass

        def acquire(self):
            return Subscription()

        def close(self):
            Session.closed = True

    stop = threading.Event()
    out, err = io.StringIO(), io.StringIO()
    thread = threading.Thread(target=direct_cli.serve, args=(lambda: None, "127.0.0.1:0"),
                              kwargs={"out": out, "err": err, "stop": stop, "session_factory": Session})
    thread.start()
    for _ in range(100):
        if "streaming at" in out.getvalue():
            break
        threading.Event().wait(0.02)
    url = out.getvalue().split("streaming at ", 1)[1].split()[0]
    with urllib.request.urlopen(url, timeout=5) as response:
        assert response.headers["Content-Type"] == "video/h264"
        assert response.read() == b"\x00\x00\x00\x01live"
    stop.set()
    thread.join(timeout=5)
    assert Session.closed and not err.getvalue()


def test_serve_warns_when_bound_beyond_localhost():
    class Server:
        server_address = ("0.0.0.0", 1)
        daemon_threads = False

        def __init__(self, address, handler):
            pass

        def serve_forever(self):
            pass

        def shutdown(self):
            pass

        def server_close(self):
            pass

    err = io.StringIO()
    stop = threading.Event()
    stop.set()
    direct_cli.serve(lambda: None, "0.0.0.0:8554", out=io.StringIO(), err=err, stop=stop,
                     server_factory=Server, session_factory=lambda *_a, **_k: type(
                         "S", (), {"close": lambda self: None})())
    assert "unauthenticated" in err.getvalue()


def test_cameras_command_prints_no_secrets_by_default(capsys):
    def login(_email):
        client = Client()
        return client, client.enumerate("user@example.com", "secret")

    args = main.__globals__["argparse"].Namespace(command="cameras", email=None, vp_salt_file=None,
                                                  show_secrets=False)
    assert run_direct(args, login=login) == 0
    output = capsys.readouterr()
    assert json.loads(output.out)[0]["alias"] == "parking-lot"
    assert "Abc123" not in output.out + output.err


def test_failures_do_not_echo_private_input(capsys):
    def login(_email):
        raise direct_cli.CliError("camera not found (use the name or alias from 'okam cameras')")

    args = main.__globals__["argparse"].Namespace(command="cameras", email="secret-email",
                                                  vp_salt_file=None, show_secrets=False)
    assert run_direct(args, login=login) == 1
    assert "secret-email" not in capsys.readouterr().err


def test_parser_has_no_password_argument():
    with pytest.raises(SystemExit):
        main(["cameras", "--password", "x"])


def test_clip_failure_explains_the_worker_stage_and_removes_the_empty_file(tmp_path):
    process = Process(data=b"")
    process.stderr = io.BytesIO(json.dumps({
        "connected": True, "authenticated": False, "failure": "VP native stream failed",
        "failure_stage": "authentication", "failure_code": "unclassified"}).encode() + b"\n")
    output = tmp_path / "clip.h264"
    with pytest.raises(direct_cli.CliError) as error:
        direct_cli.record_clip(lambda: process, output, 5)
    message = str(error.value)
    assert "did not accept the login" in message
    assert "connected=yes, authenticated=no, code=unclassified" in message
    assert not output.exists()


@pytest.mark.parametrize("stderr, expected", [
    (b"", "without a summary"),
    (b"not json\n", "without a summary"),
    (b'{"failure":"VP worker input is invalid"}\n', "rejected its inputs"),
    (b'{"failure_stage":"connect","failure_code":"bad code!"}\n', "could not be reached"),
])
def test_worker_failure_handles_missing_or_unexpected_summaries(stderr, expected):
    process = Process(data=b"")
    process.stderr = io.BytesIO(stderr)
    message = direct_cli.worker_failure(process)
    assert expected in message
    assert "bad code" not in message


def test_login_hints_that_the_password_is_hidden_and_reports_progress():
    prompts, status = [], io.StringIO()
    direct_cli.login("user@example.com", client_factory=Client,
                     secret_prompt=lambda text: prompts.append(text) or "secret", status=status)
    assert "nothing appears as you type" in prompts[0]
    assert "Signed in; 2 camera(s)" in status.getvalue()


class Store:
    def __init__(self, **values):
        self.values = values

    def get_password(self, service, name):
        assert service == direct_cli.KEYRING_SERVICE
        return self.values.get(name)

    def set_password(self, service, name, value):
        self.values[name] = value

    def delete_password(self, service, name):
        del self.values[name]


def test_login_uses_saved_credentials_without_prompting():
    status = io.StringIO()
    saved = lambda: direct_cli.saved_credentials(environ={}, store=Store(email="user@example.com",
                                                                          password="secret"))
    client, devices = direct_cli.login(None, client_factory=Client, saved=saved, status=status,
                                       prompt=pytest.fail, secret_prompt=pytest.fail)
    assert len(devices) == 2 and "saved O-KAM login" in status.getvalue()


def test_environment_credentials_take_precedence_and_need_both_values():
    environ = {"OKAM_EMAIL": "env@example.com", "OKAM_PASSWORD": "envpass"}
    assert direct_cli.saved_credentials(environ=environ, store=Store()) == ("env@example.com", "envpass")
    assert direct_cli.saved_credentials(environ={"OKAM_EMAIL": "x@example.com"}, store=Store()) is None
    assert direct_cli.saved_credentials(environ={}, store=False) is None


def test_save_login_verifies_before_storing_and_logout_removes(tmp_path):
    salt_file = tmp_path / "salt.txt"
    salt_file.write_text(SALT + "\n", encoding="ascii")
    store = Store()
    result = direct_cli.save_login("user@example.com", salt_file, client_factory=Client, store=store,
                                   secret_prompt=lambda _: "secret", status=io.StringIO())
    assert result == {"saved": True, "cameras": 2, "vp_password_key_saved": True}
    assert store.values == {"email": "user@example.com", "password": "secret", "vp_password_salt": SALT}
    assert "secret" not in json.dumps(result)
    assert direct_cli.forget_login(store=store) == {"removed": 3} and not store.values


def test_save_login_stores_nothing_when_the_account_rejects_it():
    class Rejecting(Client):
        def enumerate(self, email, password):
            raise direct_cli.CliError("rejected")

    store = Store()
    with pytest.raises(direct_cli.CliError):
        direct_cli.save_login("user@example.com", None, client_factory=Rejecting, store=store,
                              secret_prompt=lambda _: "wrong", status=io.StringIO())
    assert not store.values


def test_salt_falls_back_to_the_saved_key_before_prompting():
    assert direct_cli.read_salt(None, saved=lambda: SALT, secret_prompt=pytest.fail) == SALT


def test_waking_requests_a_wake_before_each_session_start(tmp_path):
    source = tmp_path / "device_wakeup_server.dart"
    source.write_text("secretKey = 'synthetic-secret';\ndata['AccessKey'] = 'synthetic-access';\n")
    woken, started, status = [], [], io.StringIO()

    async def waker(did, credentials, *, timeout):
        woken.append((did, credentials.access_key))
        return type("Result", (), {"responsive_servers": 2})()

    device = AccountDevice(uid="VPCAM1", name="Parking", device_password="", security=SECURITY)
    start = direct_cli.waking(lambda: started.append(len(woken)) or "process", device, status=status,
                              source=lambda: source, waker=waker)
    assert start() == "process" and start() == "process"
    assert woken == [("VPCAM1", "synthetic-access")] * 2 and started == [1, 2]
    assert "2 wake server(s)" in status.getvalue() and "synthetic" not in status.getvalue()


def test_waking_still_connects_without_wake_configuration_or_service(tmp_path):
    from okam_native.wakeup import WakeError
    device = AccountDevice(uid="VPCAM1", name="Parking", device_password="", security=SECURITY)
    status = io.StringIO()
    assert direct_cli.waking(lambda: "p", device, status=status, source=lambda: None)() == "p"
    assert "wake configuration not found" in status.getvalue()

    async def failing(*_args, **_kwargs):
        raise WakeError("down")

    source = tmp_path / "device_wakeup_server.dart"
    source.write_text("secretKey = 's';\ndata['AccessKey'] = 'a';\n")
    status = io.StringIO()
    assert direct_cli.waking(lambda: "p", device, status=status, source=lambda: source, waker=failing)() == "p"
    assert "unreachable" in status.getvalue()


def _failed_process(stage):
    process = Process(data=b"")
    process.stderr = io.BytesIO(json.dumps({"failure": "VP native stream failed", "failure_stage": stage,
                                            "failure_code": "connection_timed_out"}).encode() + b"\n")
    return process


def test_clip_retries_connect_failures_then_records(tmp_path):
    processes = iter([_failed_process("connect"), _failed_process("connect"), _two_lens_process()])
    slept, status = [], io.StringIO()
    result = direct_cli.record_clip(lambda: next(processes), tmp_path / "clip.mp4", 60, clock=Clock(),
                                    sleep=slept.append, status=status)
    assert result["saved"] and slept == list(direct_cli.CONNECT_RETRY_SECONDS)
    assert status.getvalue().count("retrying in") == 2


def test_clip_does_not_retry_authentication_failures(tmp_path):
    starts = []

    def start():
        starts.append(1)
        return _failed_process("authentication")

    with pytest.raises(direct_cli.CliError, match="did not accept the login"):
        direct_cli.record_clip(start, tmp_path / "clip.mp4", 5, clock=Clock(), sleep=pytest.fail,
                               status=io.StringIO())
    assert len(starts) == 1


def test_clip_gives_up_after_the_last_connect_retry(tmp_path):
    starts = []

    def start():
        starts.append(1)
        return _failed_process("connect")

    with pytest.raises(direct_cli.CliError, match="could not be reached"):
        direct_cli.record_clip(start, tmp_path / "clip.mp4", 5, clock=Clock(), sleep=lambda _: None,
                               status=io.StringIO())
    assert len(starts) == len(direct_cli.CONNECT_RETRY_SECONDS) + 1


def test_waking_reports_cameras_without_low_power_wake(tmp_path):
    from okam_native.wakeup import WakeError
    source = tmp_path / "device_wakeup_server.dart"
    source.write_text("secretKey = 's';\ndata['AccessKey'] = 'a';\n")

    async def unregistered(*_args, **_kwargs):
        raise WakeError("camera was not registered with the official wake service")

    device = AccountDevice(uid="VPCAM1", name="Parking", device_password="", security=SECURITY)
    status = io.StringIO()
    assert direct_cli.waking(lambda: "p", device, status=status, source=lambda: source,
                             waker=unregistered)() == "p"
    assert "not a low-power model" in status.getvalue()
