import json
import struct
import subprocess
from urllib.parse import urlsplit

import pytest

from okam_native.p2p import (
    _jpeg_dimensions,
    _stream_result,
    ConnectResult,
    P2PError,
    VpResolution,
    decode_vp_service_parameter,
    diagnostic_line,
    get_service_parameter,
    is_vp_account_record,
    open_stream_process,
    resolve_camera_client_id,
    resolve_client_id,
    resolve_vp_device,
    run_authentication_probe,
    run_connect_probe,
    run_stream_probe,
    select_camera_password,
    valid_vp_security,
)


def test_service_parameter_uses_only_device_family() -> None:
    requests = []

    def opener(request, timeout: float) -> bytes:
        requests.append((request, timeout))
        return json.dumps(["A" * 32]).encode()

    value = get_service_parameter("ABCD-sensitive-device-id", opener=opener)

    assert value == "A" * 32
    assert urlsplit(requests[0][0].full_url).path == "/getInitstring"
    assert json.loads(requests[0][0].data) == {"uid": ["ABCD"]}
    assert b"sensitive-device-id" not in requests[0][0].data


def test_virtual_id_is_resolved_without_exposing_it() -> None:
    requests = []

    def opener(request, timeout: float) -> bytes:
        requests.append((request, timeout))
        return json.dumps({"uid": "ABCD123456789"}).encode()

    result = resolve_client_id("VUID1234567A", opener=opener)

    assert result == "ABCD123456789"
    assert urlsplit(requests[0][0].full_url).hostname == "vuid.eye4.cn"


def test_physical_id_does_not_call_virtual_resolver() -> None:
    def opener(_request, _timeout: float) -> bytes:
        raise AssertionError("resolver should not be called")

    assert resolve_client_id("ABCD123456789", opener=opener) == "ABCD123456789"


def test_connect_probe_passes_sensitive_fields_only_on_stdin(monkeypatch) -> None:
    recorded = {}

    def run(command, **kwargs):
        recorded["command"] = command
        recorded["input"] = kwargs["input"]
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=b'{"connected":true,"connect_state":3,"disconnected":true}\n',
            stderr=b"",
        )

    monkeypatch.setattr(subprocess, "run", run)
    result = run_connect_probe(
        "/helper",
        "/library",
        "sensitive-device-id",
        "sensitive-service-parameter",
        environment={"SAFE": "1"},
    )

    assert result.connected is True
    assert recorded["command"] == ["/helper", "/library"]
    assert b"sensitive-device-id" in recorded["input"]
    first_size = struct.unpack(">I", recorded["input"][:4])[0]
    assert first_size == len(b"sensitive-device-id")


def test_directory_errors_do_not_expose_identifier() -> None:
    def opener(_request, _timeout: float) -> bytes:
        raise OSError("failure containing ABCD-sensitive-device-id")

    with pytest.raises(P2PError) as caught:
        get_service_parameter("ABCD-sensitive-device-id", opener=opener)
    assert "sensitive-device-id" not in str(caught.value)


def test_camera_password_prefers_explicit_override() -> None:
    assert select_camera_password("account-value", "configured-value") == "configured-value"


def test_camera_password_uses_enumerated_value_when_available() -> None:
    assert select_camera_password("account-value") == "account-value"


def test_camera_password_uses_safe_default_when_account_omits_it() -> None:
    assert select_camera_password("") == "888888"
    assert select_camera_password(None, "") == "888888"


def test_camera_password_rejects_invalid_override_without_echoing_it() -> None:
    secret = "invalid\nsecret"
    with pytest.raises(P2PError) as caught:
        select_camera_password(None, secret)
    assert secret not in str(caught.value)


def test_authentication_probe_passes_all_sensitive_fields_only_on_stdin(monkeypatch) -> None:
    recorded = {}

    def run(command, **kwargs):
        recorded["command"] = command
        recorded["input"] = kwargs["input"]
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=(
                b'{"connected":true,"connect_state":3,"login_sent":true,'
                b'"login_response_received":true,"authenticated":true,'
                b'"login_command":24736,"login_result":0,"disconnected":true}\n'
            ),
            stderr=b"",
        )

    monkeypatch.setattr(subprocess, "run", run)
    result = run_authentication_probe(
        "/helper",
        "/library",
        "sensitive-device-id",
        "sensitive-service-parameter",
        "sensitive-device-password",
        environment={"SAFE": "1"},
    )

    assert result.authenticated is True
    assert result.login_result == 0
    assert recorded["command"] == ["/helper", "/library", "--authenticate"]
    assert b"sensitive-device-password" in recorded["input"]
    assert b"sensitive-device-password" not in b" ".join(
        value.encode() for value in recorded["command"]
    )


def test_stream_probe_returns_only_sanitized_metrics(monkeypatch) -> None:
    recorded = {}

    def run(command, **kwargs):
        recorded["command"] = command
        recorded["input"] = kwargs["input"]
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=(
                b'{"connected":true,"connect_state":3,"login_sent":true,'
                b'"login_response_received":true,"authenticated":true,'
                b'"login_command":24577,"login_result":0,'
                b'"stream_start_sent":true,"stream_stop_sent":true,'
                b'"h264_received":true,"h264_frames":4,"h264_bytes":8192,'
                b'"keyframe_seen":true,"h265_frames":0,"disconnected":true}\n'
            ),
            stderr=b"",
        )

    monkeypatch.setattr(subprocess, "run", run)
    result = run_stream_probe(
        "/helper",
        "/library",
        "sensitive-device-id",
        "sensitive-service-parameter",
        "sensitive-device-password",
        environment={"SAFE": "1"},
    )

    assert result.h264_received is True
    assert result.h264_frames == 4
    assert result.h264_bytes == 8192
    assert recorded["command"] == ["/helper", "/library", "--stream-test"]
    assert b"sensitive-device-password" in recorded["input"]
    assert b"sensitive-device-password" not in b" ".join(
        value.encode() for value in recorded["command"]
    )


def test_jpeg_dimensions_accepts_bounded_sof_header() -> None:
    jpeg = (
        b"\xff\xd8"
        b"\xff\xe0\x00\x04\x00\x00"
        b"\xff\xc0\x00\x11\x08\x01\xe0\x02\x80"
        b"\x03\x01\x11\x00\x02\x11\x00\x03\x11\x00"
        b"\xff\xd9"
    )

    assert _jpeg_dimensions(jpeg) == (640, 480)


def test_open_stream_process_keeps_sensitive_fields_out_of_argv(monkeypatch) -> None:
    recorded = {}

    class Input:
        def write(self, value):
            recorded["input"] = value

        def close(self):
            pass

    class Process:
        stdin = Input()
        stdout = object()
        stderr = object()

    def popen(command, **kwargs):
        recorded["command"] = command
        return Process()

    monkeypatch.setattr(subprocess, "Popen", popen)
    open_stream_process(
        "/helper",
        "/library",
        "sensitive-device-id",
        "sensitive-service-parameter",
        "sensitive-device-password",
        environment={"SAFE": "1"},
    )

    assert recorded["command"] == ["/helper", "/library", "--stream-stdout"]
    assert b"sensitive-device-password" in recorded["input"]
    assert "sensitive-device-password" not in " ".join(recorded["command"])


def _stream_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "connected": True,
        "connect_state": 3,
        "login_sent": True,
        "login_response_received": True,
        "authenticated": True,
        "login_command": 0x6001,
        "login_result": 0,
        "disconnected": True,
        "stream_start_sent": True,
        "stream_stop_sent": True,
        "h264_received": False,
        "h264_frames": 0,
        "h264_bytes": 0,
        "keyframe_seen": False,
        "h265_frames": 0,
    }
    payload.update(overrides)
    return payload


def test_stream_result_carries_transport_diagnostics() -> None:
    result = _stream_result(
        _stream_payload(
            connect_path="direct-punch",
            login_candidate=2,
            login_attempts=[-1, None, 0],
            stream_start_command=0x60D1,
            stream_start_result=0,
            counters={"channel0_bytes": 96, "channel1_bytes": 0},
        ),
        0,
    )

    assert result.connect_path == "direct-punch"
    assert result.login_candidate == 2
    assert result.login_attempts == (-1, None, 0)
    assert result.stream_start_result == 0
    assert result.counters == {"channel0_bytes": 96, "channel1_bytes": 0}


@pytest.mark.parametrize(
    "counters",
    [
        {"channel1_bytes": -1},
        {"channel1_bytes": "many"},
        {"channel1_bytes": True},
        [("channel1_bytes", 1)],
        {str(index): index for index in range(65)},
    ],
)
def test_malformed_counters_degrade_instead_of_failing_the_probe(counters: object) -> None:
    # Diagnostics explain a failure, so they must never cause one.
    result = _stream_result(_stream_payload(counters=counters), 0)

    assert result.counters == {}
    assert result.connected is True


def test_diagnostic_line_is_counts_only_and_survives_partial_results() -> None:
    connect_only = ConnectResult(
        connected=True,
        connect_state=3,
        disconnected=True,
        connect_path="relay",
        counters={"packets_from_other_source": 7, "channel1_bytes": 0},
    )

    line = diagnostic_line(connect_only)

    assert line.startswith("transport_diagnostics ")
    assert "connect_path=relay" in line
    assert "channel1_bytes=0 packets_from_other_source=7" in line
    assert "login_attempts=-" in line


def test_diagnostic_line_renders_silent_login_candidates() -> None:
    result = _stream_result(
        _stream_payload(login_attempts=[-1, None], counters={}), 0
    )

    assert "login_attempts=-1,none" in diagnostic_line(result)


# ---------------------------------------------------------------------------
# VP resolution seam (offline; wire validity and streaming are UNVERIFIED)
# ---------------------------------------------------------------------------

VP_DID = "AB" + "ABCD123456ABXYZ"        # 17 chars, last 15 CS2-shaped
VP_TRANSPORT_ID = "ABCD123456ABXYZ"      # 15 chars
VP_ADDRESS = "ABS-" + "C" * 160          # 164 chars, <2 chars>S-<160 chars>
VP_SECURITY = "S" * 32


def _vp_opener(body: object = None):
    requests = []

    def opener(request, timeout: float) -> bytes:
        requests.append(request)
        payload = {"did": VP_DID, "address": VP_ADDRESS} if body is None else body
        return json.dumps(payload).encode()

    return opener, requests


def test_vp_resolver_uses_the_newer_contract() -> None:
    opener, requests = _vp_opener()

    resolution = resolve_vp_device("VUID1234567A", opener=opener)

    assert isinstance(resolution, VpResolution)
    assert resolution.transport_id == VP_TRANSPORT_ID
    assert resolution.address == VP_ADDRESS
    assert resolution.native_identity == VP_DID
    assert VP_DID not in repr(resolution)
    assert VP_ADDRESS not in repr(resolution)
    parsed = urlsplit(requests[0].full_url)
    assert parsed.hostname == "vuid-vp.eye4.cn"
    assert parsed.path == "/vuid/query"
    assert parsed.query == "vuid=VUID1234567A"


def test_vp_native_input_preserves_full_identity_and_record():
    identity = "TEST12345678ABCDE"
    address = "DAS-" + "C" * 160
    opener, _ = _vp_opener({"did": identity, "address": address})
    resolution = resolve_vp_device("VUID1234567A", opener=opener)
    assert resolution.native_connection_input() == identity + "%%" + address


def test_vp_native_input_does_not_guess_missing_or_legacy_identity():
    for resolution in (VpResolution(VP_TRANSPORT_ID, VP_ADDRESS),
                       VpResolution(VP_TRANSPORT_ID, VP_ADDRESS, VP_DID)):
        with pytest.raises(P2PError, match="unavailable"):
            resolution.native_connection_input()


@pytest.mark.parametrize("body", [
    "not-a-dict",
    [],
    {},
    {"did": VP_DID},
    {"address": VP_ADDRESS},
    {"did": "SHORT", "address": VP_ADDRESS},
    {"did": "AB" + "ABCD123456ABXY1", "address": VP_ADDRESS},
    {"did": VP_DID, "address": VP_ADDRESS[:-1]},
    {"did": VP_DID, "address": VP_ADDRESS + "C"},
    {"did": VP_DID, "address": "ABC" + "C" * 161},
    {"did": VP_DID, "address": "ABS-" + "Z" * 160},
])
def test_vp_resolver_rejects_malformed_responses(body: object) -> None:
    opener, _requests = _vp_opener(body)

    with pytest.raises(P2PError):
        resolve_vp_device("VUID1234567A", opener=opener)


def test_vp_resolver_failures_never_echo_inputs() -> None:
    sentinel = "vp-sentinel.example.test"

    def raising(_request, _timeout: float) -> bytes:
        raise OSError("failure mentioning " + sentinel)

    with pytest.raises(P2PError) as caught:
        resolve_vp_device(sentinel, opener=raising)
    message = str(caught.value)
    assert sentinel not in message
    assert "example.test" not in message

    def malformed(_request, _timeout: float) -> bytes:
        return b"{not json"

    with pytest.raises(P2PError) as caught:
        resolve_vp_device(sentinel, opener=malformed)
    assert sentinel not in str(caught.value)


def test_decode_vp_service_parameter_accepts_hostnames_and_ipv4() -> None:
    servers, key = decode_vp_service_parameter("cam.example.com,10.0.0.1:candidate-key")

    assert servers == ("cam.example.com", "10.0.0.1")
    assert key == "candidate-key"


def test_decode_vp_service_parameter_accepts_the_upper_bounds() -> None:
    joined = ",".join(f"host{index}.example.com" for index in range(16))

    servers, key = decode_vp_service_parameter(joined + ":" + "k" * 128)

    assert len(servers) == 16
    assert key == "k" * 128
    assert decode_vp_service_parameter("camera:candidate-key") == (
        ("camera",),
        "candidate-key",
    )


@pytest.mark.parametrize("value", [
    123,
    "",
    "no-separator",
    ":key",
    "server:",
    "server:key:extra",
    "server:bad key",
    "server:" + "k" * 129,
    "1.2.3:key",
    "999.1.1.1:key",
    "01.2.3.4:key",
    "bad_host:key",
    "-bad.example:key",
    "a" * 254 + ":key",
    ",".join(["h"] * 17) + ":key",
    "x" * 5000 + ":key",
])
def test_decode_vp_service_parameter_rejects_malformed(value: object) -> None:
    with pytest.raises(P2PError):
        decode_vp_service_parameter(value)


def test_decode_vp_service_parameter_failures_never_echo_inputs() -> None:
    sentinel = "vp-sentinel.example.test"
    with pytest.raises(P2PError) as caught:
        decode_vp_service_parameter(sentinel)
    assert sentinel not in str(caught.value)


def test_valid_vp_security_enforces_the_documented_shape() -> None:
    assert valid_vp_security("S" * 32) is True
    for bad in (
        "S" * 31,
        "S" * 33,
        "S" * 31 + " ",
        "S" * 31 + "\n",
        "S" * 31 + "\u00e9",
        "",
        None,
        12345,
        True,
        ["S" * 32],
        {"value": "S" * 32},
    ):
        assert valid_vp_security(bad) is False, bad


@pytest.mark.parametrize("device_password,security,expected", [
    ("", VP_SECURITY, True),
    ("888888", VP_SECURITY, False),
    (None, VP_SECURITY, False),
    ("", None, False),
    ("", "S" * 31, False),
    ("", "S" * 33, False),
    ("", "S" * 31 + "\n", False),
    ("", "S" * 31 + " ", False),
])
def test_is_vp_account_record_matches_only_the_documented_shape(
    device_password: object, security: object, expected: bool
) -> None:
    assert is_vp_account_record(
        device_password=device_password, security=security
    ) is expected


def test_vp_router_selects_vp_for_documented_records_only() -> None:
    vp_hosts: list[str | None] = []

    def vp_opener(request, timeout: float) -> bytes:
        vp_hosts.append(urlsplit(request.full_url).hostname)
        return json.dumps({"did": VP_DID, "address": VP_ADDRESS}).encode()

    routed = resolve_camera_client_id(
        "VUID1234567A",
        device_password="",
        security=VP_SECURITY,
        opener=vp_opener,
    )
    assert routed == VP_TRANSPORT_ID
    assert vp_hosts == ["vuid-vp.eye4.cn"]

    legacy_hosts: list[str | None] = []

    def legacy_opener(request, timeout: float) -> bytes:
        legacy_hosts.append(urlsplit(request.full_url).hostname)
        return json.dumps({"uid": "ABCD123456789"}).encode()

    routed = resolve_camera_client_id(
        "VUID1234567A",
        device_password="888888",
        security=VP_SECURITY,
        opener=legacy_opener,
    )
    assert routed == "ABCD123456789"
    assert legacy_hosts == ["vuid.eye4.cn"]


def test_non_vp_resolution_is_unchanged_and_never_calls_the_vp_endpoint() -> None:
    def never(_request, _timeout: float) -> bytes:
        raise AssertionError("the resolver should not be called")

    # A physical identifier still short-circuits without any request.
    assert resolve_camera_client_id(
        "ABCD123456789",
        device_password="",
        security=None,
        opener=never,
    ) == "ABCD123456789"

    hosts: list[str | None] = []

    def legacy_opener(request, timeout: float) -> bytes:
        hosts.append(urlsplit(request.full_url).hostname)
        return json.dumps({"uid": "ABCD123456789"}).encode()

    assert resolve_client_id("VUID1234567A", opener=legacy_opener) == "ABCD123456789"
    assert hosts == ["vuid.eye4.cn"]
