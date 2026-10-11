"""Unit coverage for the multi-camera alias rules in the app entrypoint."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from okam_native.account import AccountDevice
from okam_native.p2p import P2PError


ROOT = Path(__file__).parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "okam_app_entrypoint", ROOT / "okam_native_app" / "app_entrypoint.py"
)
assert _SPEC is not None and _SPEC.loader is not None
entrypoint = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(entrypoint)


@pytest.fixture(autouse=True)
def isolated_alias_state(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(entrypoint, "ALIASES_FILE", tmp_path / "camera_aliases.json")
    monkeypatch.setattr(entrypoint, "LENSES_FILE", tmp_path / "camera_lenses.json")
    monkeypatch.delenv("SUPERVISOR_TOKEN", raising=False)

def _device(uid: str, name: str) -> AccountDevice:
    return AccountDevice(uid=uid, name=name, device_password="")


def test_camera_alias_is_home_assistant_safe() -> None:
    assert entrypoint._camera_alias("Front Gate") == "front-gate"
    assert entrypoint._camera_alias("  Cabin  ") == "cabin"
    assert entrypoint._camera_alias("Barn #2") == "barn-2"
    assert entrypoint._camera_alias("") == "camera"
    assert len(entrypoint._camera_alias("x" * 80)) == 32


def test_camera_aliases_are_unique_and_keep_account_order(monkeypatch) -> None:
    monkeypatch.setattr(entrypoint, "load_options", lambda: {})
    devices = [
        _device("u1", "Front Gate"),
        _device("u2", "Front Gate"),
        _device("u3", "Barn"),
    ]
    assert entrypoint.camera_aliases(devices) == [
        "front-gate",
        "front-gate-2",
        "barn",
    ]


def test_lone_camera_keeps_the_configured_alias(monkeypatch) -> None:
    # Backwards compatibility: an existing single-camera install must not have
    # its entity identifier change underneath it.
    monkeypatch.setattr(entrypoint, "load_options", lambda: {"camera_id": "cabin"})
    assert entrypoint.camera_aliases([_device("u1", "Front Gate")]) == ["cabin"]


def test_multiple_cameras_ignore_the_lone_configured_alias(monkeypatch) -> None:
    # The single camera_id option cannot name more than one camera, so derived
    # aliases take over.
    monkeypatch.setattr(entrypoint, "load_options", lambda: {"camera_id": "cabin"})
    devices = [_device("u1", "Front Gate"), _device("u2", "Barn")]
    assert entrypoint.camera_aliases(devices) == ["front-gate", "barn"]


def test_camera_aliases_survive_reorder_and_rename(monkeypatch) -> None:
    monkeypatch.setattr(entrypoint, "load_options", lambda: {})
    assert entrypoint.camera_aliases([_device("u1", "Parking"), _device("u2", "Gate")]) == [
        "parking", "gate"
    ]
    assert entrypoint.camera_aliases([_device("u2", "Main Gate"), _device("u1", "Lot")]) == [
        "gate", "parking"
    ]


@pytest.fixture(autouse=True)
def isolated_status(monkeypatch) -> None:
    monkeypatch.setattr(entrypoint, "STATUS", dict(entrypoint.STATUS))


def _configure(monkeypatch, failing: set[str], *, returns_none: bool = False):
    configured: list[str] = []

    def accept(device: AccountDevice) -> None:
        if device.uid in failing:
            raise P2PError("camera device identifier is invalid")

    def configure(device: AccountDevice, alias: str):
        configured.append(alias)
        return None if returns_none else object()

    monkeypatch.setattr(entrypoint, "load_options", lambda: {})
    monkeypatch.setattr(entrypoint, "run_p2p_acceptance", accept)
    monkeypatch.setattr(entrypoint, "configure_bridge", configure)
    return configured


def test_failing_first_camera_still_configures_the_healthy_one(monkeypatch) -> None:
    devices = [_device("u1", "Parking"), _device("u2", "Main Gate")]
    configured = _configure(monkeypatch, {"u1"})

    ready, failed = entrypoint.configure_cameras(devices)

    assert (ready, failed) == (1, 1)
    assert configured == ["main-gate"]
    assert entrypoint.STATUS["camera_ready_count"] == 1
    assert entrypoint.STATUS["camera_failed_count"] == 1


def test_failing_second_camera_preserves_the_healthy_first(monkeypatch) -> None:
    devices = [_device("u1", "Parking"), _device("u2", "Main Gate")]
    configured = _configure(monkeypatch, {"u2"})

    ready, failed = entrypoint.configure_cameras(devices)

    assert (ready, failed) == (1, 1)
    assert configured == ["parking"]


def test_all_cameras_failing_reports_nothing_ready(monkeypatch) -> None:
    devices = [_device("u1", "Parking"), _device("u2", "Main Gate")]
    configured = _configure(monkeypatch, {"u1", "u2"})

    ready, failed = entrypoint.configure_cameras(devices)

    assert (ready, failed) == (0, 2)
    assert configured == []
    assert entrypoint.STATUS["camera_ready"] is False
    assert entrypoint.STATUS["phase"] == "no_camera_ready"


def test_missing_api_token_keeps_configuration_semantics(monkeypatch) -> None:
    devices = [_device("u1", "Parking")]
    configured = _configure(monkeypatch, set(), returns_none=True)
    entrypoint.set_status(configuration_required=True, phase="api_token_required")

    ready, failed = entrypoint.configure_cameras(devices)

    assert (ready, failed) == (0, 1)
    assert configured == ["parking"]
    assert entrypoint.STATUS["phase"] == "api_token_required"


def test_programming_errors_are_not_swallowed(monkeypatch) -> None:
    devices = [_device("u1", "Parking")]

    def accept(_device: AccountDevice) -> None:
        raise RuntimeError("camera alias is invalid")

    monkeypatch.setattr(entrypoint, "load_options", lambda: {})
    monkeypatch.setattr(entrypoint, "run_p2p_acceptance", accept)

    with pytest.raises(RuntimeError):
        entrypoint.configure_cameras(devices)


def test_shared_configuration_failure_stays_global(monkeypatch) -> None:
    devices = [_device("u1", "Parking"), _device("u2", "Main Gate")]

    def aliases(_devices):
        raise RuntimeError("camera alias state is invalid")

    monkeypatch.setattr(entrypoint, "camera_aliases", aliases)

    with pytest.raises(RuntimeError):
        entrypoint.configure_cameras(devices)


def test_configure_bridge_p2p_failure_is_contained(monkeypatch) -> None:
    devices = [_device("u1", "Parking"), _device("u2", "Main Gate")]

    def configure(device: AccountDevice, _alias: str):
        if device.uid == "u1":
            raise P2PError("official P2P directory rejected a request")
        return object()

    monkeypatch.setattr(entrypoint, "load_options", lambda: {})
    monkeypatch.setattr(entrypoint, "run_p2p_acceptance", lambda _device: None)
    monkeypatch.setattr(entrypoint, "configure_bridge", configure)

    ready, failed = entrypoint.configure_cameras(devices)

    assert (ready, failed) == (1, 1)
    assert entrypoint.STATUS["phase"] == "bridge_ready"


def test_healthy_then_failing_acceptance_restores_ready_phase(monkeypatch) -> None:
    devices = [_device("u1", "Parking"), _device("u2", "Main Gate")]

    def accept(device: AccountDevice) -> None:
        if device.uid == "u2":
            # A failing camera leaves the global phase mid-connect.
            entrypoint.set_status(phase="connecting_p2p")
            raise P2PError("camera did not establish a native P2P session")

    monkeypatch.setattr(entrypoint, "load_options", lambda: {})
    monkeypatch.setattr(entrypoint, "run_p2p_acceptance", accept)
    monkeypatch.setattr(entrypoint, "configure_bridge", lambda _device, _alias: object())

    ready, failed = entrypoint.configure_cameras(devices)

    assert (ready, failed) == (1, 1)
    assert entrypoint.STATUS["phase"] == "bridge_ready"


def test_invalid_shared_camera_password_fails_globally(monkeypatch) -> None:
    devices = [_device("u1", "Parking"), _device("u2", "Main Gate")]
    monkeypatch.setattr(entrypoint, "load_options", lambda: {"camera_password": 12345})
    monkeypatch.setattr(entrypoint, "run_p2p_acceptance", lambda _device: None)
    monkeypatch.setattr(entrypoint, "configure_bridge", lambda _device, _alias: object())

    with pytest.raises(P2PError):
        entrypoint.configure_cameras(devices)


VP_SECURITY = "0123456789abcdef0123456789abcdef"


def _vp_device(uid: str = "VP1", name: str = "Parking") -> AccountDevice:
    return AccountDevice(uid=uid, name=name, device_password="", security=VP_SECURITY)


def test_vp_cameras_skip_the_cs2_acceptance_probes(monkeypatch) -> None:
    accepted: list[str] = []
    monkeypatch.setattr(entrypoint, "load_options", lambda: {})
    monkeypatch.setattr(entrypoint, "run_p2p_acceptance", lambda device: accepted.append(device.uid))
    monkeypatch.setattr(entrypoint, "configure_bridge", lambda _device, _alias: object())
    assert entrypoint.configure_cameras([_vp_device(), _device("CS1", "Gate")]) == (2, 0)
    assert accepted == ["CS1"]


def _vp_bridge_environment(monkeypatch, options: dict[str, object]) -> dict[str, object]:
    calls: dict[str, object] = {}
    monkeypatch.setattr(entrypoint, "load_options", lambda: options)
    monkeypatch.setattr(entrypoint, "BRIDGES", {})
    monkeypatch.setattr(entrypoint, "ACCOUNT_SESSION", {"user_id": "123456789", "token": "tok"})
    monkeypatch.setattr(entrypoint, "load_wake_credentials", lambda _path: object())
    monkeypatch.setattr(entrypoint, "resolve_client_id",
                        lambda _uid: (_ for _ in ()).throw(AssertionError("CS2 resolver used")))

    class Resolution:
        def native_connection_input(self) -> str:
            return "connection"

    monkeypatch.setattr(entrypoint, "resolve_vp_device", lambda _uid: Resolution())

    class Inputs:
        def worker_config(self, **extra: object) -> dict[str, object]:
            return {"private": True, **extra}

    def build(**kwargs):
        calls["build"] = kwargs
        return Inputs()

    monkeypatch.setattr(entrypoint, "build_worker_inputs", build)
    monkeypatch.setattr(entrypoint, "open_vp_stream_process",
                        lambda config, environment: calls.setdefault("worker", config))
    return calls


def test_vp_camera_bridge_uses_the_vp_worker(monkeypatch) -> None:
    calls = _vp_bridge_environment(monkeypatch, {"api_token": "x" * 16, "vp_password_salt": "salt"})
    bridge = entrypoint.configure_bridge(_vp_device(), "parking")
    assert bridge is not None
    build = calls["build"]
    assert build["connection"] == "connection" and build["user_id"] == "123456789"
    assert build["token"] == "tok" and build["security"] == VP_SECURITY
    assert build["password_salt"] == "salt"
    async def wake(*_args, **_kwargs):
        raise entrypoint.WakeError("unreachable")  # wake failures are tolerated

    monkeypatch.setattr(entrypoint, "wake_camera", wake)
    bridge.session._starter()
    # Framed output lets the session serve every lens from one connection.
    assert calls["worker"] == {"private": True, "framed": True}
    assert bridge.session.framed is True


def test_vp_camera_without_salt_fails_contained(monkeypatch) -> None:
    _vp_bridge_environment(monkeypatch, {"api_token": "x" * 16})
    with pytest.raises(P2PError, match="salt is not configured"):
        entrypoint.configure_bridge(_vp_device(), "parking")
    assert entrypoint.STATUS["configuration_required"] is True


def test_blank_api_token_is_generated_once_and_persisted(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(entrypoint, "TOKEN_FILE", tmp_path / "api_token")

    first = entrypoint.resolve_api_token({})
    second = entrypoint.resolve_api_token({"api_token": ""})

    assert first is not None and len(first) >= 32
    assert second == first
    assert (tmp_path / "api_token").read_text(encoding="utf-8") == first


def test_configured_api_token_overrides_and_short_one_is_rejected(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(entrypoint, "TOKEN_FILE", tmp_path / "api_token")

    assert entrypoint.resolve_api_token({"api_token": "y" * 16}) == "y" * 16
    assert entrypoint.resolve_api_token({"api_token": "short"}) is None
    assert not (tmp_path / "api_token").exists()


def test_discovery_announces_host_port_and_token(monkeypatch) -> None:
    calls: list[tuple[str, object]] = []

    def fake_request(path, payload=None):
        calls.append((path, payload))
        return {"hostname": "local-okam-native"} if payload is None else {}

    monkeypatch.setenv("SUPERVISOR_TOKEN", "supervisor")
    monkeypatch.setattr(entrypoint, "_supervisor_request", fake_request)

    assert entrypoint.publish_discovery("t" * 32) is True
    assert calls[-1] == (
        "/discovery",
        {
            "service": "okam",
            "config": {"host": "local-okam-native", "port": 8099, "api_token": "t" * 32},
        },
    )


def test_discovery_is_skipped_outside_supervisor_and_failures_are_contained(monkeypatch) -> None:
    monkeypatch.delenv("SUPERVISOR_TOKEN", raising=False)
    assert entrypoint.publish_discovery("t" * 32) is False

    def failing(path, payload=None):
        raise OSError("unreachable")

    monkeypatch.setenv("SUPERVISOR_TOKEN", "supervisor")
    monkeypatch.setattr(entrypoint, "_supervisor_request", failing)
    assert entrypoint.publish_discovery("t" * 32) is False


def test_missing_account_details_are_named_without_values(monkeypatch, capsys) -> None:
    notices: list[str | None] = []
    monkeypatch.setattr(entrypoint, "load_options", lambda: {"account_username": "user@example.invalid"})
    monkeypatch.setattr(entrypoint, "notify", notices.append)

    assert entrypoint.enumerate_account() is None

    output = capsys.readouterr().out
    assert "configuration_required=account_password " in output
    assert "example.invalid" not in output
    assert entrypoint.STATUS["phase"] == "account_required"
    assert entrypoint.STATUS["missing_options"] == ["account_password"]
    assert notices and "O-KAM account password" in notices[0]
    assert "example.invalid" not in notices[0]


def test_missing_salt_keeps_its_configuration_phase(monkeypatch) -> None:
    monkeypatch.setattr(entrypoint, "notify", lambda _message: None)
    devices = [_device("u1", "Parking")]

    def fail(_device, _alias):
        entrypoint.report_missing(["vp_password_salt"], "vp_password_salt_required")
        raise P2PError("VP camera password salt is not configured")

    monkeypatch.setattr(entrypoint, "load_options", lambda: {})
    monkeypatch.setattr(entrypoint, "is_vp_device", lambda _device: True)
    monkeypatch.setattr(entrypoint, "configure_bridge", fail)

    assert entrypoint.configure_cameras(devices) == (0, 1)
    assert entrypoint.STATUS["phase"] == "vp_password_salt_required"


def test_generated_token_is_written_into_the_app_options(monkeypatch, tmp_path: Path) -> None:
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(entrypoint, "TOKEN_FILE", tmp_path / "api_token")
    monkeypatch.setenv("SUPERVISOR_TOKEN", "supervisor")
    monkeypatch.setattr(
        entrypoint, "_supervisor_request", lambda path, payload=None: calls.append((path, payload)) or {}
    )

    token = entrypoint.resolve_api_token({"account_username": "kept", "api_token": ""})

    assert calls == [
        ("/addons/self/options", {"options": {"account_username": "kept", "api_token": token}})
    ]


def test_lens_counts_persist_and_ignore_invalid_entries(tmp_path: Path) -> None:
    entrypoint.save_lens_count("parking", 2)
    assert entrypoint.load_lens_counts() == {"parking": 2}
    entrypoint.LENSES_FILE.write_text('{"parking": 2, "bad": 9, "worse": "2"}', encoding="utf-8")
    assert entrypoint.load_lens_counts() == {"parking": 2}


def test_vp_password_key_is_found_in_the_client_once_then_saved(monkeypatch, tmp_path: Path) -> None:
    from test_vp_credentials import SALT, _fake_client, encrypt_password

    monkeypatch.setattr(entrypoint, "SALT_FILE", tmp_path / "vp_password_salt")
    monkeypatch.setattr(entrypoint, "CLIENT_DIR", tmp_path)
    records = [(encrypt_password(b"Abc123def456ghi", "123456789"), "123456789")]

    assert entrypoint.resolve_vp_password_salt({}, records) is None

    (tmp_path / "SuperIPCam.exe").write_bytes(_fake_client(SALT))
    assert entrypoint.resolve_vp_password_salt({}, records) == SALT
    assert (tmp_path / "vp_password_salt").read_text(encoding="ascii") == SALT

    # The saved key is reused without the client, and an explicit option wins.
    (tmp_path / "SuperIPCam.exe").unlink()
    assert entrypoint.resolve_vp_password_salt({}, records) == SALT
    assert entrypoint.resolve_vp_password_salt({"vp_password_salt": "manual"}, records) == "manual"


def test_an_existing_generated_token_is_also_shown_in_the_options(monkeypatch, tmp_path: Path) -> None:
    calls: list[str] = []
    (tmp_path / "api_token").write_text("s" * 40, encoding="utf-8")
    monkeypatch.setattr(entrypoint, "TOKEN_FILE", tmp_path / "api_token")
    monkeypatch.setattr(entrypoint, "store_token_in_options", lambda _options, token: calls.append(token))

    assert entrypoint.resolve_api_token({}) == "s" * 40
    assert calls == ["s" * 40]


def test_guest_tokens_are_generated_saved_and_named_only(monkeypatch, capsys) -> None:
    saved: list[object] = []
    monkeypatch.setenv("SUPERVISOR_TOKEN", "supervisor")
    monkeypatch.setattr(entrypoint, "_OPTION_CHANGES", {})
    monkeypatch.setattr(
        entrypoint, "_supervisor_request", lambda path, payload=None: saved.append(payload) or {}
    )
    options = {
        "api_token": "m" * 32,
        "guest_tokens": [
            {"name": "friend"},
            {"name": "kept", "token": "k" * 32},
            {"name": "bad name!"},
            {"name": "kept", "token": "d" * 32},
            {"name": "short", "token": "tiny"},
        ],
    }

    tokens = entrypoint.resolve_guest_tokens(options)

    assert set(tokens) == {"friend", "kept"} and tokens["kept"] == "k" * 32
    assert len(tokens["friend"]) >= 32
    written = saved[-1]["options"]
    assert written["api_token"] == "m" * 32
    assert {"name": "friend", "token": tokens["friend"]} in written["guest_tokens"]
    output = capsys.readouterr().out
    assert "guest_tokens_active=friend,kept" in output
    assert tokens["friend"] not in output and "k" * 32 not in output


def test_lone_camera_alias_survives_adding_a_second_camera(monkeypatch) -> None:
    monkeypatch.setattr(entrypoint, "load_options", lambda: {"camera_id": "cabin"})
    assert entrypoint.camera_aliases([_device("u1", "Front Door")]) == ["cabin"]
    two = entrypoint.camera_aliases([_device("u1", "Front Door"), _device("u2", "Barn")])
    assert two == ["cabin", "barn"]
    assert entrypoint.camera_aliases([_device("u1", "Front Door")]) == ["cabin"]


def test_tokens_must_be_printable_ascii() -> None:
    assert entrypoint._valid_token("a" * 32)
    assert not entrypoint._valid_token("a" * 31 + "é")
    assert not entrypoint._valid_token("a" * 16 + " " + "b" * 16)


def test_lone_camera_never_takes_another_cameras_alias(monkeypatch) -> None:
    monkeypatch.setattr(entrypoint, "load_options", lambda: {"camera_id": "cabin"})
    assert entrypoint.camera_aliases([_device("a", "Front"), _device("b", "Barn")]) == ["front", "barn"]
    entrypoint.camera_aliases([_device("a", "Front")])  # A alone: keeps "front"
    assert entrypoint.camera_aliases([_device("b", "Barn")]) == ["barn"]
    assert entrypoint.camera_aliases([_device("a", "Front"), _device("b", "Barn")]) == ["front", "barn"]


def test_camera_password_override_skips_the_vp_key(monkeypatch) -> None:
    calls = _vp_bridge_environment(monkeypatch, {"api_token": "x" * 16, "camera_password": "ChangedOnCamera1"})
    monkeypatch.setattr(entrypoint, "resolve_vp_password_salt", lambda *_: pytest.fail("key not needed"))
    bridge = entrypoint.configure_bridge(_vp_device(), "parking")
    assert bridge is not None
    assert calls["build"]["password_override"] == "ChangedOnCamera1"
