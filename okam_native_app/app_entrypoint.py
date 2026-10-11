#!/usr/bin/env python3
"""Run the native O-KAM bridge for the current Home Assistant architecture."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import re
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

from okam_native.account import AccountDevice, AccountError, Eye4AccountClient
from okam_native.bridge import CameraBridge, QuietThreadingHTTPServer, make_handler
from okam_native.p2p import (
    P2PError,
    diagnostic_line,
    get_service_parameter,
    is_vp_account_record,
    open_stream_process,
    resolve_client_id,
    resolve_vp_device,
    run_authentication_probe,
    run_connect_probe,
    run_snapshot_probe,
    run_stream_probe,
    select_camera_password,
)
from okam_native.session import NativeStreamSession
from okam_native.vp_credentials import (
    build_worker_inputs,
    decrypt_camera_password,
    select_password_salt,
)
from okam_native.vp_helper import open_stream_process as open_vp_stream_process
from okam_native.wakeup import WakeError, load_wake_credentials, wake_camera


DATA = Path("/data")
VENDOR = DATA / "vendor"
RUNTIME_ARCH = os.environ.get("OKAM_RUNTIME_ARCH", platform.machine()).lower()
if RUNTIME_ARCH in {"x86_64", "x64"}:
    RUNTIME_ARCH = "amd64"
elif RUNTIME_ARCH in {"arm64", "armv8"}:
    RUNTIME_ARCH = "aarch64"
PROBE = Path("/opt/okam/okam-hybris-probe")
CONNECT_HELPER = Path(
    "/opt/okam/okam-amd64-connect"
    if RUNTIME_ARCH == "amd64"
    else "/opt/okam/okam-hybris-connect"
)
FFMPEG = Path("/usr/bin/ffmpeg")
LIBRARY = Path("/dev/null") if RUNTIME_ARCH == "amd64" else VENDOR / "libOKSMARTPPCS.so"
# VP records that carry a checksum need a salt from the SDK library, selected
# by validating the record. It is present on aarch64; observed records omit it.
SDK_LIBRARY = VENDOR / "libOKSMARTPPCS.so"
STATUS: dict[str, object] = {
    "service": "okam-native-bridge",
    "loader_ready": False,
    "account_ready": False,
    "p2p_ready": False,
    "camera_ready": False,
    "connect_test_enabled": False,
    "auth_test_enabled": False,
    "camera_authenticated": False,
    "stream_test_enabled": False,
    "h264_ready": False,
    "snapshot_test_enabled": False,
    "snapshot_ready": False,
    "configuration_required": True,
    "phase": "starting",
}
LOCK = threading.Lock()
BRIDGES: dict[str, CameraBridge] = {}
# The account identifier and login token from enumeration, used only to
# authenticate VP camera channels. Never logged or exposed by status.
ACCOUNT_SESSION: dict[str, str | None] = {}
ALIASES_FILE = DATA / "camera_aliases.json"
# Lens counts learned from framed streams, so every lens of a multi-lens
# camera is offered again after a restart without waking the camera first.
LENSES_FILE = DATA / "camera_lenses.json"
CONFIGURATION_NOTICE = "okam_native_configuration"
# The VP camera-password key: found once by scanning the official PC client
# the user places in the app's config folder, then kept privately here.
SALT_FILE = DATA / "vp_password_salt"
CLIENT_DIR = Path("/config")
CLIENT_NAME = "superipcam.exe"
# Missing-setting phases are shared configuration states, not camera failures.
CONFIGURATION_PHASES = {"api_token_required", "account_required", "vp_password_salt_required"}
# Generated when the api_token option is blank, so first-time users never have
# to invent a secret; the integration receives it through Supervisor discovery.
TOKEN_FILE = DATA / "api_token"
SUPERVISOR = "http://supervisor"
BRIDGE_PORT = 8099


def set_status(**values: object) -> None:
    with LOCK:
        STATUS.update(values)


def get_status() -> dict[str, object]:
    with LOCK:
        payload = dict(STATUS)
        bridges = dict(BRIDGES)
    payload["camera_count"] = len(bridges)
    if bridges:
        active = next(
            (item for item in bridges.values() if item.session.status().running),
            None,
        )
        bridge = active or next(iter(bridges.values()))
        session = bridge.session.status()
        payload.update(
            stream_running=session.running,
            stream_viewers=session.viewers,
            stream_media_ready=session.media_ready,
            idle_timeout_seconds=int(bridge.session.idle_timeout),
            clean_disconnect=session.clean_disconnect,
            stream_error=session.last_error,
            phase=(
                "streaming"
                if session.running and session.media_ready
                else "camera_waking"
                if session.running
                else "bridge_ready"
            ),
        )
    return payload


def get_bridges() -> dict[str, CameraBridge]:
    with LOCK:
        return dict(BRIDGES)


def load_vendor_runtime() -> None:
    set_status(phase="fetching_vendor_sdk")
    VENDOR.mkdir(parents=True, exist_ok=True)
    required = [VENDOR / "device_wakeup_server.dart"]
    if RUNTIME_ARCH == "aarch64":
        required.extend((LIBRARY, VENDOR / "libvp_log.so"))
    if any(not path.exists() for path in required):
        command = [
            sys.executable,
            "/opt/okam/tools/fetch_official_sdk.py",
            "--destination",
            str(VENDOR),
        ]
        if RUNTIME_ARCH == "amd64":
            command.append("--wake-only")
        subprocess.run(
            command,
            check=True,
            timeout=180,
        )

    if RUNTIME_ARCH == "amd64":
        if not CONNECT_HELPER.is_file():
            raise RuntimeError("native amd64 P2P helper is unavailable")
        set_status(loader_ready=True, phase="native_loader_ready", runtime_arch=RUNTIME_ARCH)
        print("native_loader_ready=true", flush=True)
        return
    if RUNTIME_ARCH != "aarch64":
        raise RuntimeError("Home Assistant architecture is unsupported")

    environment = os.environ.copy()
    environment.update(
        {
            "LD_LIBRARY_PATH": "/opt/hybris/lib",
            "HYBRIS_LINKER_DIR": "/opt/hybris/lib/libhybris/linker",
            "HYBRIS_ANDROID_SDK_VERSION": "28",
            "HYBRIS_LD_LIBRARY_PATH": "/opt/android-stubs:/opt/bionic:/data/vendor",
        }
    )
    set_status(phase="loading_arm64_sdk")
    completed = subprocess.run(
        [str(PROBE), str(LIBRARY)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )
    result = json.loads(completed.stdout)
    if result.get("hybris_load") is not True or not all(result["symbols"].values()):
        raise RuntimeError("native loader did not satisfy every required symbol")
    set_status(loader_ready=True, phase="native_loader_ready", runtime_arch=RUNTIME_ARCH)
    print("native_loader_ready=true", flush=True)


def load_options() -> dict[str, object]:
    path = DATA / "options.json"
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise RuntimeError("Home Assistant app options are invalid") from None
    if not isinstance(value, dict):
        raise RuntimeError("Home Assistant app options are invalid")
    return value


def load_lens_counts() -> dict[str, int]:
    try:
        saved = json.loads(LENSES_FILE.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    if not isinstance(saved, dict):
        return {}
    return {
        alias: count
        for alias, count in saved.items()
        if isinstance(alias, str) and type(count) is int and 1 <= count <= 4
    }


_LENSES_LOCK = threading.Lock()


def save_lens_count(alias: str, count: int) -> None:
    # Camera pump threads report lenses concurrently; serialize the whole
    # read-modify-replace so one update cannot overwrite another.
    with _LENSES_LOCK:
        counts = load_lens_counts()
        if counts.get(alias) == count:
            return
        counts[alias] = count
        try:
            LENSES_FILE.parent.mkdir(parents=True, exist_ok=True)
            temporary = LENSES_FILE.with_suffix(".tmp")
            temporary.write_text(json.dumps(counts, sort_keys=True), encoding="utf-8")
            temporary.replace(LENSES_FILE)
        except OSError:
            return
    print(f"camera_lenses={count}", flush=True)


def _salt_decodes(salt: str, records: list[tuple[str, str]]) -> bool:
    try:
        for security, double_check in records:
            decrypt_camera_password(security, double_check, salt)
    except P2PError:
        return False
    return True


def find_client() -> Path | None:
    try:
        return next(
            (item for item in CLIENT_DIR.iterdir() if item.name.lower() == CLIENT_NAME),
            None,
        )
    except OSError:
        return None


def resolve_vp_password_salt(
    options: dict[str, object], records: list[tuple[str, str]]
) -> str | None:
    """The configured key, else the saved one, else one found in the client."""

    configured = options.get("vp_password_salt")
    if isinstance(configured, str) and configured:
        return configured
    try:
        saved = SALT_FILE.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        saved = ""
    if saved and _salt_decodes(saved, records):
        return saved
    client = find_client()
    if client is None:
        return None
    set_status(phase="finding_vp_password_key")
    print("vp_password_key_search=started", flush=True)
    try:
        salt = select_password_salt(client.read_bytes(), records)
    except (OSError, P2PError) as error:
        reason = "not_found" if isinstance(error, P2PError) else "unreadable"
        print(f"vp_password_key_search=failed reason={reason}", flush=True)
        return None
    partial = SALT_FILE.with_suffix(".tmp")
    descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(salt)
    os.replace(partial, SALT_FILE)
    print("vp_password_key_search=found", flush=True)
    return salt


GUEST_NAME = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def resolve_guest_tokens(options: dict[str, object]) -> dict[str, str]:
    """Named read-only tokens; blank ones are generated and shown in options.

    Each entry of the ``guest_tokens`` option names one person or program.
    Deleting an entry and restarting revokes it. Only names are logged.
    """

    entries = options.get("guest_tokens")
    if not isinstance(entries, list):
        return {}
    tokens: dict[str, str] = {}
    updated: list[object] = []
    generated: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        token = entry.get("token")
        if not isinstance(name, str) or not GUEST_NAME.fullmatch(name) or name in tokens:
            print("guest_token_ignored=true reason=invalid_or_duplicate_name", flush=True)
            continue
        if token in (None, ""):
            token = secrets.token_urlsafe(32)
            generated.append(name)
        if not _valid_token(token):
            print(f"guest_token_ignored=true name={name} reason=too_short", flush=True)
            continue
        tokens[name] = token
        updated.append({**entry, "token": token})
    if generated:
        print(f"guest_tokens_generated={','.join(generated)}", flush=True)
        if os.environ.get("SUPERVISOR_TOKEN"):
            try:
                save_options(options, {"guest_tokens": updated})
            except (OSError, ValueError, KeyError):
                print("guest_tokens_saved_to_configuration=false", flush=True)
    if tokens:
        print(f"guest_tokens_active={','.join(sorted(tokens))}", flush=True)
    return tokens


def _valid_token(value: object) -> bool:
    # Printable ASCII without spaces: tokens travel in headers and links.
    return (
        isinstance(value, str)
        and 16 <= len(value) <= 1024
        and all(33 <= ord(character) <= 126 for character in value)
    )


def resolve_api_token(options: dict[str, object]) -> str | None:
    """Return the configured token, or a persisted generated one when blank."""

    configured = options.get("api_token")
    if configured not in (None, ""):
        return configured if _valid_token(configured) else None
    try:
        stored = TOKEN_FILE.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        stored = ""
    if _valid_token(stored):
        # Tokens generated before the field was filled in are shown now too.
        store_token_in_options(options, stored)
        return stored
    token = secrets.token_urlsafe(32)
    partial = TOKEN_FILE.with_suffix(".tmp")
    descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(token)
    os.replace(partial, TOKEN_FILE)
    print("api_token_generated=true", flush=True)
    store_token_in_options(options, token)
    return token


# Changes this run has saved to the app options. Supervisor does not rewrite
# options.json until the next start, so each save re-applies earlier ones.
_OPTION_CHANGES: dict[str, object] = {}


def save_options(options: dict[str, object], changes: dict[str, object]) -> None:
    _OPTION_CHANGES.update(changes)
    _supervisor_request("/addons/self/options", {"options": {**options, **_OPTION_CHANGES}})


def store_token_in_options(options: dict[str, object], token: str) -> bool:
    """Show the generated token in the app's own Configuration tab.

    The option is a password field, so it stays masked and visible only to
    Home Assistant administrators; nothing is printed to the log.
    """

    if not os.environ.get("SUPERVISOR_TOKEN"):
        return False
    try:
        save_options(options, {"api_token": token})
    except (OSError, ValueError, KeyError):
        print("api_token_saved_to_configuration=false", flush=True)
        return False
    print("api_token_saved_to_configuration=true", flush=True)
    return True


def notify(message: str | None) -> None:
    """Show (or, with None, dismiss) the setup notice in Home Assistant."""

    if not os.environ.get("SUPERVISOR_TOKEN"):
        return
    service = "create" if message else "dismiss"
    payload: dict[str, object] = {"notification_id": CONFIGURATION_NOTICE}
    if message:
        payload.update(title="O-KAM Native Bridge needs setup", message=message)
    try:
        _supervisor_request(
            f"/core/api/services/persistent_notification/{service}", payload
        )
    except (OSError, ValueError, KeyError):
        pass


def report_missing(names: list[str], phase: str) -> None:
    """Name missing settings in the log, status and a notification, never values."""

    joined = ",".join(names)
    set_status(configuration_required=True, phase=phase, missing_options=names)
    print(
        f"configuration_required={joined} "
        "action=open_the_app_Configuration_tab_and_fill_these_in",
        flush=True,
    )
    labels = {
        "account_username": "O-KAM account email",
        "account_password": "O-KAM account password",
        "vp_password_salt": (
            "VP camera password key (or put the O-KAM PC client SuperIPCam.exe "
            "in the app's config folder so it is found automatically)"
        ),
    }
    readable = ", ".join(labels.get(name, name) for name in names)
    notify(
        f"Open **Settings → Apps → O-KAM Native Bridge → Configuration** and fill in: "
        f"{readable}. Then save and restart the app."
    )


def _supervisor_request(path: str, payload: dict[str, object] | None = None) -> dict:
    request = urllib.request.Request(
        SUPERVISOR + path,
        data=None if payload is None else json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {os.environ['SUPERVISOR_TOKEN']}",
            "Content-Type": "application/json",
        },
        method="GET" if payload is None else "POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        body = json.loads(response.read().decode("utf-8") or "{}")
    data = body.get("data") if isinstance(body, dict) else None
    return data if isinstance(data, dict) else {}


def publish_discovery(api_token: str) -> bool:
    """Announce the bridge so Home Assistant offers the integration itself."""

    if not os.environ.get("SUPERVISOR_TOKEN"):
        return False
    try:
        hostname = _supervisor_request("/addons/self/info").get("hostname")
        if not isinstance(hostname, str) or not hostname:
            hostname = socket.gethostname()
        _supervisor_request(
            "/discovery",
            {
                "service": "okam",
                "config": {"host": hostname, "port": BRIDGE_PORT, "api_token": api_token},
            },
        )
    except (OSError, ValueError, KeyError):
        print("discovery_published=false", flush=True)
        return False
    print("discovery_published=true", flush=True)
    return True


def enumerate_account() -> list[AccountDevice] | None:
    options = load_options()
    username = options.get("account_username")
    password = options.get("account_password")
    missing = [
        name
        for name, value in (("account_username", username), ("account_password", password))
        if not isinstance(value, str) or not value
    ]
    if missing:
        report_missing(missing, "account_required")
        return None
    set_status(phase="enumerating_account", configuration_required=False)
    client = Eye4AccountClient()
    try:
        devices = client.enumerate(username, password)
    finally:
        username = ""
        password = ""
    with LOCK:
        ACCOUNT_SESSION.update(user_id=client.user_id, token=client.login_token)
    if not devices:
        raise AccountError("O-KAM account exposes no cameras")
    set_status(
        account_ready=True,
        device_count=len(devices),
        phase="account_enumerated",
    )
    print(f"account_enumerated=true device_count={len(devices)}", flush=True)
    return devices


def _camera_alias(name: str) -> str:
    """A Home Assistant safe alias derived from a camera name."""

    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", name).strip("-").lower()
    return (slug or "camera")[:32]


def camera_aliases(devices: list[AccountDevice]) -> list[str]:
    """Keep aliases stable across account reorderings and camera renames.

    A lone camera keeps the configured alias so existing installations and
    their entity identifiers do not change. Multiple cameras derive aliases
    from the device names and are disambiguated on collision.
    """

    options = load_options()
    configured = options.get("camera_id")
    try:
        saved = json.loads(ALIASES_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        saved = {}
    if not isinstance(saved, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in saved.items()
    ):
        raise RuntimeError("camera alias state is invalid")
    if len(devices) == 1 and isinstance(configured, str) and configured:
        # Remember the lone camera's alias too, so adding a second camera
        # later does not rename it. An established mapping wins, and the
        # configured alias is never taken from another camera.
        key = hashlib.sha256(devices[0].uid.encode("utf-8")).hexdigest()
        if key in saved:
            return [saved[key]]
        if configured not in saved.values():
            saved[key] = configured
            _write_aliases(saved)
            return [configured]
    aliases: list[str] = []
    used: set[str] = set(saved.values())
    for device in devices:
        key = hashlib.sha256(device.uid.encode("utf-8")).hexdigest()
        if key in saved:
            aliases.append(saved[key])
            continue
        base = _camera_alias(device.name)
        alias = base
        suffix = 2
        while alias in used:
            alias = f"{base[:28]}-{suffix}"
            suffix += 1
        used.add(alias)
        saved[key] = alias
        aliases.append(alias)
    _write_aliases(saved)
    return aliases


def _write_aliases(saved: dict[str, str]) -> None:
    ALIASES_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = ALIASES_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(saved, sort_keys=True), encoding="utf-8")
    temporary.replace(ALIASES_FILE)


def p2p_environment() -> dict[str, str]:
    environment = os.environ.copy()
    if RUNTIME_ARCH == "amd64":
        return environment
    environment.update(
        {
            "LD_LIBRARY_PATH": "/opt/hybris/lib",
            "HYBRIS_LINKER_DIR": "/opt/hybris/lib/libhybris/linker",
            "HYBRIS_ANDROID_SDK_VERSION": "28",
            "HYBRIS_LD_LIBRARY_PATH": "/opt/android-stubs:/opt/bionic:/data/vendor",
        }
    )
    return environment


def run_p2p_acceptance(device: AccountDevice) -> None:
    options = load_options()
    enabled = options.get("run_connect_test") is True
    auth_enabled = options.get("run_auth_test") is True
    stream_enabled = options.get("run_stream_test") is True
    snapshot_enabled = options.get("run_snapshot_test") is True
    stream_enabled = stream_enabled or snapshot_enabled
    auth_enabled = auth_enabled or stream_enabled
    set_status(
        connect_test_enabled=enabled or auth_enabled,
        auth_test_enabled=auth_enabled,
        stream_test_enabled=stream_enabled,
        snapshot_test_enabled=snapshot_enabled,
    )
    if not enabled and not auth_enabled and not stream_enabled:
        return
    camera_password = select_camera_password(
        device.device_password, options.get("camera_password")
    )
    credentials = load_wake_credentials(VENDOR / "device_wakeup_server.dart")
    if credentials is None:
        raise WakeError("official wake configuration was unavailable")
    client_id = resolve_client_id(device.uid)
    service_parameter = get_service_parameter(client_id)
    wake_requested = False
    responsive_servers = 0
    last_state = -1
    for attempt in range(1, 4):
        set_status(phase="waking_camera", connect_attempt=attempt)
        try:
            wake = asyncio.run(wake_camera(device.uid, credentials, timeout=12.0))
            wake_requested = wake_requested or wake.requested
            responsive_servers = max(responsive_servers, wake.responsive_servers)
        except WakeError:
            pass
        set_status(
            wake_requested=wake_requested,
            wake_responsive_servers=responsive_servers,
            phase="connecting_p2p",
        )
        if snapshot_enabled:
            result = run_snapshot_probe(
                str(CONNECT_HELPER),
                str(LIBRARY),
                str(FFMPEG),
                client_id,
                service_parameter,
                camera_password,
                environment=p2p_environment(),
            )
        elif stream_enabled:
            result = run_stream_probe(
                str(CONNECT_HELPER),
                str(LIBRARY),
                client_id,
                service_parameter,
                camera_password,
                environment=p2p_environment(),
            )
        elif auth_enabled:
            result = run_authentication_probe(
                str(CONNECT_HELPER),
                str(LIBRARY),
                client_id,
                service_parameter,
                camera_password,
                environment=p2p_environment(),
            )
        else:
            result = run_connect_probe(
                str(CONNECT_HELPER),
                str(LIBRARY),
                client_id,
                service_parameter,
                environment=p2p_environment(),
            )
        last_state = result.connect_state
        if auth_enabled:
            set_status(
                connect_state=result.connect_state,
                login_sent=result.login_sent,
                login_response_received=result.login_response_received,
                login_result=result.login_result,
                clean_disconnect=result.disconnected,
            )
            if result.authenticated:
                set_status(p2p_ready=True, camera_authenticated=True)
            if not (result.connected and result.authenticated and result.disconnected):
                print(
                    "camera_authentication=false "
                    f"connect_state={result.connect_state} "
                    f"login_sent={str(result.login_sent).lower()} "
                    f"login_response_received={str(result.login_response_received).lower()} "
                    f"login_command={result.login_command} "
                    f"login_result={result.login_result} "
                    f"clean_disconnect={str(result.disconnected).lower()}",
                    flush=True,
                )
                print(diagnostic_line(result), flush=True)
        if stream_enabled:
            set_status(
                stream_start_sent=result.stream_start_sent,
                stream_stop_sent=result.stream_stop_sent,
                h264_frames=result.h264_frames,
                h264_bytes=result.h264_bytes,
                keyframe_seen=result.keyframe_seen,
                h265_frames=result.h265_frames,
            )
            if snapshot_enabled and result.h264_received and result.disconnected:
                set_status(
                    h264_ready=True,
                    snapshot_ready=True,
                    snapshot_bytes=len(result.jpeg),
                    snapshot_width=result.width,
                    snapshot_height=result.height,
                    phase="snapshot_created",
                    connect_attempt=attempt,
                )
                print(
                    f"snapshot_created=true width={result.width} "
                    f"height={result.height} bytes={len(result.jpeg)} "
                    "clean_disconnect=true",
                    flush=True,
                )
                return
            if not snapshot_enabled and result.h264_received and result.disconnected:
                set_status(
                    h264_ready=True,
                    phase="h264_received",
                    connect_attempt=attempt,
                )
                print(
                    f"h264_received=true frames={result.h264_frames} "
                    f"bytes={result.h264_bytes} clean_disconnect=true",
                    flush=True,
                )
                return
            print(
                "h264_received=false "
                f"stream_start_sent={str(result.stream_start_sent).lower()} "
                f"stream_stop_sent={str(result.stream_stop_sent).lower()} "
                f"frames={result.h264_frames} bytes={result.h264_bytes} "
                f"keyframe_seen={str(result.keyframe_seen).lower()} "
                f"h265_frames={result.h265_frames} "
                f"clean_disconnect={str(result.disconnected).lower()}",
                flush=True,
            )
            print(diagnostic_line(result), flush=True)
        if not stream_enabled and auth_enabled and result.connected and result.authenticated and result.disconnected:
            set_status(
                p2p_ready=True,
                camera_authenticated=True,
                phase="camera_authenticated",
                connect_attempt=attempt,
                login_command=result.login_command,
                login_result=result.login_result,
            )
            print("camera_authenticated=true clean_disconnect=true", flush=True)
            return
        if not auth_enabled and result.connected and result.disconnected:
            set_status(p2p_ready=True, phase="p2p_connected", connect_attempt=attempt)
            print("p2p_connected=true clean_disconnect=true", flush=True)
            return
        if attempt < 3:
            time.sleep(5)
    set_status(connect_state=last_state)
    raise P2PError("camera did not establish a native P2P session")


def is_vp_device(device: AccountDevice) -> bool:
    return is_vp_account_record(device_password=device.device_password, security=device.security)


def vp_stream_launcher(device: AccountDevice, options: dict[str, object]):
    """Derive the VP worker inputs once; the returned callable starts a worker."""

    with LOCK:
        user_id = ACCOUNT_SESSION.get("user_id")
        token = ACCOUNT_SESSION.get("token")
    if not isinstance(user_id, str) or not isinstance(token, str):
        raise P2PError("VP account session is unavailable")
    override = options.get("camera_password")
    override = override if isinstance(override, str) and override else None
    # A configured camera password makes decrypting the account's one, and
    # therefore the key, unnecessary.
    password_salt = "" if override else resolve_vp_password_salt(
        options, [(device.security or "", user_id)]
    )
    if password_salt is None:
        report_missing(["vp_password_salt"], "vp_password_salt_required")
        raise P2PError("VP camera password salt is not configured")
    connection = resolve_vp_device(device.uid).native_connection_input()
    try:
        library = SDK_LIBRARY.read_bytes() if SDK_LIBRARY.is_file() else b""
    except OSError:
        library = b""
    inputs = build_worker_inputs(
        connection=connection, user_id=user_id, token=token, security=device.security or "",
        password_salt=password_salt, library=library, password_override=override,
    )

    def launch() -> subprocess.Popen[bytes]:
        environment = os.environ.copy()
        # The worker runs as a module; the package sits beside this script.
        environment["PYTHONPATH"] = os.pathsep.join(
            item for item in (str(Path(__file__).resolve().parent), environment.get("PYTHONPATH")) if item
        )
        # Framed output carries every lens of a multi-lens camera in one
        # connection; the session splits it per lens.
        return open_vp_stream_process(
            inputs.worker_config(framed=True), environment=environment
        )

    return launch


_GUEST_TOKENS: dict[str, str] | None = None


def guest_tokens() -> dict[str, str]:
    # Resolved once per start, so tokens are generated and saved only once.
    global _GUEST_TOKENS
    if _GUEST_TOKENS is None:
        _GUEST_TOKENS = resolve_guest_tokens(load_options())
    return _GUEST_TOKENS


def configure_bridge(device: AccountDevice, alias: str) -> CameraBridge | None:
    """Prepare one long-lived, on-demand runtime without waking the camera."""

    options = load_options()
    api_token = resolve_api_token(options)
    idle_timeout = options.get("idle_timeout_seconds", 120)
    always_on = options.get("always_on", False)
    camera_password = select_camera_password(
        device.device_password, options.get("camera_password")
    )
    if api_token is None:
        set_status(configuration_required=True, camera_ready=False, phase="api_token_required")
        print("bridge_ready=false configuration_required=api_token", flush=True)
        return None
    if not isinstance(alias, str) or not alias:
        raise RuntimeError("camera alias is invalid")
    if not isinstance(idle_timeout, int) or not 10 <= idle_timeout <= 600:
        raise RuntimeError("idle timeout is invalid")
    if not isinstance(always_on, bool):
        raise RuntimeError("always-on option is invalid")
    credentials = load_wake_credentials(VENDOR / "device_wakeup_server.dart")
    if credentials is None:
        raise WakeError("official wake configuration was unavailable")
    if is_vp_device(device):
        launch = vp_stream_launcher(device, options)
    else:
        client_id = resolve_client_id(device.uid)
        service_parameter = get_service_parameter(client_id)

        def launch() -> subprocess.Popen[bytes]:
            return open_stream_process(
                str(CONNECT_HELPER),
                str(LIBRARY),
                client_id,
                service_parameter,
                camera_password,
                environment=p2p_environment(),
            )

    def start_stream() -> subprocess.Popen[bytes]:
        set_status(phase="waking_camera_on_demand")
        try:
            wake = asyncio.run(wake_camera(device.uid, credentials, timeout=12.0))
            set_status(
                wake_requested=wake.requested,
                wake_responsive_servers=wake.responsive_servers,
                phase="starting_native_stream",
            )
        except WakeError:
            set_status(phase="starting_native_stream")
        return launch()

    vp = is_vp_device(device)
    session = NativeStreamSession(
        start_stream,
        idle_timeout=float(idle_timeout),
        always_on=always_on,
        framed=vp,
        lenses=load_lens_counts().get(alias, 1) if vp else 1,
        on_lenses=lambda count: save_lens_count(alias, count),
    )
    bridge = CameraBridge(
        camera_id=alias,
        camera_name=device.name,
        api_token=api_token,
        session=session,
        ffmpeg=str(FFMPEG),
        guest_tokens=guest_tokens(),
    )
    with LOCK:
        BRIDGES[alias] = bridge
        camera_count = len(BRIDGES)
    set_status(
        camera_ready=True,
        configuration_required=False,
        phase="bridge_ready",
        idle_timeout_seconds=idle_timeout,
        always_on=always_on,
        camera_count=camera_count,
    )
    print(f"bridge_ready=true camera_count={camera_count}", flush=True)
    if always_on:
        # The first start wakes the camera; keep it off the configuration path
        # so one slow camera does not delay the others.
        threading.Thread(target=session.start_always_on, daemon=True).start()
    return bridge


def configure_cameras(devices: list[AccountDevice]) -> tuple[int, int]:
    """Configure each camera independently and report ready/failed counts.

    An expected per-camera failure (resolution, service lookup, acceptance) is
    contained to that camera so the remaining cameras still start. Account,
    loader, and shared-configuration failures are not caught here and stay
    global. Programming errors are deliberately not swallowed either.
    """

    options = load_options()
    # Validate the shared camera-password option once. An invalid global value
    # must fail globally rather than be swallowed as a per-camera error.
    configured_password = options.get("camera_password")
    if configured_password not in (None, ""):
        select_camera_password("", configured_password)

    aliases = camera_aliases(devices)
    ready = 0
    failed = 0
    for device, alias in zip(devices, aliases, strict=True):
        try:
            # The bounded acceptance probes exercise the CS2 transport only.
            if not is_vp_device(device):
                run_p2p_acceptance(device)
            bridge = configure_bridge(device, alias)
        except P2PError:
            failed += 1
            set_status(camera_failed_count=failed)
            print(
                f"camera_setup_failed=true reason=P2PError ready={ready} failed={failed}",
                flush=True,
            )
            continue
        if bridge is None:
            failed += 1
        else:
            ready += 1
    set_status(camera_ready_count=ready, camera_failed_count=failed)
    if ready > 0:
        # A later camera's acceptance failure can leave the phase mid-connect;
        # restore the ready phase so the global state matches reality.
        set_status(phase="bridge_ready")
    # A missing API token is a shared configuration state reported by
    # configure_bridge, not a camera failure, so it must not be overwritten.
    if ready == 0 and STATUS.get("phase") not in CONFIGURATION_PHASES:
        set_status(camera_ready=False, phase="no_camera_ready")
        print(f"no_camera_ready=true failed={failed}", flush=True)
    return ready, failed


def main() -> int:
    server = QuietThreadingHTTPServer(
        ("0.0.0.0", BRIDGE_PORT), make_handler(get_status, get_bridges)
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    stop = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        load_vendor_runtime()
        devices = enumerate_account()
        if devices is not None:
            ready, _failed = configure_cameras(devices)
            api_token = resolve_api_token(load_options())
            if ready > 0 and api_token is not None:
                notify(None)
                publish_discovery(api_token)
    except Exception as error:
        phase = "startup_error" if STATUS["loader_ready"] else "native_loader_error"
        detail = str(error).replace(" ", "_") if isinstance(error, P2PError) else None
        set_status(phase=phase, error=type(error).__name__, error_detail=detail)
        suffix = f" detail={detail}" if detail else ""
        print(f"startup_ready=false error={type(error).__name__}{suffix}", flush=True)
    stop.wait()
    for bridge in get_bridges().values():
        bridge.session.close()
    server.shutdown()
    server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
