"""Direct camera commands for the okam CLI, using the O-KAM account.

The account password is prompted unless the user saved it with ``okam login``
(Windows Credential Manager or the platform keyring through ``keyring``) or set
``OKAM_EMAIL``/``OKAM_PASSWORD``. It is never written to files or logs. Secrets
are printed only by the explicit ``cameras --show-secrets`` command.
"""
from __future__ import annotations

import asyncio
import getpass
import json
import os
import re
import queue
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import lens_clip
from .account import AccountDevice, Eye4AccountClient
from .lens_clip import ClipError, LensRecorder, lens_path
from .p2p import is_vp_account_record, resolve_vp_device
from .session import NativeStreamSession
from .vp_credentials import VPWorkerInputs, build_worker_inputs
from .vp import VPError
from .vp_helper import MAX_LENS, open_stream_process, read_lens_records
from .wakeup import WakeError, load_wake_credentials, wake_camera

PACKAGE_PARENT = str(Path(__file__).resolve().parents[1])
MAX_CLIP_SECONDS = 600
# The relay occasionally refuses connections for minutes; retry connect failures.
CONNECT_RETRY_SECONDS = (5, 15)
KEYRING_SERVICE = "okam-ha-native"
# Worker summary stages mapped to user-facing explanations; the summary itself
# has a fixed schema without private input.
STAGE_HINTS = {
    "configuration": "the worker rejected its inputs (check the VP password key file)",
    "connect": "the camera could not be reached through the relay "
               "(camera offline, or the vendor app or another session is connected)",
    "authentication": "the camera did not accept the login (code camera_password_rejected means a "
                      "wrong camera password; status_timeout means no reply)",
    "read_media": "the camera accepted the login but sent no video within 30 seconds",
    "validate_media": "the camera sent data that is not H.264",
}


class CliError(Exception):
    """A user-facing failure whose message never contains private input."""


def camera_alias(name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", name).strip("-").lower()
    return (slug or "camera")[:32]


def is_vp(device: AccountDevice) -> bool:
    return is_vp_account_record(device_password=device.device_password, security=device.security)


def _keyring():
    try:
        import keyring
    except ImportError:
        return None
    return keyring


def _saved(name: str, environ, store) -> str | None:
    value = environ.get("OKAM_" + name.upper())
    if value:
        return value
    store = _keyring() if store is None else store
    if not store:
        return None
    try:
        return store.get_password(KEYRING_SERVICE, name) or None
    except Exception:  # keyring backends raise backend-specific errors
        return None


def saved_credentials(*, environ=os.environ, store=None) -> tuple[str, str] | None:
    email = _saved("email", environ, store)
    password = _saved("password", environ, store) if email else None
    return (email, password) if email and password else None


def _prompt_password(secret_prompt) -> str:
    return secret_prompt("O-KAM account password (hidden: nothing appears as you type, "
                         "press Enter when done): ")


def login(email: str | None, *, client_factory=Eye4AccountClient, prompt=input,
          secret_prompt=getpass.getpass, status=None, saved=saved_credentials):
    status = status or sys.stderr
    credentials = None if email else saved()
    if credentials:
        email, password = credentials
        print("Using the saved O-KAM login.", file=status)
    else:
        email = email or prompt("O-KAM account email: ").strip()
        password = _prompt_password(secret_prompt)
    client = client_factory()
    print("Signing in to the O-KAM account...", file=status)
    try:
        devices = client.enumerate(email, password)
    finally:
        password = ""
    print(f"Signed in; {len(devices)} camera(s) on the account.", file=status)
    return client, devices


def save_login(email: str | None, salt_file: Path | None, *, client_factory=Eye4AccountClient,
               prompt=input, secret_prompt=getpass.getpass, store=None, status=None):
    """Verify the account login, then keep it in the platform keyring."""
    status = status or sys.stderr
    store = _keyring() if store is None else store
    if not store:
        raise CliError("saving needs the keyring package (uv pip install keyring)")
    email = email or prompt("O-KAM account email: ").strip()
    password = _prompt_password(secret_prompt)
    salt = _read_salt_file(salt_file) if salt_file is not None else None
    print("Checking the login before saving...", file=status)
    try:
        devices = client_factory().enumerate(email, password)
        try:
            store.set_password(KEYRING_SERVICE, "email", email)
            store.set_password(KEYRING_SERVICE, "password", password)
            if salt:
                store.set_password(KEYRING_SERVICE, "vp_password_salt", salt)
        except Exception:  # keyring backends raise backend-specific errors
            raise CliError("the system keyring refused to save the login") from None
    finally:
        password = ""
    return {"saved": True, "cameras": len(devices), "vp_password_key_saved": bool(salt)}


def forget_login(*, store=None) -> dict[str, object]:
    store = _keyring() if store is None else store
    removed = 0
    for name in ("email", "password", "vp_password_salt"):
        try:
            store.delete_password(KEYRING_SERVICE, name)
            removed += 1
        except Exception:  # missing entries and absent backends are both fine
            pass
    return {"removed": removed}


def find_camera(devices: list[AccountDevice], key: str) -> AccountDevice:
    matches = [d for d in devices if key in (d.name, camera_alias(d.name))]
    if len(matches) != 1:
        raise CliError("camera not found (use the name or alias from 'okam cameras')")
    return matches[0]


def _read_salt_file(path: Path) -> str:
    try:
        return path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        raise CliError("VP salt file could not be read") from None


def read_salt(path: Path | None, *, secret_prompt=getpass.getpass,
              saved=lambda: _saved("vp_password_salt", os.environ, None)) -> str:
    if path is not None:
        salt = _read_salt_file(path)
    else:
        salt = saved() or secret_prompt("VP camera password key (vp_password_salt): ").strip()
    if not salt:
        raise CliError("a VP camera password key is required")
    return salt


def vp_inputs(client, device: AccountDevice, salt: str, *, resolver=resolve_vp_device) -> VPWorkerInputs:
    if not is_vp(device):
        raise CliError("VP cameras only for now")
    return build_worker_inputs(
        connection=resolver(device.uid).native_connection_input(), user_id=client.user_id,
        token=client.login_token, security=device.security, password_salt=salt, library=b"")


def worker_starter(inputs: VPWorkerInputs, *, substream: int = 0, opener=open_stream_process,
                   **options: object):
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(
        item for item in (PACKAGE_PARENT, environment.get("PYTHONPATH")) if item)
    config = inputs.worker_config(substream=substream, **options)
    return lambda: opener(config, environment=environment)


def wake_source() -> Path | None:
    """The official SDK file holding the wake signing values, if present."""
    names = [os.environ.get("OKAM_VENDOR_DIR"), str(Path.cwd() / ".vendor" / "arm64"),
             str(Path(PACKAGE_PARENT).parent / ".vendor" / "arm64")]
    for name in names:
        if name and (Path(name) / "device_wakeup_server.dart").is_file():
            return Path(name) / "device_wakeup_server.dart"
    return None


def waking(starter, device: AccountDevice, *, status=None, source=wake_source, waker=wake_camera):
    """Wake a low-power camera before each session start, as the bridge does."""
    def start():
        out = status or sys.stderr
        path = source()
        credentials = load_wake_credentials(path) if path else None
        if credentials is None:
            print("warning: wake configuration not found (set OKAM_VENDOR_DIR); "
                  "a sleeping camera may not answer", file=out)
        else:
            try:
                result = asyncio.run(waker(device.uid, credentials, timeout=12.0))
                print(f"Wake requested ({result.responsive_servers} wake server(s) answered).", file=out)
            except WakeError as error:
                # Fixed messages from wakeup.wake_camera; mains-powered cameras are not registered.
                if "not registered" in str(error):
                    print("Camera is not a low-power model; no wake needed.", file=out)
                else:
                    print("warning: the wake service was unreachable; trying to connect anyway", file=out)
        return starter()
    return start


def list_cameras(client, devices, *, show_secrets: bool, salt: str | None, resolver=resolve_vp_device):
    rows = []
    for device in devices:
        row = {"name": device.name, "alias": camera_alias(device.name),
               "transport": "VP" if is_vp(device) else "CS2"}
        if show_secrets and is_vp(device):
            inputs = vp_inputs(client, device, salt or "", resolver=resolver)
            row.update(camera_password=inputs.password, connection=inputs.connection)
        rows.append(row)
    return rows


def _ffmpeg(which=shutil.which) -> str:
    path = which("ffmpeg")
    if not path:
        raise CliError("ffmpeg was not found on PATH")
    return path


def record_clip(starter, output: Path, seconds: float, *, lens: int | None = None,
                clock=time.monotonic, startup_timeout: float = 60.0, sleep=time.sleep,
                status=None) -> dict[str, object]:
    """Record each lens to its own file, timing from the first frame, then verify."""
    status = status or sys.stderr
    if not 1 <= seconds <= MAX_CLIP_SECONDS:
        raise CliError(f"clip length must be 1 to {MAX_CLIP_SECONDS} seconds")
    if output.suffix.lower() not in (".h264", ".mp4"):
        raise CliError("output must end in .h264 or .mp4")
    single = lens is not None
    targets = [lens_path(output, item, single=single) for item in ([lens] if single else range(MAX_LENS + 1))]
    if any(target.exists() for target in targets):
        raise CliError("output file already exists")
    try:
        lens_clip._av()
    except ClipError as error:
        raise CliError(str(error)) from None
    for attempt, delay in enumerate((*CONNECT_RETRY_SECONDS, None), start=1):
        process, recorders = _record_attempt(starter, output, seconds, lens, single, clock, startup_timeout)
        if recorders or delay is None or worker_summary(process).get("failure_stage") != "connect":
            break
        print(f"Could not reach the camera (attempt {attempt}); retrying in {delay} s...", file=status)
        sleep(delay)
    try:
        results = [recorders[item].finish() for item in sorted(recorders)]
    except ClipError as error:
        raise CliError(str(error)) from None
    saved = [result for result in results if result["saved"]]
    if not saved:
        raise CliError("the camera sent no video: " + worker_failure(process))
    if any(not result["decoded_frames"] for result in saved):
        raise CliError("a saved clip has no decodable pictures")
    return {"saved": True, "lenses": results}


def _record_attempt(starter, output, seconds, lens, single, clock, startup_timeout):
    """Run one worker session for a clip; recorders exist only if video arrived."""
    process = starter()
    records: queue.Queue = queue.Queue(maxsize=512)

    def pump():
        try:
            for item in read_lens_records(process.stdout):
                records.put(item)
        except (VPError, OSError, ValueError):
            pass
        finally:
            records.put(None)

    threading.Thread(target=pump, daemon=True).start()
    recorders: dict[int, LensRecorder] = {}
    deadline = None
    startup_deadline = clock() + startup_timeout
    try:
        while True:
            limit = deadline if deadline is not None else startup_deadline
            remaining = limit - clock()
            if remaining <= 0:
                break
            try:
                item = records.get(timeout=min(.5, remaining))
            except queue.Empty:
                continue
            if item is None:
                break
            frame_lens, payload = item
            if single and frame_lens != lens:
                continue
            recorder = recorders.get(frame_lens)
            if recorder is None:
                recorder = recorders[frame_lens] = LensRecorder(
                    frame_lens, lens_path(output, frame_lens, single=single))
            recorder.add(payload, clock=clock)
            if deadline is None and recorder.frames:
                deadline = clock() + seconds
    finally:
        _stop(process)
    return process, recorders


def worker_summary(process) -> dict:
    """The worker's fixed-schema stderr summary, read once and cached."""
    cached = getattr(process, "okam_summary", None)
    if cached is not None:
        return cached
    try:
        lines = process.stderr.read(8192).decode("ascii", "replace").strip().splitlines()
        summary = json.loads(lines[-1]) if lines else {}
    except (AttributeError, OSError, ValueError):
        summary = {}
    summary = summary if isinstance(summary, dict) else {}
    try:
        process.okam_summary = summary
    except AttributeError:
        pass
    return summary


def worker_failure(process) -> str:
    """Explain a worker failure from its fixed-schema stderr summary."""
    summary = worker_summary(process)
    if not summary:
        return "the stream worker exited without a summary"
    stage = summary.get("failure_stage")
    if stage not in STAGE_HINTS:
        return ("the stream worker rejected its inputs" if summary.get("failure")
                else "the stream worker stopped without video")
    code = summary.get("failure_code")
    flags = ", ".join(f"{name}={'yes' if summary.get(name) else 'no'}"
                      for name in ("connected", "authenticated"))
    detail = f" [stage={stage}, {flags}"
    if isinstance(code, str) and code.isidentifier():
        detail += f", code={code}"
    return STAGE_HINTS[stage] + detail + "]"


def _stop(process) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def grab_jpeg(starter, output: Path, *, which=shutil.which, session_factory=NativeStreamSession):
    if output.exists():
        raise CliError("output file already exists")
    ffmpeg = _ffmpeg(which)
    session = session_factory(starter, idle_timeout=10)
    try:
        jpeg, width, height = session.snapshot(ffmpeg)
    finally:
        session.close()
    with output.open("xb") as handle:
        handle.write(jpeg)
    return {"saved": True, "width": width, "height": height}


def make_stream_handler(session: NativeStreamSession):
    class StreamHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server API
            if self.path.split("?", 1)[0] != "/stream.h264":
                self.send_error(404)
                return
            subscription = session.acquire()
            try:
                self.send_response(200)
                self.send_header("Content-Type", "video/h264")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                for chunk in subscription:
                    self.wfile.write(chunk)
            except (BrokenPipeError, ConnectionError, OSError):
                pass
            finally:
                subscription.close()

        def log_message(self, *_args):
            pass

    return StreamHandler


def parse_listen(value: str) -> tuple[str, int]:
    host, separator, port = value.rpartition(":")
    # Port 0 asks the OS for a free port; the bound address is printed.
    if not separator or not host or not port.isdigit() or not 0 <= int(port) <= 65535:
        raise CliError("--listen must be HOST:PORT")
    return host, int(port)


def serve(starter, listen: str, *, out=sys.stdout, err=sys.stderr, stop: threading.Event | None = None,
          server_factory=ThreadingHTTPServer, session_factory=NativeStreamSession):
    host, port = parse_listen(listen)
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("warning: the stream is unauthenticated on this network address", file=err)
    session = session_factory(starter, idle_timeout=30)
    server = server_factory((host, port), make_stream_handler(session))
    server.daemon_threads = True
    url = f"http://{host}:{server.server_address[1]}/stream.h264"
    print(f"streaming at {url}", file=out)
    print(f"  VLC:    vlc --demux h264 {url}", file=out)
    print(f"  go2rtc: ffmpeg:{url}#video=copy", file=out)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    stop = stop or threading.Event()
    try:
        # Short waits keep Ctrl+C responsive on Windows.
        while not stop.wait(0.5):
            pass
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
        session.close()
    return {"stopped": True}
