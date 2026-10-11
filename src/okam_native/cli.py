"""CLI for the local bridge, plus direct camera commands through the account.

Bridge commands need only the local API token. Direct commands (cameras, clip,
grab, serve) prompt for the O-KAM account password and never store it.
"""

from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    """Never forward bridge credentials to a redirect destination."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(base: str, token: str, path: str, *, body=None, timeout=90):
    parsed = urlsplit(base)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or parsed.path not in {"", "/"}):
        raise ValueError("bridge URL must be an HTTP(S) origin without credentials")
    if not token or "\r" in token or "\n" in token:
        raise ValueError("set OKAM_API_TOKEN to the local bridge API token")
    payload = None if body is None else json.dumps(body).encode()
    req = Request(base.rstrip("/") + path, data=payload,
                  method="GET" if body is None else "PATCH",
                  headers={"Authorization": f"Bearer {token}",
                           "Content-Type": "application/json"})
    with build_opener(NoRedirect()).open(req, timeout=timeout) as response:
        return response.read()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Control cameras exposed by a local O-KAM bridge")
    parser.add_argument("--bridge", default=os.environ.get("OKAM_BRIDGE_URL", "http://127.0.0.1:8099"))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("devices", help="list cameras exposed by the bridge")
    status = sub.add_parser("status", help="get status of one camera, or every exposed camera")
    status.add_argument("camera", nargs="?")
    snapshot = sub.add_parser("snapshot", help="wake a camera if needed and save a JPEG")
    snapshot.add_argument("camera")
    snapshot.add_argument("output", type=Path)
    configure = sub.add_parser("configure", help="set a camera's idle disconnect delay")
    configure.add_argument("camera")
    configure.add_argument("--idle-timeout", type=int, required=True)

    def account_parser(name, help_text):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("--email", help="O-KAM account email (saved login or prompt if omitted)")
        command.add_argument("--vp-salt-file", type=Path,
                             help="file holding the VP camera password key (saved key or prompt if omitted)")
        return command

    account_parser("login", "check the O-KAM login and save it in the system keyring")
    sub.add_parser("logout", help="remove the saved O-KAM login from the system keyring")

    cameras = account_parser("cameras", "list cameras on the O-KAM account (direct)")
    cameras.add_argument("--show-secrets", action="store_true",
                         help="also print VP camera passwords and connection inputs")
    clip = account_parser("clip", "record a short H.264 clip directly from a VP camera")
    clip.add_argument("camera")
    clip.add_argument("output", type=Path)
    clip.add_argument("--seconds", type=float, required=True)
    clip.add_argument("--substream", type=int, choices=(0, 1, 2), default=0)
    clip.add_argument("--lens", type=int, choices=(0, 1, 2, 3),
                      help="record one lens to OUTPUT (default: every lens, OUTPUT-lensN)")
    grab = account_parser("grab", "save one JPEG directly from a VP camera")
    grab.add_argument("camera")
    grab.add_argument("output", type=Path)
    grab.add_argument("--lens", type=int, choices=(0, 1, 2, 3), default=0)
    serve = account_parser("serve", "serve a VP camera as live H.264 over HTTP for VLC or go2rtc")
    serve.add_argument("camera")
    serve.add_argument("--listen", default="127.0.0.1:8554")
    serve.add_argument("--substream", type=int, choices=(0, 1, 2), default=0)
    serve.add_argument("--lens", type=int, choices=(0, 1, 2, 3), default=0)
    tui = account_parser("tui", "watch every lens of a VP camera live in the terminal")
    tui.add_argument("camera")
    tui.add_argument("--output-dir", type=Path, default=Path("okam-captures"),
                     help="where recordings and snapshots go (default: ./okam-captures)")
    tui.add_argument("--substream", type=int, choices=(0, 1, 2), default=0)
    tui.add_argument("--quality", choices=("low", "medium", "high"), default="medium",
                     help="terminal preview quality; press v to change it while watching")
    args = parser.parse_args(argv)
    if args.command in {"login", "logout", "cameras", "clip", "grab", "serve", "tui"}:
        return run_direct(args)
    token = os.environ.get("OKAM_API_TOKEN", "")
    def call(path, **kwargs):
        return request(args.bridge, token, path, **kwargs)
    def camera_path(camera):
        return "/api/cameras/" + quote(camera, safe="")
    try:
        if args.command == "devices":
            result = json.loads(call("/api/devices"))
        elif args.command == "status":
            if args.camera:
                result = json.loads(call(camera_path(args.camera) + "/status"))
            else:
                devices = json.loads(call("/api/devices"))
                result = [json.loads(call(camera_path(device["camera_id"]) + "/status"))
                          for device in devices]
        elif args.command == "snapshot":
            data = call(camera_path(args.camera) + "/snapshot.jpg")
            if not data.startswith(b"\xff\xd8") or not data.endswith(b"\xff\xd9"):
                raise ValueError("bridge did not return a complete JPEG")
            # Exclusive creation protects an existing image from accidental overwrite.
            with args.output.open("xb") as output:
                output.write(data)
            result = {"saved": True}
        else:
            if not 10 <= args.idle_timeout <= 600:
                raise ValueError("idle timeout must be between 10 and 600 seconds")
            result = json.loads(call(camera_path(args.camera) + "/config",
                                     body={"idle_timeout_seconds": args.idle_timeout}))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except HTTPError as exc:
        print(f"bridge request failed (HTTP {exc.code})", file=sys.stderr)
    except (URLError, OSError, TimeoutError):
        print("bridge request or local file operation failed", file=sys.stderr)
    except (ValueError, KeyError, TypeError):
        print("invalid configuration or bridge response; check URL, token, timeout, and output", file=sys.stderr)
    return 1


def run_direct(args, *, login=None) -> int:
    from . import direct_cli
    from .account import AccountError
    from .p2p import P2PError

    login = login or direct_cli.login
    try:
        if args.command in {"login", "logout"}:
            result = (direct_cli.save_login(args.email, args.vp_salt_file) if args.command == "login"
                      else direct_cli.forget_login())
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        client, devices = login(args.email)
        if args.command == "cameras":
            salt = direct_cli.read_salt(args.vp_salt_file) if args.show_secrets and any(
                direct_cli.is_vp(device) for device in devices) else None
            if args.show_secrets:
                print("warning: output contains camera secrets", file=sys.stderr)
            result = direct_cli.list_cameras(client, devices, show_secrets=args.show_secrets, salt=salt)
        else:
            device = direct_cli.find_camera(devices, args.camera)
            if not direct_cli.is_vp(device):
                raise direct_cli.CliError("VP cameras only for now")
            print(f"Found camera '{device.name}'; resolving its relay connection...", file=sys.stderr)
            inputs = direct_cli.vp_inputs(client, device, direct_cli.read_salt(args.vp_salt_file))
            print("Connecting to the camera and starting video...", file=sys.stderr)
            substream = getattr(args, "substream", 0)
            if args.command == "clip":
                # Framed output carries every lens of the single camera session.
                starter = direct_cli.waking(
                    direct_cli.worker_starter(inputs, substream=substream, framed=True), device)
                result = direct_cli.record_clip(starter, args.output, args.seconds, lens=args.lens)
            elif args.command == "tui":
                from . import tui
                # The TUI owns the terminal, so wake messages are not printed there.
                starter = direct_cli.waking(
                    direct_cli.worker_starter(inputs, substream=substream, framed=True), device,
                    status=io.StringIO())
                result = tui.run(starter, device.name, args.output_dir, failure=direct_cli.worker_failure,
                                 quality=args.quality)
            elif args.command == "grab":
                starter = direct_cli.waking(
                    direct_cli.worker_starter(inputs, substream=substream, lens=args.lens), device)
                result = direct_cli.grab_jpeg(starter, args.output)
            else:
                starter = direct_cli.waking(
                    direct_cli.worker_starter(inputs, substream=substream, lens=args.lens), device)
                result = direct_cli.serve(starter, args.listen)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except direct_cli.CliError as exc:
        print(str(exc), file=sys.stderr)
    except AccountError:
        print("O-KAM account login or device listing failed", file=sys.stderr)
    except P2PError:
        print("camera resolution, credentials or stream failed", file=sys.stderr)
    except (OSError, EOFError):
        print("local file, network or input operation failed", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
