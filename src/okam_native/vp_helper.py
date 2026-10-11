"""Pure Python VP streaming worker; private configuration arrives on stdin.

Provisioning fresh account-derived VP material is separate from this worker.
No vendor DLL, GUI, or emulation is loaded. Stdout contains only H.264 bytes;
stderr contains a fixed-schema summary without private input or exceptions.
"""
from __future__ import annotations

import json
import re
import signal
import struct
import subprocess
import sys
import time

from .cs2 import inspect_h264
from .vp import MAX_VIDEO_BYTES, VPError, decode_initialization, split_connection_input
from .vp_commands import (make_cgi_request, parse_authentication,
                          read_video_frame, start_authenticated_stream)
from .vp_session import VPSession, VPTimeout


_running = True


def open_stream_process(config: dict, *, environment: dict[str, str] | None = None,
                        python: str = sys.executable) -> subprocess.Popen:
    """Start a worker with private fields on stdin, never process arguments."""
    process = None
    try:
        encoded = json.dumps(config, ensure_ascii=True, allow_nan=False).encode() + b'\n'
        if len(encoded) > 16384:
            raise ValueError
        process = subprocess.Popen([python, '-m', 'okam_native.vp_helper'],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=environment, bufsize=0)
        process.stdin.write(encoded)
        process.stdin.close()
        process.stdin = None
        return process
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        raise VPError('VP native stream worker failed') from None


MAX_LENS = 3
# Seconds without any video after media started before the worker gives up.
MEDIA_STALL_SECONDS = 20
LENS_RECORD_HEADER = struct.Struct('>BI')


def encode_lens_record(lens: int, payload: bytes) -> bytes:
    """Framed worker output: lens index, payload length, H.264 payload."""
    return LENS_RECORD_HEADER.pack(lens, len(payload)) + payload


def read_lens_records(stream):
    """Yield ``(lens, payload)`` from framed worker output until EOF."""
    while True:
        header = _read_exact(stream, LENS_RECORD_HEADER.size)
        if header is None:
            return
        lens, size = LENS_RECORD_HEADER.unpack(header)
        if lens > MAX_LENS or not 0 < size <= MAX_VIDEO_BYTES:
            raise VPError('VP worker lens record is invalid')
        payload = _read_exact(stream, size)
        if payload is None:
            raise VPError('VP worker lens record is truncated')
        yield lens, payload


def _read_exact(stream, size: int) -> bytes | None:
    data = b''
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            if data:
                raise VPError('VP worker lens record is truncated')
            return None
        data += chunk
    return data


def _error_code(error: Exception) -> str:
    """Slug of a fixed VPError message; other errors may carry values."""
    message = str(error)
    if isinstance(error, VPError) and re.fullmatch(r"VP [A-Za-z0-9 .]{1,80}", message):
        return re.sub(r"[^a-z0-9]+", "_", message[3:].lower()).strip("_")
    return "unclassified" if isinstance(error, VPError) else type(error).__name__


def _stop(*_):
    global _running
    _running = False


def run(config: dict, output, *, session_factory=VPSession) -> tuple[int, dict]:
    """Stream until stop or bounded startup/read failure, always tearing down."""
    global _running
    _running = True
    summary = dict(connected=False, authenticated=False, stream_start_sent=False,
                   stream_stop_sent=False, disconnected=False, h264_received=False,
                   h264_frames=0, h264_bytes=0, keyframe_seen=False, lens_frames={},
                   counters={})
    state = None
    started = False
    code = 1
    stage = 'configuration'
    try:
        required = {'connection', 'authentication', 'password', 'checksum_salt'}
        optional = {'substream', 'max_frames', 'lens', 'framed'}
        if not isinstance(config, dict) or set(config) - required - optional or not required <= set(config):
            raise VPError('VP worker configuration is invalid')
        if any(not isinstance(config[k], str) for k in required):
            raise VPError('VP worker configuration is invalid')
        salt = config['checksum_salt'].encode('ascii')
        if len(salt) != 5:
            raise VPError('VP worker configuration is invalid')
        maximum = config.get('max_frames', 0)
        if type(maximum) is not int or not 0 <= maximum <= 1000:
            raise VPError('VP worker frame limit is invalid')
        lens, framed = config.get('lens', 0), config.get('framed', False)
        if type(lens) is not int or not 0 <= lens <= MAX_LENS or type(framed) is not bool:
            raise VPError('VP worker lens selection is invalid')
        parts = split_connection_input(config['connection'])
        init = decode_initialization(parts.initialization_record, checksum_salt=salt)
        auth = parse_authentication(config['authentication'], config['password'])
        state = session_factory(parts.transport_id, init)
        stage = 'connect'
        state.connect(timeout=20)
        summary['connected'] = True
        # Mark attempted before writing: a lost acknowledgement can still mean
        # the camera started; cleanup must send stop in that case too.
        started = True
        stage = 'authentication'
        start_authenticated_stream(state, auth, substream=config.get('substream', 0))
        summary.update(authenticated=True, stream_start_sent=True)
        first_frame_deadline = time.monotonic() + 30
        last_media = time.monotonic()
        while _running:
            stage = 'read_media'
            try:
                payload, keyframe, frame_lens = read_video_frame(state, timeout=1)
            except VPTimeout:
                if not summary['h264_received'] and time.monotonic() >= first_frame_deadline:
                    raise VPError('VP media startup timed out')
                # A relay that stays connected but stops sending video must end
                # the worker, so the session reconnects instead of hanging.
                if summary['h264_received'] and time.monotonic() - last_media >= MEDIA_STALL_SECONDS:
                    raise VPError('VP media stalled')
                continue
            last_media = time.monotonic()
            valid, nal_keyframe = inspect_h264(payload)
            stage = 'validate_media'
            if not valid:
                raise VPError('VP media is not H264')
            seen = summary['lens_frames']
            seen[str(frame_lens)] = seen.get(str(frame_lens), 0) + 1
            if framed:
                output.write(encode_lens_record(frame_lens, payload))
            elif frame_lens == lens:
                output.write(payload)
            else:
                continue
            output.flush()
            summary['h264_received'] = True
            summary['h264_frames'] += 1
            summary['h264_bytes'] += len(payload)
            summary['keyframe_seen'] |= keyframe or nal_keyframe
            if maximum and summary['h264_frames'] >= maximum:
                break
        code = 0 if summary['h264_received'] else 1
    except (VPError, OSError, ValueError, UnicodeError, TypeError) as error:
        summary['failure'] = 'VP native stream failed'
        summary['failure_stage'] = stage
        summary['failure_code'] = {
            'VP camera video body did not arrive': 'missing_video_body',
            'VP status authentication rejected': 'camera_password_rejected',
            'VP status authentication timed out': 'status_timeout',
            'VP partial channel read timed out': 'partial_channel_timeout',
            'VP media is not H264': 'not_h264',
            'VP video payload length is invalid': 'invalid_video_length',
            'VP H.265 video requires separate validation': 'unsupported_codec',
        }.get(str(error)) or _error_code(error)
    finally:
        if state is not None:
            if started:
                try:
                    state.write(0, make_cgi_request('livestream.cgi?streamid=16&substream=0&',
                                                   auth.user, auth.password), timeout=2)
                    summary['stream_stop_sent'] = True
                except (VPError, OSError):
                    pass
            try:
                state.close()
                summary['disconnected'] = True
            except (VPError, OSError):
                code = 1
            summary['counters'] = dict(state.counters)
    return code, summary


def main() -> int:
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        raw = sys.stdin.buffer.readline(16385)
        if len(raw) > 16384 or not raw.endswith(b'\n'):
            raise ValueError
        config = json.loads(raw)
    except (ValueError, UnicodeError):
        print('{"failure":"VP worker input is invalid"}', file=sys.stderr)
        return 1
    code, summary = run(config, sys.stdout.buffer)
    print(json.dumps(summary, sort_keys=True), file=sys.stderr)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
