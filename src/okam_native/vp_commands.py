"""Camera command framing shared by the observed VP relay session."""
import struct
import time
from dataclasses import dataclass, field

from .vp import VPError, extract_video_payload, video_lens, MAX_VIDEO_BYTES


@dataclass(frozen=True)
class VPAuthentication:
    user: str = field(repr=False)
    password: str = field(repr=False)
    account: str = field(repr=False)
    token: str = field(repr=False)


def parse_authentication(value: str, password: str) -> VPAuthentication:
    """Bounded counterpart of CPPPP2Channel's structured auth constructor.

    The %% form contains user, account and token separated by ampersands.
    Plain usernames cannot establish the account-token path and fail closed.
    """
    if not isinstance(value, str) or not value.startswith('%%'):
        raise VPError('VP structured authentication is required')
    parts = value[2:].split('&')
    if len(parts) != 3:
        raise VPError('VP authentication fields are invalid')
    for item, limit in zip((*parts, password), (127, 63, 255, 63), strict=True):
        if (not isinstance(item, str) or not item or len(item) > limit
                or any(ord(c) < 33 or ord(c) > 126 or c in '&?#' for c in item)):
            raise VPError('VP authentication fields are invalid')
    return VPAuthentication(parts[0], password, parts[1], parts[2])


# An idle camera acknowledged the first command and began its status reply
# only after more than five seconds; later commands answer promptly.
WAKE_TIMEOUT_SECONDS = 20


def start_authenticated_stream(session, auth: VPAuthentication, *, substream: int = 0) -> None:
    """Measured status, account-auth, user-check and live-start sequence."""
    from .cs2 import parse_result
    if type(substream) is not int or substream not in (0, 1, 2):
        raise VPError('VP substream is invalid')
    session.write(0, make_cgi_request('get_status.cgi?name=admin&', auth.user, auth.password),
                  timeout=WAKE_TIMEOUT_SECONDS)
    deadline = time.monotonic() + WAKE_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        command, body = read_command(session, timeout=max(.001, deadline-time.monotonic()))
        if command == 0x6001:
            if parse_result(body) != 0:
                raise VPError('VP status authentication rejected')
            break
    else:
        raise VPError('VP status authentication timed out')
    for path in (
        'eye4_authentication.cgi?loginAccount='+auth.account+'&loginToken='+auth.token+'&',
        'check_user.cgi?',
        f'livestream.cgi?streamid=10&substream={substream}&',
    ):
        session.write(0, make_cgi_request(path, auth.user, auth.password), timeout=5)


def make_cgi_request(path: str, user: str, password: str) -> bytes:
    if (not isinstance(path, str) or not path or len(path) > 2048
            or any(ord(char) < 32 for char in path)):
        raise VPError("VP camera CGI path is invalid")
    for value in (user, password):
        if (not isinstance(value, str) or len(value) > 512
                or any(ord(char) < 32 for char in value)):
            raise VPError("VP camera credential is invalid")
    try:
        body = (f"GET /{path}loginuse={user}&loginpas={password}"
                f"&user={user}&pwd={password}&").encode("ascii")
    except UnicodeError:
        raise VPError("VP camera CGI request is invalid") from None
    return struct.pack("<HHHH", 0x0A01, 0, len(body), 0) + body


def read_command(session, *, timeout: float = 5.0) -> tuple[int, bytes]:
    deadline = time.monotonic() + timeout
    header = session.read_exact(0, 8, timeout=timeout)
    magic, command, size, reserved = struct.unpack("<HHHH", header)
    # Parking's 0x6001 status response uses 0x0100 in the final word.
    # Its meaning is unresolved; admit only zero and this measured value.
    if magic != 0x0A01 or reserved not in (0, 0x0100):
        raise VPError("VP camera command header is invalid")
    from .vp_session import VPTimeout
    try:
        body = session.read_exact(0, size, timeout=max(.001, deadline-time.monotonic()))
    except VPTimeout:
        raise VPError('VP camera command body did not arrive') from None
    session.counters[f"command_{command:04x}"] += 1
    return command, body


def read_video_frame(session, *, timeout: float = 30.0) -> tuple[bytes, bool, int]:
    """Return one frame's H.264 payload, keyframe flag and lens index."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        header = session.read_exact(1, 32, timeout=max(.001, deadline-time.monotonic()))
        size = int.from_bytes(header[16:20], "little")
        if size > MAX_VIDEO_BYTES:
            raise VPError("VP camera video size is invalid")
        if size == 0:
            continue
        from .vp_session import VPTimeout
        try:
            body = session.read_exact(1, size, timeout=max(.001, deadline-time.monotonic()))
        except VPTimeout:
            raise VPError('VP camera video body did not arrive') from None
        payload, keyframe = extract_video_payload(header + body)
        return payload, keyframe, video_lens(header)
    raise VPError("VP camera video timed out")
