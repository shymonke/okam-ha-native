"""Verified building blocks for the Parking VP transport.

These decode initialization records; they do not establish a video session.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
from dataclasses import dataclass, field

from .p2p import P2PError, _valid_vp_server

MAX_VIDEO_BYTES = 512 * 1024


class VPError(P2PError):
    """A VP failure with no input values in its message."""


@dataclass(frozen=True)
class VPConnectionInput:
    """Private constructor fields; the record still needs validation."""

    transport_id: str = field(repr=False)
    initialization_record: str = field(repr=False)


def split_connection_input(value: str) -> VPConnectionInput:
    """Mirror CPPPP2Channel's first %% split without vendor buffer overflow.

    This is the connection input, not the app-wide InitialWithServer input.
    An absent suffix remains empty; no vendor service default is embedded.
    """
    if (not isinstance(value, str) or len(value) > 1088
            or any(ord(c) < 33 or ord(c) > 126 for c in value)):
        raise VPError("VP connection input is invalid")
    identifier, separator, record = value.partition("%%")
    if not identifier or len(identifier) >= 64 or len(record) >= 1024:
        raise VPError("VP connection field length is invalid")
    return VPConnectionInput(identifier, record if separator else "")


def extract_video_payload(data: bytes) -> tuple[bytes, bool]:
    """Validate a complete vendor video buffer and remove its 32-byte header.

    The header layout and H.264 payload were verified by independent decoding
    of Parking callbacks. H.265 is deliberately rejected until tested.
    """
    if not isinstance(data, bytes) or len(data) < 32:
        raise VPError("VP video header is incomplete")
    length = int.from_bytes(data[16:20], "little")
    if not 0 < length <= MAX_VIDEO_BYTES or length != len(data) - 32:
        raise VPError("VP video payload length is invalid")
    if data[4] in (0x10, 0x11):
        raise VPError("VP H.265 video requires separate validation")
    return data[32:], data[:4] == b"\x55\xaa\x15\xa8"


def video_lens(header: bytes) -> int:
    """Lens index from a vendor video header.

    Measured on the dual-lens Parking camera (2026-10-11): one live session
    alternates frames from two independent H.264 encoders, distinguished only
    by offset 26 (0 or 1). Single-lens cameras are expected to report 0.
    """
    if not isinstance(header, bytes) or len(header) < 32:
        raise VPError("VP video header is incomplete")
    return header[26]


class VPVideoFrames:
    """Frame the channel byte stream, preserving split headers and bodies."""

    def __init__(self):
        self._buffer = bytearray()
        self._failed = False

    def feed(self, data: bytes) -> list[tuple[bytes, bool]]:
        if self._failed:
            raise VPError("VP video parser is closed")
        if not isinstance(data, bytes) or len(self._buffer) + len(data) > MAX_VIDEO_BYTES + 32:
            self._fail("VP video buffer limit exceeded")
        self._buffer.extend(data)
        frames = []
        while len(self._buffer) >= 32:
            size = int.from_bytes(self._buffer[16:20], "little")
            if size > MAX_VIDEO_BYTES:
                self._fail("VP video payload length is invalid")
            if len(self._buffer) < size + 32:
                break
            packet = bytes(self._buffer[:size + 32])
            del self._buffer[:size + 32]
            if size == 0:
                continue  # The recovered worker skips empty media records.
            try:
                frames.append(extract_video_payload(packet))
            except VPError:
                self._failed = True
                self._buffer.clear()
                raise
        return frames

    def finish(self) -> None:
        """Reject a truncated final record rather than silently losing media."""
        if self._failed:
            raise VPError("VP video parser is closed")
        self._failed = True
        if self._buffer:
            self._buffer.clear()
            raise VPError("VP video stream ended with an incomplete frame")

    def _fail(self, message: str):
        self._buffer.clear()
        self._failed = True
        raise VPError(message)


class VPChannelBuffer:
    """Bounded ordered byte stream for one VP reliable channel.

    Mirrors the recovered reader's partial-buffer and reserved-sequence
    behavior. The packet decoder must explicitly supply the prefix length;
    this class does not guess wire flag meanings, acknowledge packets, wait,
    or open a socket. Each channel/session needs its own instance.
    """

    def __init__(self, *, next_sequence: int = 0, window: int = 128,
                 max_bytes: int = 1024 * 1024):
        if (type(next_sequence) is not int or not 0 <= next_sequence < 0xFFFF
                or type(window) is not int or not 1 <= window < 0x8000
                or type(max_bytes) is not int or not 1 <= max_bytes <= 8 * 1024 * 1024):
            raise VPError("VP channel limits are invalid")
        self.next_sequence = next_sequence
        self.window = window
        self.max_bytes = max_bytes
        self._pending: dict[int, tuple[bytes, int]] = {}
        self._offset = 0
        self._bytes = 0
        self._closed = False

    def feed(self, sequence: int, data: bytes, *, header_bytes: int) -> bool:
        """Queue one complete packet; return false for duplicates/stale data."""
        if self._closed:
            raise VPError("VP channel is closed")
        if (type(sequence) is not int or not 0 <= sequence < 0xFFFF
                or not isinstance(data, bytes) or type(header_bytes) is not int
                or header_bytes not in (1, 6) or len(data) < header_bytes):
            raise VPError("VP channel packet is invalid")
        distance = (sequence - self.next_sequence) % 0xFFFF
        if distance > 0x7FFF:
            return False  # An already-consumed packet, including across wrap.
        if distance >= self.window:
            raise VPError("VP channel reorder window exceeded")
        previous = self._pending.get(sequence)
        if previous is not None:
            if previous != (data, header_bytes):
                raise VPError("VP channel duplicate conflicts with buffered data")
            return False
        if self._bytes + len(data) > self.max_bytes:
            raise VPError("VP channel buffer limit exceeded")
        self._pending[sequence] = data, header_bytes
        self._bytes += len(data)
        return True

    def read(self, count: int) -> bytes:
        """Consume up to count contiguous bytes, retaining partial offsets."""
        if type(count) is not int or not 0 <= count <= self.max_bytes:
            raise VPError("VP channel read size is invalid")
        result = bytearray()
        while len(result) < count:
            packet = self._pending.get(self.next_sequence)
            if packet is None:
                break
            data, header_bytes = packet
            start = header_bytes + self._offset
            size = min(count - len(result), len(data) - start)
            result.extend(data[start:start + size])
            self._offset += size
            if header_bytes + self._offset == len(data):
                del self._pending[self.next_sequence]
                self._bytes -= len(data)
                self._offset = 0
                self.next_sequence = (self.next_sequence + 1) % 0xFFFF
            else:
                break
        return bytes(result)

    def close(self) -> None:
        """Discard buffered media and prevent reuse by another session."""
        self._pending.clear()
        self._bytes = 0
        self._offset = 0
        self._closed = True


@dataclass(frozen=True)
class VPInitialization:
    # Names describe observed use, not an established vendor API contract.
    record_number: int = field(repr=False)
    rendezvous_descriptor: str = field(repr=False)
    rendezvous_hosts: tuple[str, ...] = field(repr=False)
    peer_hosts: tuple[str, ...] = field(repr=False)
    family_rule: str = field(repr=False)
    auth_digest: bytes = field(repr=False)


def _md5(value: bytes) -> bytes:
    return hashlib.md5(value, usedforsecurity=False).digest()


def _initialization_material() -> tuple[bytes, bytes, bytes, bytes]:
    """Reproduce FUN_10029de0 without embedding derived values.

    Both AES inputs were compared in memory against the initialized vendor
    DLL. The remaining slices are used by its record marker/auth derivation.
    """
    first = _md5(bytes(sum((13, 19, 5, 14, 10)))).hex().upper().encode("ascii")
    second = _md5(b"".join(first[:n] for n in (3, 14, 17, 20, 24)))
    second_hex = second.hex().upper().encode("ascii")
    # DAT_102e52c1 is copied from local_98 after the second hex conversion,
    # while DAT_102e52b0 belongs to the first conversion. The record's
    # authentication digest uses the former, not the first chain's tail.
    return first[:16], second_hex[:16], second_hex[16:24], second_hex[24:32]


def _initialization_parts(value: str) -> tuple[list[str], str]:
    """Decrypt a DAS record and validate its fields, excluding the checksum."""
    invalid = "VP initialization record is invalid"
    if not isinstance(value, str) or not 36 <= len(value) <= 4096:
        raise VPError(invalid)
    if not value.startswith("DAS-") or not value.isascii():
        raise VPError(invalid)
    body, separator, suffix = value[4:].partition(":")
    if (not body or len(body) % 32 or not re.fullmatch(r"[0-9A-Fa-f]+", body)
            or (separator and (not suffix or ":" in suffix
                or any(ord(c) < 32 or ord(c) > 126 for c in suffix)))):
        raise VPError(invalid)
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        raise VPError("VP initialization decoder requires the vp dependency") from None

    key, iv, salt, marker = _initialization_material()
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    plain = decryptor.update(bytes.fromhex(body)) + decryptor.finalize()
    # The vendor allocates one extra zero byte before strtok. Do not assume
    # PKCS#7 padding: it never unpads this buffer in the recovered routine.
    plain = plain.split(b"\0", 1)[0]
    try:
        parts = plain.decode("ascii").split(",")
    except UnicodeError:
        raise VPError(invalid) from None
    if (len(parts) not in (6, 7) or not all(parts)
            or parts[0].encode("ascii") != marker or parts[1] != "das"
            # The vendor hashes eight bytes from this token. Restrict to
            # the verified eight-digit form rather than inventing padding
            # semantics for a shorter token or truncating a longer number.
            or not re.fullmatch(r"[0-9]{8}", parts[2])
            or not re.fullmatch(r"[A-Za-z0-9]{3,16}", parts[5])):
        raise VPError(invalid)
    return parts, suffix


def _checksum_matches(parts: list[str], checksum_salt: bytes) -> bool:
    # FUN_1002c390 compares nine uppercase digest characters at offset 8.
    signed_fields = [parts[1], str(int(parts[2])), *parts[3:6]]
    signature = _md5(",".join(signed_fields).encode("ascii") + checksum_salt)
    return hmac.compare_digest(parts[6], signature.hex().upper()[8:17])


def select_checksum_salt(value: str, candidates) -> bytes | None:
    """Return the first 5-byte candidate that validates the record's checksum.

    Records without a checksum field need no salt and return None.
    """
    parts, _suffix = _initialization_parts(value)
    if len(parts) != 7:
        return None
    for candidate in candidates:
        if isinstance(candidate, bytes) and len(candidate) == 5 and _checksum_matches(parts, candidate):
            return candidate
    raise VPError("VP initialization checksum material was not found")


def decode_initialization(value: str, *, checksum_salt: bytes | None = None) -> VPInitialization:
    """Decrypt and validate a DAS connection record with bounded input.

    No network access, vendor DLL, camera, or filesystem is used. Optional
    ``vp`` dependencies supply AES; the legacy CS2 transport is unchanged.
    The resulting object deliberately hides all fields from repr().
    """
    invalid = "VP initialization record is invalid"
    parts, suffix = _initialization_parts(value)
    _key, _iv, salt, _marker = _initialization_material()
    # FUN_1002c390 only creates the auxiliary rendezvous resolver for a
    # descriptor longer than ten bytes. Short descriptors are opaque flags,
    # not malformed DNS names. Its host-list delimiter is '+', not '-'.
    descriptor = parts[3]
    if len(descriptor) > 1024 or any(ord(c) < 33 or ord(c) > 126 for c in descriptor):
        raise VPError(invalid)
    hosts = tuple(descriptor.split("+")) if len(descriptor) > 10 else ()
    peers = tuple(parts[4].split("-"))
    if len(hosts) > 16 or not all(_valid_vp_server(host) for host in hosts):
        raise VPError(invalid)
    try:
        if not 1 <= len(peers) <= 3:
            raise ValueError
        for host in peers:
            ipaddress.IPv4Address(host)
    except ValueError:
        raise VPError(invalid) from None
    if len(parts) == 7:
        if not isinstance(checksum_salt, bytes) or len(checksum_salt) != 5:
            raise VPError("VP initialization checksum requires protocol material")
        if not _checksum_matches(parts, checksum_salt):
            raise VPError(invalid)
    # The optional outer suffix is truncated to 16 bytes by the vendor and
    # included in this digest only when at least two bytes remain.
    suffix_bytes = suffix[:16].encode("ascii")
    auth = _md5(parts[2].encode("ascii")[:8] + salt
                + (suffix_bytes if len(suffix_bytes) > 1 else b""))
    return VPInitialization(int(parts[2]), descriptor, hosts, peers, parts[5], auth)
