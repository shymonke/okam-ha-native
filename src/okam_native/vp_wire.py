"""Verified VP reliable-message decoding, after fragment assembly.

This is not an outer UDP packet decoder. Key provenance and packet framing
must be established by the caller before any connection can use this codec.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import struct

from .vp import VPError

MAX_MESSAGE_BYTES = 2 * 1024 * 1024
FRAGMENT_BYTES = 1100


@dataclass(frozen=True)
class VPDataFragment:
    packet_sequence: int
    channel: int
    flow_mask: int
    message_sequence: int
    index: int
    count: int
    payload: bytes = field(repr=False)


def decode_data_fragment(packet: bytes, *, fragment_bytes: int = FRAGMENT_BYTES) -> VPDataFragment:
    """Decode a direct-path 0x0d datagram from the CPPPP2 reader.

    Relay envelopes must be removed separately. All four 16-bit message
    header fields use network order; declared length includes that header.
    """
    if type(fragment_bytes) is not int or not 1 <= fragment_bytes <= FRAGMENT_BYTES:
        raise VPError("VP fragment size is invalid")
    if not isinstance(packet, bytes) or len(packet) < 13 or packet[0] != 0x0D:
        raise VPError("VP data fragment is incomplete")
    sequence, channel, flow, message, length, index, count = struct.unpack(
        ">HBBHHHH", packet[1:13])
    payload = packet[13:]
    if (sequence == 0xFFFF or channel >= 8 or message == 0xFFFF
            or length != len(payload) + 8 or not 1 <= count <= 0x3FFF
            or index >= count or not 1 <= len(payload) <= fragment_bytes
            or count * fragment_bytes > MAX_MESSAGE_BYTES + fragment_bytes
            or (index < count - 1 and len(payload) != fragment_bytes)):
        raise VPError("VP data fragment fields are invalid")
    return VPDataFragment(sequence, channel, flow, message, index, count, payload)


def encode_data_fragment(fragment: VPDataFragment, *, fragment_bytes: int = FRAGMENT_BYTES) -> bytes:
    """Serialize the verified direct-path fragment layout."""
    if not isinstance(fragment, VPDataFragment):
        raise VPError("VP data fragment fields are invalid")
    values = (fragment.packet_sequence, fragment.channel, fragment.flow_mask,
              fragment.message_sequence, fragment.index, fragment.count)
    if any(type(value) is not int for value in values) or not isinstance(fragment.payload, bytes):
        raise VPError("VP data fragment fields are invalid")
    try:
        packet = b"\x0d" + struct.pack(
            ">HBBHHHH", *values[:4], len(fragment.payload) + 8,
            fragment.index, fragment.count) + fragment.payload
    except (struct.error, OverflowError):
        raise VPError("VP data fragment fields are invalid") from None
    decode_data_fragment(packet, fragment_bytes=fragment_bytes)
    return packet


def encode_fragment_ack(fragment: VPDataFragment, *, next_packet: int,
                        flow_mask: int = 0, fragment_bytes: int = FRAGMENT_BYTES) -> bytes:
    """Channel eight acknowledges the message and individual packet IDs."""
    if (type(next_packet) is not int or not 0 <= next_packet < 0xFFFF
            or type(flow_mask) is not int or not 0 <= flow_mask <= 255):
        raise VPError("VP acknowledgement fields are invalid")
    # Validate object fields through the same serializer as outbound data.
    encode_data_fragment(fragment, fragment_bytes=fragment_bytes)
    return b"\x0d" + struct.pack(
        ">HBBHH", next_packet, 8, flow_mask,
        fragment.message_sequence, fragment.packet_sequence)


class VPFragmentAssembler:
    """Bound incomplete messages and assemble without trusting arrival order."""

    def __init__(self, *, max_bytes: int = 4 * 1024 * 1024, max_messages: int = 128,
                 fragment_bytes: int = FRAGMENT_BYTES):
        if (type(max_bytes) is not int or not 1 <= max_bytes <= 16 * 1024 * 1024
                or type(max_messages) is not int or not 1 <= max_messages <= 1024):
            raise VPError("VP fragment limits are invalid")
        self.max_bytes = max_bytes
        self.max_messages = max_messages
        if type(fragment_bytes) is not int or not 1 <= fragment_bytes <= FRAGMENT_BYTES:
            raise VPError("VP fragment size is invalid")
        self.fragment_bytes = fragment_bytes
        self._pending: dict[tuple[int, int], tuple[int, dict[int, bytes]]] = {}
        self._bytes = 0

    def feed(self, fragment: VPDataFragment) -> bytes | None:
        encode_data_fragment(fragment, fragment_bytes=self.fragment_bytes)
        key = fragment.channel, fragment.message_sequence
        entry = self._pending.get(key)
        if entry is None:
            if len(self._pending) >= self.max_messages:
                raise VPError("VP incomplete message limit exceeded")
            entry = fragment.count, {}
        count, pieces = entry
        if count != fragment.count:
            raise VPError("VP fragment count conflicts")
        previous = pieces.get(fragment.index)
        if previous is not None:
            if previous != fragment.payload:
                raise VPError("VP fragment content conflicts")
            return None
        if self._bytes + len(fragment.payload) > self.max_bytes:
            raise VPError("VP fragment buffer limit exceeded")
        pieces[fragment.index] = fragment.payload
        self._bytes += len(fragment.payload)
        self._pending[key] = entry
        if len(pieces) != count:
            return None
        assembled = b"".join(pieces[i] for i in range(count))
        del self._pending[key]
        self._bytes -= len(assembled)
        if len(assembled) > MAX_MESSAGE_BYTES + 21:
            raise VPError("VP assembled message exceeds its limit")
        return assembled

    def clear(self) -> None:
        self._pending.clear()
        self._bytes = 0


@dataclass(frozen=True)
class VPDecodedMessage:
    """Reader-ready block and its verified application prefix length."""

    block: bytes
    prefix_bytes: int

    @property
    def payload(self) -> bytes:
        return self.block[self.prefix_bytes:]


def encode_reliable_message(payload: bytes, *, key: bytes, iv: bytes) -> bytes:
    """FUN_1002e130: marker, network-order size, full zero padding block."""
    if (not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_MESSAGE_BYTES
            or not isinstance(key, bytes) or len(key) != 16
            or not isinstance(iv, bytes) or len(iv) != 16):
        raise VPError("VP reliable message fields are invalid")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    plain = b"\xfa" + struct.pack(">I", len(payload)) + payload
    plain += bytes(16 - len(plain) % 16)
    encoder = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return b"\1" + encoder.update(plain) + encoder.finalize()


def decode_reliable_message(
    assembled: bytes,
    *,
    key: bytes | None = None,
    iv: bytes | None = None,
    max_payload_bytes: int = MAX_MESSAGE_BYTES,
) -> VPDecodedMessage:
    """Decode the format observed in the confirmed CPPPP2 receive worker.

    Byte zero is zero for plaintext. The encrypted path decrypts the remaining
    block with AES-128 CBC, verifies marker 0xfa, and reads a big-endian length.
    Padding is deliberately opaque: its encoding has not been established.
    Only flag 1 is accepted for encryption, because other bits are unverified.
    All failures use fixed messages without input or key material.
    """
    if not isinstance(max_payload_bytes, int) or not 0 < max_payload_bytes <= MAX_MESSAGE_BYTES:
        raise VPError("VP message limit is invalid")
    if not isinstance(assembled, bytes) or not assembled:
        raise VPError("VP reliable message is incomplete")
    if len(assembled) > max_payload_bytes + 21:
        raise VPError("VP reliable message exceeds its limit")
    if assembled[0] == 0:
        if len(assembled) - 1 > max_payload_bytes:
            raise VPError("VP reliable message exceeds its limit")
        return VPDecodedMessage(assembled, 1)
    if assembled[0] != 1:
        raise VPError("VP reliable message flag is unsupported")
    ciphertext = assembled[1:]
    if not ciphertext or len(ciphertext) % 16:
        raise VPError("VP reliable ciphertext length is invalid")
    if not isinstance(key, bytes) or len(key) != 16 or not isinstance(iv, bytes) or len(iv) != 16:
        raise VPError("VP reliable cipher material is invalid")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    if plaintext[0] != 0xFA:
        raise VPError("VP reliable message marker is invalid")
    payload_size = int.from_bytes(plaintext[1:5], "big")
    if payload_size > max_payload_bytes or payload_size > len(plaintext) - 5:
        raise VPError("VP reliable payload length is invalid")
    return VPDecodedMessage(assembled[:1] + plaintext[:5 + payload_size], 6)


# FUN_1001b380's TCP relay stream: each frame is a little-endian 16-bit length
# and that many bytes. Lengths 0 and 0xFFFF are keepalive request and reply,
# 0xFFFE carries a 16-bit packet-size hint, and data frames stay below 1500.
RELAY_PING = 0x0000
RELAY_PONG = 0xFFFF
RELAY_SIZE_HINT = 0xFFFE
RELAY_MAX_FRAME = 1500 - 1
RELAY_MAX_SIZE_HINT = 0x44C


def encode_relay_frame(payload: bytes) -> bytes:
    """Frame one relay data payload (a 0x0d packet without its type byte)."""
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= RELAY_MAX_FRAME:
        raise VPError("VP relay frame is invalid")
    return struct.pack("<H", len(payload)) + payload


def encode_relay_control(value: int) -> bytes:
    if value not in (RELAY_PING, RELAY_PONG):
        raise VPError("VP relay control is invalid")
    return struct.pack("<H", value)


@dataclass
class VPRelayFrameReader:
    """Incremental TCP relay stream parser yielding typed events.

    Events are ("ping", None), ("pong", None), ("size", int) and
    ("data", bytes). A length the vendor rejects ends the stream.
    """

    _buffer: bytearray = field(default_factory=bytearray)

    def feed(self, data: bytes) -> list[tuple[str, object]]:
        if not isinstance(data, bytes):
            raise VPError("VP relay stream data is invalid")
        self._buffer.extend(data)
        events: list[tuple[str, object]] = []
        while len(self._buffer) >= 2:
            length = int.from_bytes(self._buffer[:2], "little")
            if length == RELAY_PING:
                events.append(("ping", None))
                del self._buffer[:2]
            elif length == RELAY_PONG:
                events.append(("pong", None))
                del self._buffer[:2]
            elif length == RELAY_SIZE_HINT:
                if len(self._buffer) < 4:
                    break
                hint = int.from_bytes(self._buffer[2:4], "little")
                events.append(("size", min(hint, RELAY_MAX_SIZE_HINT)))
                del self._buffer[:4]
            elif length > RELAY_MAX_FRAME:
                raise VPError("VP relay frame length is invalid")
            else:
                if len(self._buffer) < 2 + length:
                    break
                events.append(("data", bytes(self._buffer[2:2 + length])))
                del self._buffer[:2 + length]
        return events
