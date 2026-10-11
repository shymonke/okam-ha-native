"""Pure packet builders for the recovered CPPPP2 connection handshake.

No sockets are opened here. The caller must validate response sources and
track the active request before interpreting an unauthenticated response.
"""
from __future__ import annotations

import ipaddress
import re
import struct
from dataclasses import dataclass, field

from .vp import VPError, VPInitialization, _initialization_material, _md5

PROTOCOL_VERSION = 0x134FE64
DIRECTORY_PORT = 65200
# FUN_1001b380 connects the TCP relay at this port on its primary branch.
RELAY_TCP_PORT = 0xFFF6


@dataclass(frozen=True)
class VPHandshake:
    identity: str = field(repr=False)
    initialization: VPInitialization = field(repr=False)
    attempt_id: int = field(repr=False)
    nonce: int = field(repr=False)

    def __post_init__(self):
        normalized = self.identity.replace("-", "") if isinstance(self.identity, str) else ""
        if (not re.fullmatch(r"[A-Z0-9]{4}[0-9]{8}[A-Z]{5}", normalized)
                or not isinstance(self.initialization, VPInitialization)
                or type(self.attempt_id) is not int or not 100000000 <= self.attempt_id <= 999999998
                or type(self.nonce) is not int or not 10000000 <= self.nonce <= 99999998):
            raise VPError("VP handshake inputs are invalid")
        if (len(self.initialization.auth_digest) != 16
                or not 0 <= self.initialization.record_number <= 0xFFFFFFFF):
            raise VPError("VP handshake inputs are invalid")

    @property
    def media_key(self) -> bytes:
        """FUN_1002bcc0: nonce text, per-record digest, validation marker."""
        marker = _initialization_material()[3]
        return _md5(str(self.nonce).encode("ascii") + self.initialization.auth_digest + marker)

    @property
    def media_iv(self) -> bytes:
        return _initialization_material()[1]

    def _encrypted_identity(self, packet_type: int) -> bytes:
        normalized = self.identity.replace("-", "")
        plain = (struct.pack("<II", self.initialization.record_number, self.attempt_id)
                 + normalized[:4].encode("ascii")
                 + struct.pack("<I", int(normalized[4:12])))
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        cipher = Cipher(algorithms.AES(self.initialization.auth_digest), modes.CBC(self.media_iv))
        encryptor = cipher.encryptor()
        return bytes([packet_type]) + encryptor.update(plain) + encryptor.finalize()

    def directory_request(self, *, local_port: int, public_ip: str = "0.0.0.0",
                          server_index: int = 0, socket_index: int = 0) -> bytes:
        """FUN_10025740 / FUN_10024cf0's 33-byte rendezvous request."""
        if (type(local_port) is not int or not 1 <= local_port <= 65535
                or type(server_index) is not int or not 0 <= server_index < 3
                or type(socket_index) is not int or socket_index not in (0, 1)):
            raise VPError("VP rendezvous fields are invalid")
        try:
            address = ipaddress.IPv4Address(public_ip).packed
        except (ipaddress.AddressValueError, TypeError):
            raise VPError("VP rendezvous address is invalid") from None
        flags = (server_index << 4) | (socket_index << 6)
        return (self._encrypted_identity(0x28) + bytes([flags])
                + struct.pack("<IH", PROTOCOL_VERSION, local_port) + address
                + struct.pack("<I", self.nonce) + b"\0")

    def lan_request(self) -> bytes:
        """The directory response's advertised host accepts type 5 probes."""
        return self._encrypted_identity(5)

    def relay_hello(self) -> bytes:
        """FUN_1001b380: 22-byte TCP relay hello sent right after connect.

        Type 0x15 and subtype 0x0b precede the record number, identity prefix,
        identity number and attempt, encrypted like the UDP identity block,
        then the clear protocol version. The 26-byte form's trailing field is
        omitted on the observed branch.
        """
        normalized = self.identity.replace("-", "")
        plain = (struct.pack("<I", self.initialization.record_number)
                 + normalized[:4].encode("ascii")
                 + struct.pack("<II", int(normalized[4:12]), self.attempt_id))
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        cipher = Cipher(algorithms.AES(self.initialization.auth_digest), modes.CBC(self.media_iv))
        encryptor = cipher.encryptor()
        return (b"\x15\x0b" + encryptor.update(plain) + encryptor.finalize()
                + struct.pack("<I", PROTOCOL_VERSION))

    def relay_request(self) -> bytes:
        """FUN_10024a30 requests a relay slot with the protocol version."""
        return self._encrypted_identity(0x1A) + struct.pack("<I", PROTOCOL_VERSION)

    def directory_followup(self, packet_type: int, *, server_index: int = 0) -> bytes:
        """FUN_10025740: 22-byte UDP followup from FUN_1001f870.

        The send length includes eight encrypted bytes, followed by flags;
        it does not include the full encrypted block built in scratch space.
        """
        if (type(packet_type) is not int or packet_type not in (0x2E, 0x2F)
                or type(server_index) is not int or not 0 <= server_index < 3):
            raise VPError("VP directory followup fields are invalid")
        normalized = self.identity.replace("-", "")
        identity = normalized[:4].encode("ascii") + struct.pack("<I", int(normalized[4:12]))
        return (bytes([packet_type]) + identity + struct.pack("<I", self.attempt_id)
                + self._encrypted_identity(packet_type)[1:9] + bytes([server_index << 4]))

    def lan_ack(self, packet: bytes) -> bytes:
        """Echo the verified attempt and nonce after a 0x11 challenge.

        Nonzero challenge modes require a different transport and are rejected.
        """
        if not isinstance(packet, bytes) or len(packet) != 15 or packet[0] != 0x11:
            raise VPError("VP LAN challenge is invalid")
        attempt, nonce = struct.unpack("<II", packet[1:9])
        if attempt != self.attempt_id or nonce != self.nonce or packet[10] != 0:
            raise VPError("VP LAN challenge does not match")
        return bytes([0x11, packet[9]]) + struct.pack("<III", attempt, nonce, PROTOCOL_VERSION)


@dataclass(frozen=True)
class VPRendezvous:
    result: int
    server_index: int
    socket_index: int
    endpoint: tuple[str, int] | None = field(repr=False)
    advertised_host: str | None = field(repr=False)
    relay_hosts: tuple[str, ...] = field(default=(), repr=False)


def decode_rendezvous(packet: bytes) -> VPRendezvous:
    """Decode only the observed result-zero and result-four response forms."""
    if not isinstance(packet, bytes) or len(packet) < 2 or packet[0] != 0x28:
        raise VPError("VP rendezvous response is invalid")
    flags = packet[1]
    result = flags & 7
    server_index = (flags >> 3) & 3
    socket_index = (flags >> 5) & 1
    if server_index >= 3:
        raise VPError("VP rendezvous response is invalid")
    if result == 4:
        if len(packet) != 8:
            raise VPError("VP rendezvous response length is invalid")
        port = int.from_bytes(packet[2:4], "little")
        host = str(ipaddress.IPv4Address(packet[4:8]))
        if not port or host == "0.0.0.0":
            raise VPError("VP rendezvous endpoint is invalid")
        return VPRendezvous(result, server_index, socket_index, (host, port), None)
    if result in (0, 2):
        if (len(packet) < 14 or (len(packet) - 14) % 5 or len(packet) > 44
                or (result == 0 and len(packet) != 14)):
            raise VPError("VP rendezvous response length is invalid")
        host = str(ipaddress.IPv4Address(packet[2:6]))
        # Result two appends at most six five-byte relay records. The fifth
        # byte is opaque metadata; relay slot requests use port 65000.
        relays = tuple(str(ipaddress.IPv4Address(packet[offset:offset + 4]))
                       for offset in range(14, len(packet), 5))
        if any(value == "0.0.0.0" for value in relays):
            raise VPError("VP rendezvous relay is invalid")
        return VPRendezvous(result, server_index, socket_index, None, host, relays)
    # Offline, maximum sessions and other error results contain no endpoint
    # needed by this implementation; don't guess an unverified body layout.
    return VPRendezvous(result, server_index, socket_index, None, None)
