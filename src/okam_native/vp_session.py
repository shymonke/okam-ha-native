"""Bounded native CPPPP2 connection (media readiness is separate).

Only the recovered LAN challenge, requested relay slot readiness or a TCP
relay's reply to the hello is admitted as connected. None of these
establishes authentication or media readiness.
"""
from __future__ import annotations

import collections
import math
import secrets
import socket
import struct
import time

from .vp import VPError, VPInitialization, VPChannelBuffer
from .vp_handshake import DIRECTORY_PORT, RELAY_TCP_PORT, VPHandshake, decode_rendezvous
from .vp_wire import (VPDataFragment, VPFragmentAssembler, VPRelayFrameReader, FRAGMENT_BYTES,
                      RELAY_PING, RELAY_PONG, decode_data_fragment, decode_reliable_message,
                      encode_data_fragment, encode_fragment_ack, encode_relay_control,
                      encode_relay_frame, encode_reliable_message)


class VPTimeout(VPError):
    pass


class VPSession:
    def __init__(self, identity: str, initialization: VPInitialization, *,
                 socket_factory=socket.socket, clock=time.monotonic):
        self.handshake = VPHandshake(identity, initialization,
                                     secrets.randbelow(899999999) + 100000000,
                                     secrets.randbelow(89999999) + 10000000)
        self._socket_factory = socket_factory
        self._clock = clock
        self._socket = None
        self._relay_stream = None
        self._relay_reader = VPRelayFrameReader()
        self._peer = None
        self.connect_path = None
        self.counters = collections.Counter()
        self._closed = False
        self._packet_sequence = 0
        self._message_sequences = [0] * 8
        self._receive_sequence = 0
        self._receive_pending = set()
        self._assembler = VPFragmentAssembler()
        self._channels = [VPChannelBuffer(max_bytes=4 * 1024 * 1024) for _ in range(8)]
        self._acknowledged = set()
        self._pending_writes = {}

    def connect(self, *, timeout: float = 20.0) -> None:
        if (self._closed or self._socket is not None or isinstance(timeout, bool)
                or not isinstance(timeout, (int, float)) or not math.isfinite(timeout)
                or not 0 < timeout <= 60):
            raise VPError("VP connection state or timeout is invalid")
        # The decoded record contains at most three canonical IPv4 servers.
        servers = tuple((host, DIRECTORY_PORT) for host in self.handshake.initialization.peer_hosts)
        if not 1 <= len(servers) <= 3:
            raise VPError("VP connection has no directory servers")
        try:
            self._socket = self._socket_factory(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.bind(("0.0.0.0", 0))
            port = self._socket.getsockname()[1]
            deadline = self._clock() + timeout
            followup_at = self._clock() + 2.5
            followup_type = 0x2e
            followup_rounds = 0
            resend = 0.0
            candidates = set()
            punch_endpoints = set()
            relay_candidates = []
            requested_relay = None
            relay_peer = None
            tcp_relay_tried = False
            while self._clock() < deadline:
                now = self._clock()
                if now >= resend:
                    if now < followup_at:
                        for index, endpoint in enumerate(servers):
                            self._send(self.handshake.directory_request(local_port=port, server_index=index), endpoint)
                    elif followup_rounds < 8:
                        if followup_rounds >= 4:
                            followup_type = 0x2f
                        for index, endpoint in enumerate(servers):
                            self._send(self.handshake.directory_followup(followup_type, server_index=index), endpoint)
                        followup_rounds += 1
                    for endpoint in sorted(candidates):
                        self._send(self.handshake.lan_request(), endpoint)
                    if relay_peer is not None:
                        self._send(b"\x07", relay_peer)
                    elif relay_candidates:
                        requested_relay = relay_candidates[0]
                        self._send(self.handshake.relay_request(), requested_relay)
                    resend = now + 0.5
                self._socket.settimeout(max(0.001, min(0.2, deadline - self._clock())))
                try:
                    packet, source = self._socket.recvfrom(2048)
                except socket.timeout:
                    continue
                self.counters["received"] += 1
                if not packet:
                    self.counters["invalid"] += 1
                    continue
                if packet[0] == 0x28:
                    if source not in servers:
                        self.counters["foreign"] += 1
                        continue
                    try:
                        response = decode_rendezvous(packet)
                    except VPError:
                        self.counters["invalid"] += 1
                        continue
                    # The response encodes the original directory and socket.
                    if response.server_index != servers.index(source) or response.socket_index != 0:
                        self.counters["uncorrelated"] += 1
                        continue
                    self.counters[f"directory_result_{response.result}"] += 1
                    if response.endpoint is not None and response.endpoint not in punch_endpoints:
                        # FUN_10021540 result four calls FUN_10025380 with
                        # type 0x0f. That builder sends a one-byte punch at
                        # the supplied port and its fifteen neighbours on
                        # each side, once per distinct advertised endpoint.
                        if len(punch_endpoints) < 6:
                            punch_endpoints.add(response.endpoint)
                            host, target_port = response.endpoint
                            for probe_port in range(max(1, target_port - 15),
                                                    min(65535, target_port + 15) + 1):
                                self._send(b"\x0f", (host, probe_port))
                            self.counters["punch_endpoint_probed"] += 1
                    if response.relay_hosts and not tcp_relay_tried:
                        # The vendor client connects the first advertised
                        # relay over TCP as soon as a result-two reply lists
                        # relays, without a UDP slot request.
                        tcp_relay_tried = True
                        if self._connect_tcp_relay(response.relay_hosts[0], deadline):
                            return
                    for host in response.relay_hosts:
                        endpoint = (host, 65000)
                        if endpoint not in relay_candidates and len(relay_candidates) < 6:
                            relay_candidates.append(endpoint)
                    if response.advertised_host and response.advertised_host != "0.0.0.0":
                        for target_port in (65530, 65531):
                            endpoint = (response.advertised_host, target_port)
                            if len(candidates) < 6:
                                candidates.add(endpoint)
                                self._send(self.handshake.lan_request(), endpoint)
                elif packet[0] in (0x2e, 0x2f):
                    if source not in servers or self._clock() < followup_at:
                        self.counters["foreign"] += 1
                        continue
                    # Negative two-byte 0x2e replies advance the vendor's
                    # lookup to 0x2f. Positive replies carry a six-byte
                    # endpoint and need a separate, verified punch path.
                    if len(packet) != 2 or packet[1] & 8:
                        self.counters["unsupported_followup_reply"] += 1
                        continue
                    self.counters[f"followup_{packet[0]:02x}_received"] += 1
                    if packet[0] == 0x2e and followup_type == 0x2e:
                        followup_type = 0x2f
                        followup_rounds = max(followup_rounds, 4)
                        resend = 0.0
                elif packet[0] == 0x1A:
                    if source != requested_relay:
                        self.counters["foreign"] += 1
                        continue
                    # FUN_10021540's slot reply supplies a little-endian port
                    # followed by opaque metadata and a four-byte slot token.
                    if len(packet) != 8 or not int.from_bytes(packet[1:3], "little"):
                        self.counters["invalid_relay_slot"] += 1
                        continue
                    relay_peer = (source[0], int.from_bytes(packet[1:3], "little"))
                    self.counters["relay_slot_received"] += 1
                    self._send(b"\x07", relay_peer)
                elif packet[0] == 0x48:
                    if relay_peer is None or source != relay_peer:
                        self.counters["foreign"] += 1
                        continue
                    if len(packet) != 1:
                        self.counters["invalid_relay_ready"] += 1
                        continue
                    self._peer = source
                    self.connect_path = "relay"
                    self.counters["relay_ready"] += 1
                    return
                elif packet[0] == 0x11:
                    if source[0] not in {host for host, _ in candidates | punch_endpoints}:
                        self.counters["foreign"] += 1
                        continue
                    try:
                        acknowledgement = self.handshake.lan_ack(packet)
                    except VPError:
                        self.counters["invalid_challenge"] += 1
                        continue
                    # The vendor sends this acknowledgement twice.
                    self._send(acknowledgement, source)
                    self._send(acknowledgement, source)
                    self._peer = source
                    self.connect_path = "lan"
                    self.counters["challenge_matched"] += 1
                    return
                else:
                    self.counters[f"packet_type_{packet[0]:02x}"] += 1
            raise VPError("VP connection timed out")
        except OSError:
            self.close()
            raise VPError("VP connection socket failed") from None
        except Exception:
            self.close()
            raise

    def _connect_tcp_relay(self, host, deadline) -> bool:
        """FUN_1001b380: connect, send the hello, read the 4-byte reply."""
        remaining = deadline - self._clock()
        if remaining <= 0:
            return False
        stream = None
        try:
            stream = self._socket_factory(socket.AF_INET, socket.SOCK_STREAM)
            stream.settimeout(min(5.0, remaining))
            stream.connect((host, RELAY_TCP_PORT))
            self.counters["relay_tcp_connected"] += 1
            stream.sendall(self.handshake.relay_hello())
            self.counters["sent"] += 1
            reply = b""
            while len(reply) < 4:
                chunk = stream.recv(4 - len(reply))
                if not chunk:
                    break
                reply += chunk
        except OSError:
            reply = b""
        if len(reply) != 4:
            self.counters["relay_tcp_failed"] += 1
            if stream is not None:
                stream.close()
            return False
        self.counters["relay_tcp_ready"] += 1
        self._relay_stream = stream
        self._peer = (host, RELAY_TCP_PORT)
        self.connect_path = "relay-tcp"
        # The vendor client opens the framed stream with a keepalive request.
        try:
            stream.sendall(encode_relay_control(RELAY_PING))
        except OSError:
            self.close()
            raise VPError("VP TCP relay socket failed") from None
        return True

    def _send(self, packet, endpoint):
        self._socket.sendto(packet, endpoint)
        self.counters["sent"] += 1

    def _send_peer(self, packet):
        if self._closed or self._peer is None:
            raise VPError("VP session is not connected")
        if self.connect_path == "relay-tcp":
            # TCP relay frames carry the 0x0d packet without its type byte.
            if not packet or packet[0] != 0x0D:
                raise VPError("VP TCP relay carries data packets only")
            self._relay_stream.sendall(encode_relay_frame(packet[1:]))
            self.counters["sent"] += 1
            return
        self._send((b"\0" if self.connect_path == "relay" else b"") + packet, self._peer)

    def write(self, channel: int, payload: bytes, *, timeout: float = 5.0) -> None:
        if type(channel) is not int or not 0 <= channel < 8:
            raise VPError("VP channel is invalid")
        deadline = self._deadline(timeout)
        assembled = encode_reliable_message(payload, key=self.handshake.media_key,
                                            iv=self.handshake.media_iv)
        count = (len(assembled) + FRAGMENT_BYTES - 1) // FRAGMENT_BYTES
        message = self._message_sequences[channel]
        packets = {}
        for index in range(count):
            sequence = self._packet_sequence
            fragment = VPDataFragment(sequence, channel, 0, message, index, count,
                                      assembled[index * FRAGMENT_BYTES:(index + 1) * FRAGMENT_BYTES])
            packets[sequence] = encode_data_fragment(fragment)
            self._pending_writes[sequence] = message
            self._packet_sequence = (sequence + 1) % 0xFFFF
        self._message_sequences[channel] = (message + 1) % 0xFFFF
        resend = 0.0
        try:
            while packets:
                if self._clock() >= deadline:
                    raise VPTimeout("VP channel write timed out")
                if self._clock() >= resend:
                    for packet in packets.values():
                        self._send_peer(packet)
                    # TCP delivers reliably, so fragments go out once.
                    resend = math.inf if self.connect_path == "relay-tcp" else self._clock() + .5
                self._pump(min(.2, deadline - self._clock()))
                for sequence in tuple(packets):
                    if sequence in self._acknowledged:
                        del packets[sequence]
                        self._acknowledged.discard(sequence)
        except OSError:
            raise VPError("VP session socket failed") from None
        finally:
            for sequence in tuple(self._pending_writes):
                if self._pending_writes[sequence] == message:
                    del self._pending_writes[sequence]

    def _deadline(self, timeout):
        if (self._closed or self._peer is None or isinstance(timeout, bool)
                or not isinstance(timeout, (int, float)) or not math.isfinite(timeout)
                or not 0 < timeout <= 60):
            raise VPError("VP session state or timeout is invalid")
        return self._clock() + timeout

    def read_exact(self, channel: int, count: int, *, timeout: float) -> bytes:
        if (type(channel) is not int or not 0 <= channel < 8
                or type(count) is not int or not 0 <= count <= 2 * 1024 * 1024):
            raise VPError("VP channel read is invalid")
        deadline = self._deadline(timeout)
        result = bytearray()
        while len(result) < count:
            result.extend(self._channels[channel].read(count - len(result)))
            if len(result) == count:
                return bytes(result)
            if self._clock() >= deadline:
                if result:
                    raise VPError("VP partial channel read timed out")
                raise VPTimeout("VP channel read timed out")
            try:
                self._pump(min(.2, deadline - self._clock()))
            except OSError:
                raise VPError("VP session socket failed") from None
        return bytes(result)

    def _pump(self, timeout):
        if self.connect_path == "relay-tcp":
            self._pump_relay_stream(timeout)
            return
        self._socket.settimeout(max(.001, timeout))
        try:
            packet, source = self._socket.recvfrom(2048)
        except socket.timeout:
            return
        self.counters["received"] += 1
        if source != self._peer:
            self.counters["foreign"] += 1
            return
        self._handle_peer_packet(packet)

    def _pump_relay_stream(self, timeout):
        self._relay_stream.settimeout(max(.001, timeout))
        try:
            data = self._relay_stream.recv(65536)
        except socket.timeout:
            return
        if not data:
            raise VPError("VP TCP relay closed the session")
        for kind, value in self._relay_reader.feed(data):
            if kind == "ping":
                self._relay_stream.sendall(encode_relay_control(RELAY_PONG))
                self.counters["relay_ping_received"] += 1
            elif kind == "pong":
                self.counters["relay_pong_received"] += 1
            elif kind == "size":
                self.counters["relay_size_hint"] += 1
            else:
                self.counters["received"] += 1
                self._handle_peer_packet(b"\x0d" + value)

    def _handle_peer_packet(self, packet):
        if not packet:
            self.counters["invalid"] += 1
            return
        if packet[0] == 0x0B and len(packet) == 3:
            if self.connect_path == "relay":
                self._send(b"\2", self._peer)
            else:
                self._send_peer(b"\x0c")
            self.counters["heartbeat_received"] += 1
            return
        if packet[0] == 0x0A:
            raise VPError("VP peer closed the session")
        if packet[0] != 0x0D:
            self.counters[f"packet_type_{packet[0]:02x}"] += 1
            return
        if len(packet) >= 9 and packet[3] == 8:
            message, sequence = struct.unpack(">HH", packet[5:9])
            if self._pending_writes.get(sequence) == message:
                self._acknowledged.add(sequence)
                self.counters["write_ack"] += 1
            else:
                self.counters["uncorrelated_ack"] += 1
            return
        fragment = decode_data_fragment(packet)
        distance = (fragment.packet_sequence - self._receive_sequence) % 0xFFFF
        if distance < 0x8000:
            if distance >= 1024:
                raise VPError("VP packet reorder window exceeded")
            self._receive_pending.add(fragment.packet_sequence)
            while self._receive_sequence in self._receive_pending:
                self._receive_pending.remove(self._receive_sequence)
                self._receive_sequence = (self._receive_sequence + 1) % 0xFFFF
        self._send_peer(encode_fragment_ack(fragment, next_packet=self._receive_sequence))
        self.counters[f"channel{fragment.channel}_packets"] += 1
        self.counters[f"channel{fragment.channel}_bytes"] += len(fragment.payload)
        assembled = self._assembler.feed(fragment)
        if assembled is not None:
            message = decode_reliable_message(assembled, key=self.handshake.media_key,
                                              iv=self.handshake.media_iv)
            self._channels[fragment.channel].feed(fragment.message_sequence, message.block,
                                                   header_bytes=message.prefix_bytes)

    def close(self) -> None:
        if self._socket is not None and self._peer is not None and self.connect_path != "relay-tcp":
            try:
                # FUN_1002d630 invokes FUN_1001af60 with packet type ten.
                self._send_peer(b"\x0a")
                self.counters["close_sent"] += 1
            except (OSError, VPError):
                self.counters["close_failed"] += 1
        sock, self._socket = self._socket, None
        stream, self._relay_stream = self._relay_stream, None
        self._peer = None
        self._closed = True
        if sock is not None:
            sock.close()
        if stream is not None:
            stream.close()
        self._assembler.clear()
        for channel in self._channels:
            channel.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
