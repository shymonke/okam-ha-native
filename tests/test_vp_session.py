import socket
import struct

import pytest

from okam_native.vp import VPError, VPInitialization
from okam_native.vp_session import VPSession
from okam_native.vp_wire import (VPDataFragment, decode_data_fragment,
                                 encode_data_fragment, encode_fragment_ack)


class Clock:
    now = 0.0

    def __call__(self):
        return self.now


class DatagramSocket:
    def __init__(self, clock):
        self.clock = clock
        self.packets = []
        self.sent = []
        self.closed = False

    def bind(self, address):
        assert address == ('0.0.0.0', 0)

    def getsockname(self):
        return ('0.0.0.0', 54321)

    def settimeout(self, timeout):
        self.timeout = timeout

    def recvfrom(self, size):
        if self.packets:
            return self.packets.pop(0)
        self.clock.now += self.timeout
        raise socket.timeout()

    def sendto(self, packet, endpoint):
        self.sent.append((packet, endpoint))

    def close(self):
        self.closed = True


def session():
    clock = Clock()
    sock = DatagramSocket(clock)
    init = VPInitialization(12345678, 'test', (), ('192.0.2.1',), 'ANY', bytes(range(16)))
    # TCP relay connects are refused so these tests exercise the UDP paths.
    factory = lambda _family, kind: sock if kind == socket.SOCK_DGRAM else StreamSocket(fail=True)
    state = VPSession('TEST12345678ABCDE', init, socket_factory=factory, clock=clock)
    return state, sock


def directory(host=(192, 0, 2, 2), flags=0):
    return b'\x28' + bytes([flags]) + bytes(host) + bytes(8)


def challenge(state, *, nonce=None):
    return (b'\x11' + struct.pack('<II', state.handshake.attempt_id,
                                 state.handshake.nonce if nonce is None else nonce)
            + b'\7\0' + bytes(4))


def test_connect_requires_correlated_challenge_and_sends_ack_twice():
    state, sock = session()
    sock.packets = [(directory(), ('192.0.2.1', 65200)),
                    (challenge(state, nonce=1), ('192.0.2.2', 65530)),
                    (challenge(state), ('192.0.2.2', 65531))]
    state.connect(timeout=1)
    assert state.connect_path == 'lan'
    assert state.counters['invalid_challenge'] == 1
    assert state.counters['challenge_matched'] == 1
    assert sock.sent[-1] == sock.sent[-2]
    assert sock.sent[-1][1] == ('192.0.2.2', 65531)
    state.close()
    state.close()
    assert sock.closed


def test_foreign_or_wrong_socket_directory_does_not_authorize_peer():
    state, sock = session()
    sock.packets = [(directory(), ('192.0.2.9', 65200)),
                    (directory(flags=32), ('192.0.2.1', 65200)),
                    (challenge(state), ('192.0.2.2', 65530))]
    with pytest.raises(VPError, match='timed out'):
        state.connect(timeout=1)
    assert sock.closed
    assert state.connect_path is None
    assert state.counters['foreign'] == 2
    assert state.counters['uncorrelated'] == 1


def test_directory_success_alone_is_not_connection():
    state, sock = session()
    sock.packets = [(directory(), ('192.0.2.1', 65200))]
    with pytest.raises(VPError, match='timed out'):
        state.connect(timeout=1)
    assert state.counters['directory_result_0'] == 1
    assert len(sock.sent) < 20
    assert sock.closed


def result_four(host=(192, 0, 2, 4), port=23456):
    return b'\x28\4' + struct.pack('<H', port) + bytes(host)


def test_result_four_punches_once_and_still_requires_matching_challenge():
    state, sock = session()
    response = result_four()
    sock.packets = [(response, ('192.0.2.1', 65200)),
                    (response, ('192.0.2.1', 65200)),
                    (challenge(state, nonce=1), ('192.0.2.4', 23457)),
                    (challenge(state), ('192.0.2.4', 23457))]
    state.connect(timeout=1)
    probes = [(packet, endpoint) for packet, endpoint in sock.sent if packet == b'\x0f']
    assert probes == [(b'\x0f', ('192.0.2.4', port)) for port in range(23441, 23472)]
    assert state.counters['punch_endpoint_probed'] == 1
    assert state.counters['invalid_challenge'] == 1
    assert state.connect_path == 'lan'
    state.close()


@pytest.mark.parametrize('port', [1, 65535])
def test_result_four_port_range_is_bounded_and_reply_alone_cannot_connect(port):
    state, sock = session()
    sock.packets = [(result_four(port=port), ('192.0.2.1', 65200))]
    with pytest.raises(VPError, match='timed out'):
        state.connect(timeout=1)
    probes = [endpoint for packet, endpoint in sock.sent if packet == b'\x0f']
    assert len(probes) == 16
    assert all(1 <= endpoint[1] <= 65535 for endpoint in probes)
    assert state.connect_path is None
    assert sock.closed


def test_foreign_result_four_does_not_trigger_punches():
    state, sock = session()
    sock.packets = [(result_four(), ('192.0.2.9', 65200))]
    with pytest.raises(VPError, match='timed out'):
        state.connect(timeout=1)
    assert not any(packet == b'\x0f' for packet, _ in sock.sent)


def test_result_two_enables_direct_probes():
    state, sock = session()
    packet = directory(flags=2) + bytes([192, 0, 2, 3, 0])
    sock.packets = [(packet, ('192.0.2.1', 65200)),
                    (challenge(state), ('192.0.2.2', 65530))]
    state.connect(timeout=1)
    assert state.connect_path == 'lan'
    assert any(data[0] == 5 for data, _ in sock.sent)
    state.close()


def test_relay_ready_requires_requested_slot_and_assigned_endpoint():
    state, sock = session()
    packet = directory(flags=2) + bytes([192, 0, 2, 3, 0])
    slot = b'\x1a' + struct.pack('<H', 12345) + bytes(5)
    original_recv = sock.recvfrom
    phase = 0
    def receive(size):
        nonlocal phase
        if phase == 0:
            phase = 1
            return packet, ('192.0.2.1', 65200)
        if phase == 1 and any(data[0] == 0x1a for data, _ in sock.sent):
            phase = 2
            sock.packets = [(b'\x48', ('192.0.2.3', 12346)),
                            (b'\x48\0', ('192.0.2.3', 12345)),
                            (b'\x48', ('192.0.2.3', 12345))]
            return slot, ('192.0.2.3', 65000)
        return original_recv(size)
    sock.recvfrom = receive
    state.connect(timeout=2)
    assert state.connect_path == 'relay'
    assert state.counters['relay_slot_received'] == 1
    assert state.counters['foreign'] == 1
    assert state.counters['invalid_relay_ready'] == 1
    assert (b'\7', ('192.0.2.3', 12345)) in sock.sent
    state.close()


def test_unsolicited_relay_slot_or_ready_cannot_connect():
    state, sock = session()
    sock.packets = [(b'\x1a' + struct.pack('<H', 12345) + bytes(5), ('192.0.2.3', 65000)),
                    (b'\x48', ('192.0.2.3', 12345))]
    with pytest.raises(VPError, match='timed out'):
        state.connect(timeout=1)
    assert state.connect_path is None
    assert sock.closed
    assert state.counters['foreign'] == 2


def test_followup_advances_on_directory_reply_and_is_bounded():
    state, sock = session()
    original_receive = sock.recvfrom
    delivered = False
    def receive(size):
        nonlocal delivered
        if not delivered and any(data[0] == 0x2e for data, _ in sock.sent):
            delivered = True
            return b'\x2e\0', ('192.0.2.1', 65200)
        return original_receive(size)
    sock.recvfrom = receive
    with pytest.raises(VPError, match='timed out'):
        state.connect(timeout=10)
    kinds = [data[0] for data, _ in sock.sent]
    assert kinds.count(0x28) == 5
    assert kinds.count(0x2e) == 1
    assert kinds.count(0x2f) == 4
    assert state.counters['followup_2e_received'] == 1
    assert state.connect_path is None
    assert sock.closed


def test_unsolicited_followup_does_not_advance_lookup():
    state, sock = session()
    sock.packets = [(b'\x2e\0', ('192.0.2.9', 65200)),
                    (b'\x2e\0', ('192.0.2.1', 65200))]
    with pytest.raises(VPError, match='timed out'):
        state.connect(timeout=1)
    assert state.counters['foreign'] == 2
    assert not any(data[0] == 0x2f for data, _ in sock.sent)


@pytest.mark.parametrize('timeout', [True, 0, -1, 61, float('inf'), float('nan')])
def test_invalid_timeout_opens_no_socket(timeout):
    state, sock = session()
    with pytest.raises(VPError):
        state.connect(timeout=timeout)
    assert not sock.sent


def test_socket_failure_is_sanitized_and_closed():
    state, sock = session()
    def fail(*_):
        raise OSError('private endpoint')
    sock.sendto = fail
    with pytest.raises(VPError, match='socket failed') as error:
        state.connect(timeout=1)
    assert 'private' not in str(error.value)
    assert sock.closed


def test_closed_session_cannot_reconnect():
    state, sock = session()
    state.close()
    with pytest.raises(VPError):
        state.connect(timeout=1)


class StreamSocket:
    def __init__(self, reply=b"\x01\x02\x03\x04", fail=False):
        self.reply = bytearray(reply)
        self.fail = fail
        self.sent = b""
        self.endpoint = None
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, endpoint):
        if self.fail:
            raise ConnectionRefusedError()
        self.endpoint = endpoint

    def sendall(self, data):
        self.sent += data

    def recv(self, size):
        chunk = bytes(self.reply[:min(size, 1)])
        del self.reply[:len(chunk)]
        return chunk

    def close(self):
        self.closed = True


def tcp_session(stream):
    clock = Clock()
    sock = DatagramSocket(clock)
    init = VPInitialization(12345678, 'test', (), ('192.0.2.1',), 'ANY', bytes(range(16)))
    def factory(_family, kind):
        return stream if kind == socket.SOCK_STREAM else sock
    state = VPSession('TEST12345678ABCDE', init, socket_factory=factory, clock=clock)
    return state, sock


def relay_directory():
    return directory(flags=2) + bytes([192, 0, 2, 3, 0]) + bytes([192, 0, 2, 4, 0])


def test_tcp_relay_hello_reply_connects_to_first_relay():
    stream = StreamSocket()
    state, sock = tcp_session(stream)
    sock.packets = [(relay_directory(), ('192.0.2.1', 65200))]
    state.connect(timeout=2)
    assert state.connect_path == 'relay-tcp'
    assert stream.endpoint == ('192.0.2.3', 0xFFF6)
    assert stream.sent == state.handshake.relay_hello() + b'\0\0'
    assert state.counters['relay_tcp_ready'] == 1
    # The TCP relay replaces the UDP slot request on the vendor's path.
    assert not any(data[0] == 0x1a for data, _ in sock.sent)
    state.close()
    assert stream.closed and sock.closed


def test_tcp_relay_failure_falls_back_to_udp_slot_request():
    for stream in (StreamSocket(fail=True), StreamSocket(reply=b'\x01\x02')):
        state, sock = tcp_session(stream)
        sock.packets = [(relay_directory(), ('192.0.2.1', 65200))]
        with pytest.raises(VPError, match='timed out'):
            state.connect(timeout=1)
        assert state.connect_path is None
        assert state.counters['relay_tcp_failed'] == 1
        assert stream.closed
        assert any(data[0] == 0x1a for data, _ in sock.sent)


class RelayStream(StreamSocket):
    """A connected TCP relay: hello reply, then scripted inbound frames."""

    def __init__(self, inbound=b''):
        super().__init__()
        self.inbound = bytearray(inbound)
        self.remote_closed = False

    def recv(self, size):
        if self.reply:
            return super().recv(size)
        if not self.inbound:
            if self.remote_closed:
                return b''
            raise socket.timeout()
        chunk = bytes(self.inbound[:size])
        del self.inbound[:len(chunk)]
        return chunk


def connected_relay(inbound=b''):
    stream = RelayStream(inbound)
    state, sock = tcp_session(stream)
    sock.packets = [(relay_directory(), ('192.0.2.1', 65200))]
    state.connect(timeout=2)
    assert state.connect_path == 'relay-tcp'
    hello = state.handshake.relay_hello()
    assert stream.sent[:len(hello)] == hello
    # The framed stream opens with a keepalive request, like the vendor.
    assert stream.sent[len(hello):] == b'\0\0'
    stream.sent = b''
    return state, stream


def test_tcp_relay_write_sends_one_framed_fragment_and_accepts_ack():
    ack = struct.pack('>HBBHH', 1, 8, 0, 0, 0)
    state, stream = connected_relay(struct.pack('<H', len(ack)) + ack)
    state.write(0, b'payload', timeout=1)
    assert state.counters['write_ack'] == 1
    length = struct.unpack('<H', stream.sent[:2])[0]
    frame = stream.sent[2:2 + length]
    # One frame only: TCP needs no resend, and the 0x0d type byte is dropped.
    assert len(stream.sent) == 2 + length
    assert decode_data_fragment(b'\x0d' + frame).channel == 0
    state.close()


def test_tcp_relay_receive_answers_ping_and_acks_framed_data():
    fragment = VPDataFragment(0, 1, 0, 0, 0, 1, b'\0hello')
    data = encode_data_fragment(fragment)[1:]
    state, stream = connected_relay(b'\0\0' + struct.pack('<H', len(data)) + data)
    assert state.read_exact(1, 5, timeout=1) == b'hello'
    ack = encode_fragment_ack(fragment, next_packet=1)[1:]
    assert stream.sent == b'\xff\xff' + struct.pack('<H', len(ack)) + ack
    assert state.counters['relay_ping_received'] == 1
    state.close()


def test_tcp_relay_remote_close_and_non_data_sends_fail_closed():
    state, stream = connected_relay()
    with pytest.raises(VPError, match='data packets only'):
        state._send_peer(b'\x0a')
    stream.remote_closed = True
    with pytest.raises(VPError, match='closed the session'):
        state.read_exact(0, 1, timeout=1)
    state.close()
