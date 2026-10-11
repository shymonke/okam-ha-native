import struct

import pytest

from okam_native.vp import VPError
from okam_native.vp_commands import make_cgi_request, read_command
from okam_native.vp_session import VPTimeout
from okam_native.vp_wire import (VPDataFragment, encode_data_fragment,
    encode_reliable_message, decode_reliable_message)
from test_vp_session import session


def connected_session():
    state, sock = session()
    state._socket = sock
    state._peer = ('192.0.2.3', 12345)
    state.connect_path = 'relay'
    return state, sock


def test_reliable_encryption_has_full_zero_padding_block():
    key, iv = bytes(range(16)), bytes(range(16, 32))
    encoded = encode_reliable_message(b'x' * 11, key=key, iv=iv)
    assert len(encoded) == 33
    assert decode_reliable_message(encoded, key=key, iv=iv).payload == b'x' * 11


def test_vp_cgi_duplicates_supplied_credentials():
    packet = make_cgi_request('get_status.cgi?', 'test-user', 'synthetic-pass')
    magic, command, size, reserved = struct.unpack('<HHHH', packet[:8])
    assert (magic, command, size, reserved) == (0x0A01, 0, len(packet)-8, 0)
    assert packet[8:] == (b'GET /get_status.cgi?loginuse=test-user&loginpas=synthetic-pass'
                          b'&user=test-user&pwd=synthetic-pass&')


@pytest.mark.parametrize('flags', [0, 0x0100])
def test_status_response_accepts_measured_header_flag(flags):
    state, sock = connected_session()
    payload = b'result=0;'
    state._channels[0].feed(0, b'\0' + struct.pack('<HHHH', 0x0a01, 0x6001,
                            len(payload), flags) + payload, header_bytes=1)
    assert read_command(state, timeout=1) == (0x6001, payload)
    assert state.counters['command_6001'] == 1
    state.close()


def test_status_response_rejects_unverified_header_flag():
    state, sock = connected_session()
    state._channels[0].feed(0, b'\0' + struct.pack('<HHHH', 0x0a01, 0x6001, 0, 2),
                            header_bytes=1)
    with pytest.raises(VPError, match='header'):
        read_command(state, timeout=1)
    state.close()


def test_write_ignores_foreign_and_uncorrelated_ack_and_wraps_relay():
    state, sock = connected_session()
    wrong = b'\x0d' + struct.pack('>HBBHHH', 1, 8, 0, 1, 0, 17)
    good = b'\x0d' + struct.pack('>HBBHHH', 1, 8, 0, 0, 0, 17)
    sock.packets = [(good, ('192.0.2.9', 12345)),
                    (wrong, state._peer), (good, state._peer)]
    state.write(0, b'test', timeout=1)
    assert sock.sent[0][0][:2] == b'\0\x0d'
    assert state.counters['foreign'] == 1
    assert state.counters['uncorrelated_ack'] == 1
    assert state.counters['write_ack'] == 1
    state.close()
    assert sock.sent[-1][0] == b'\0\x0a'


def test_encrypted_fragments_reassemble_out_of_order_and_ack_each():
    state, sock = connected_session()
    payload = b'abcd' * 400
    assembled = encode_reliable_message(payload,key=state.handshake.media_key,iv=state.handshake.media_iv)
    first = encode_data_fragment(VPDataFragment(0, 1, 0, 0, 0, 2, assembled[:1100]))
    second = encode_data_fragment(VPDataFragment(1, 1, 0, 0, 1, 2, assembled[1100:]))
    sock.packets = [(second, state._peer), (first, state._peer)]
    assert state.read_exact(1, 1600, timeout=1) == payload
    assert state._receive_sequence == 2
    assert [packet[2:4] for packet, _ in sock.sent] == [b'\0\0', b'\0\2']
    state.close()


def test_relay_heartbeat_reply_is_unwrapped_type_two():
    state, sock = connected_session()
    sock.packets = [(b'\x0b\0\1', state._peer)]
    state._pump(.1)
    assert sock.sent == [(b'\2', state._peer)]
    state.close()


def test_write_timeout_is_bounded_and_clears_pending_ack_state():
    state, sock = connected_session()
    with pytest.raises(VPTimeout):
        state.write(0, b'test', timeout=.6)
    assert not state._pending_writes
    assert len(sock.sent) <= 2
    state.close()


def test_partial_read_timeout_is_hard_failure():
    state, sock = connected_session()
    state._channels[0].feed(0, b'\0abc', header_bytes=1)
    with pytest.raises(VPError, match='partial'):
        state.read_exact(0, 4, timeout=.2)
    state.close()
