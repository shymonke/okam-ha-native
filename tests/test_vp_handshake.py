import hashlib
import struct

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from okam_native.vp import VPError, VPInitialization, _initialization_material
from okam_native.vp_handshake import VPHandshake, decode_rendezvous, PROTOCOL_VERSION


def handshake(**changes):
    args = dict(identity="TEST12345678ABCDE",
                initialization=VPInitialization(12345678, "test", (), ("192.0.2.1",), "ANY", bytes(range(16))),
                attempt_id=123456789, nonce=12345678)
    args.update(changes)
    return VPHandshake(**args)


def test_directory_request_layout_and_cipher_input():
    state = handshake()
    packet = state.directory_request(local_port=54321, server_index=2, socket_index=1)
    assert len(packet) == 33
    assert packet[0] == 0x28
    decryptor = Cipher(algorithms.AES(bytes(range(16))), modes.CBC(state.media_iv)).decryptor()
    assert decryptor.update(packet[1:17]) + decryptor.finalize() == (
        struct.pack("<II", 12345678, 123456789) + b"TEST" + struct.pack("<I", 12345678))
    assert packet[17:] == b"\x60" + struct.pack("<IH", PROTOCOL_VERSION, 54321) + bytes(4) + struct.pack("<I", 12345678) + b"\0"
    assert state.lan_request() == b"\5" + packet[1:17]


def test_nonce_bound_media_key_and_secret_repr():
    state = handshake()
    expected = hashlib.md5(b"12345678" + bytes(range(16)) + _initialization_material()[3], usedforsecurity=False).digest()
    assert state.media_key == expected
    assert handshake(nonce=12345679).media_key != expected
    assert "TEST" not in repr(state)
    assert "12345678" not in repr(state)


def test_lan_challenge_correlates_attempt_and_nonce():
    state = handshake()
    challenge = b"\x11" + struct.pack("<II", state.attempt_id, state.nonce) + b"\7\0" + bytes(4)
    assert state.lan_ack(challenge) == b"\x11\7" + struct.pack("<III", state.attempt_id, state.nonce, PROTOCOL_VERSION)
    for bad in (challenge[:-1], challenge[:1] + bytes(8) + challenge[9:], challenge[:10] + b"\1" + challenge[11:]):
        with pytest.raises(VPError):
            state.lan_ack(bad)


def test_rendezvous_endpoint_and_host_metadata():
    result = decode_rendezvous(b"\x28\x14" + struct.pack("<H", 12345) + bytes([192, 0, 2, 1]))
    assert (result.result, result.server_index, result.socket_index) == (4, 2, 0)
    assert result.endpoint == ("192.0.2.1", 12345)
    assert "192.0.2.1" not in repr(result)
    assert decode_rendezvous(b"\x28\0" + bytes([192, 0, 2, 2]) + bytes(8)).advertised_host == "192.0.2.2"


def test_result_two_includes_advertised_host_and_bounded_relay_list():
    packet = b"\x28\2" + bytes([192, 0, 2, 2]) + bytes(8) + bytes([192, 0, 2, 3, 0])
    decoded = decode_rendezvous(packet)
    assert decoded.result == 2
    assert decoded.advertised_host == "192.0.2.2"
    assert decoded.relay_hosts == ("192.0.2.3",)
    assert "192.0.2" not in repr(decoded)
    for invalid in (packet[:-1], packet[:14] + bytes(5), packet[:14] + packet[14:] * 7):
        with pytest.raises(VPError):
            decode_rendezvous(invalid)


def test_relay_request_uses_same_encrypted_identity_and_version():
    state = handshake()
    assert state.relay_request() == b"\x1a" + state.lan_request()[1:] + struct.pack("<I", PROTOCOL_VERSION)


@pytest.mark.parametrize('kind', [0x2e, 0x2f])
def test_directory_followup_layout_and_truncated_encrypted_block(kind):
    state = handshake()
    packet = state.directory_followup(kind, server_index=2)
    assert len(packet) == 22
    assert packet[:13] == bytes([kind]) + b'TEST' + struct.pack('<II', 12345678, state.attempt_id)
    cipher = Cipher(algorithms.AES(bytes(range(16))), modes.CBC(state.media_iv)).encryptor()
    plain = struct.pack('<II', 12345678, state.attempt_id) + b'TEST' + struct.pack('<I', 12345678)
    expected = cipher.update(plain) + cipher.finalize()
    assert packet[13:21] == expected[:8]
    assert packet[21] == 0x20


@pytest.mark.parametrize('kind,index', [(0x28, 0), (True, 0), (0x2e, -1), (0x2f, 3), (0x2e, True)])
def test_directory_followup_rejects_unverified_modes(kind, index):
    with pytest.raises(VPError):
        handshake().directory_followup(kind, server_index=index)


@pytest.mark.parametrize("packet", [b"", b"\x28", b"\x28\x1c" + bytes(6), b"\x28\4" + bytes(6),
                                      b"\x28\4" + bytes(5), b"\x28\0" + bytes(13)])
def test_rendezvous_malformed(packet):
    with pytest.raises(VPError):
        decode_rendezvous(packet)


@pytest.mark.parametrize("changes", [{"identity": "bad"}, {"nonce": True}, {"nonce": 999}, {"attempt_id": 0}])
def test_handshake_inputs(changes):
    with pytest.raises(VPError):
        handshake(**changes)


def test_tcp_relay_hello_layout_and_cipher_input():
    state = handshake()
    packet = state.relay_hello()
    assert len(packet) == 22
    assert packet[:2] == b"\x15\x0b"
    decryptor = Cipher(algorithms.AES(bytes(range(16))), modes.CBC(state.media_iv)).decryptor()
    # Same fields as the UDP identity block, reordered: record, identity
    # prefix, identity number, attempt.
    assert decryptor.update(packet[2:18]) + decryptor.finalize() == (
        struct.pack("<I", 12345678) + b"TEST" + struct.pack("<II", 12345678, 123456789))
    assert packet[18:] == struct.pack("<I", PROTOCOL_VERSION)
