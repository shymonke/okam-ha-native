import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from okam_native.vp import VPError
from okam_native.vp_wire import decode_reliable_message


KEY = bytes(range(16))
IV = bytes(range(16, 32))


def encrypted(payload, *, marker=0xFA, declared=None):
    length = len(payload) if declared is None else declared
    plain = bytes([marker]) + length.to_bytes(4, "big") + payload
    # Synthetic arbitrary padding: decoder must not assume PKCS7.
    plain += b"\x37" * (-len(plain) % 16)
    encryptor = Cipher(algorithms.AES(KEY), modes.CBC(IV)).encryptor()
    return b"\x01" + encryptor.update(plain) + encryptor.finalize()


@pytest.mark.parametrize("payload", [b"", b"hello", bytes(range(255))])
def test_plain_message(payload):
    result = decode_reliable_message(b"\0" + payload)
    assert result.prefix_bytes == 1
    assert result.payload == payload


@pytest.mark.parametrize("payload", [b"", b"hello", bytes(range(255))])
def test_encrypted_message(payload):
    result = decode_reliable_message(encrypted(payload), key=KEY, iv=IV)
    assert result.prefix_bytes == 6
    assert result.block[:6] == b"\x01\xfa" + len(payload).to_bytes(4, "big")
    assert result.payload == payload


@pytest.mark.parametrize("message", [b"", b"\2abc", b"\x81abc", b"\1", b"\1short"])
def test_invalid_envelope(message):
    with pytest.raises(VPError):
        decode_reliable_message(message, key=KEY, iv=IV)


@pytest.mark.parametrize("key,iv", [(None, IV), (KEY, None), (b"short", IV), (KEY, b"short")])
def test_cipher_material_required(key, iv):
    with pytest.raises(VPError, match="material"):
        decode_reliable_message(encrypted(b"hello"), key=key, iv=iv)


def test_marker_and_declared_length_rejected_without_values():
    for message in (encrypted(b"private-value", marker=1), encrypted(b"private-value", declared=1000)):
        with pytest.raises(VPError) as error:
            decode_reliable_message(message, key=KEY, iv=IV)
        assert "private-value" not in str(error.value)
        assert KEY.hex() not in str(error.value)


def test_payload_limit_including_encrypted_padding():
    assert decode_reliable_message(encrypted(b"12345"), key=KEY, iv=IV, max_payload_bytes=5).payload == b"12345"
    for message in (b"\0" + b"123456", encrypted(b"123456")):
        with pytest.raises(VPError):
            decode_reliable_message(message, key=KEY, iv=IV, max_payload_bytes=5)


@pytest.mark.parametrize("limit", [0, -1, 2097153, None])
def test_invalid_limit(limit):
    with pytest.raises(VPError):
        decode_reliable_message(b"\0x", max_payload_bytes=limit)


def test_relay_frames_round_trip_and_control_events():
    from okam_native.vp_wire import (VPRelayFrameReader, encode_relay_control,
                                     encode_relay_frame)

    stream = (encode_relay_control(0) + encode_relay_control(0xFFFF)
              + b"\xfe\xff" + (2000).to_bytes(2, "little")
              + encode_relay_frame(b"\x00\x01payload"))
    reader = VPRelayFrameReader()
    events = []
    # Byte-at-a-time delivery must not split or lose events.
    for index in range(len(stream)):
        events.extend(reader.feed(stream[index:index + 1]))
    assert events == [("ping", None), ("pong", None), ("size", 0x44C),
                      ("data", b"\x00\x01payload")]


def test_relay_frame_rejects_oversized_lengths():
    from okam_native.vp_wire import VPRelayFrameReader, encode_relay_frame

    with pytest.raises(VPError):
        encode_relay_frame(bytes(1500))
    with pytest.raises(VPError):
        encode_relay_frame(b"")
    with pytest.raises(VPError):
        VPRelayFrameReader().feed((1500).to_bytes(2, "little"))
