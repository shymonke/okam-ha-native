"""Synthetic initialization inputs only; never captured camera records."""
import hashlib

import pytest

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from okam_native.vp import (VPError, VPChannelBuffer, VPVideoFrames, MAX_VIDEO_BYTES,
                            _initialization_material, decode_initialization,
                            split_connection_input)


def test_connection_suffix_is_the_record_not_global_initialization():
    encrypted = record()
    parsed = split_connection_input("TEST-CAMERA%%" + encrypted)
    assert parsed.transport_id == "TEST-CAMERA"
    assert parsed.initialization_record == encrypted
    assert decode_initialization(parsed.initialization_record).record_number == 12345678
    assert "TEST-CAMERA" not in repr(parsed)
    assert encrypted not in repr(parsed)


def test_connection_split_preserves_suffix_and_absent_record():
    assert split_connection_input("TEST%%one%%two").initialization_record == "one%%two"
    assert split_connection_input("TEST").initialization_record == ""
    assert split_connection_input("TEST%%").initialization_record == ""
    assert len(split_connection_input("x" * 63 + "%%" + "y" * 1023).initialization_record) == 1023


@pytest.mark.parametrize("value", [None, "", "%%record", "x" * 64,
                                  "TEST%%" + "y" * 1024, "TEST\0hidden", "TEST\n", "TESTé"])
def test_connection_input_rejects_unsafe_fields_without_echo(value):
    with pytest.raises(VPError) as error:
        split_connection_input(value)
    assert str(error.value).startswith("VP connection")


def record(*, fields=None, suffix="", checksum=False):
    key, iv, _, marker = _initialization_material()
    parts = fields or [marker.decode(), "das", "12345678", "relay.example", "192.0.2.1", "ANY"]
    if checksum:
        signed_fields = [parts[1], str(int(parts[2])), *parts[3:]]
        signature = hashlib.md5(",".join(signed_fields).encode() + b"tests", usedforsecurity=False)
        parts = [*parts, signature.hexdigest().upper()[8:17]]
    plain = ",".join(parts).encode()
    plain += bytes(16 - len(plain) % 16)
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    encrypted = encryptor.update(plain) + encryptor.finalize()
    return "DAS-" + encrypted.hex().upper() + (":" + suffix if suffix else "")


def test_record_decodes_without_vendor_runtime_and_hides_fields():
    decoded = decode_initialization(record())
    assert decoded.record_number == 12345678
    assert decoded.rendezvous_hosts == ("relay.example",)
    assert decoded.peer_hosts == ("192.0.2.1",)
    assert decoded.family_rule == "ANY"
    assert len(decoded.auth_digest) == 16
    assert repr(decoded) == "VPInitialization()"


def test_auth_digest_uses_second_hex_chain_salt():
    # Model the initializer's overlapping local buffers independently. The
    # authentication salt is local_98 after its second hex conversion.
    first_hex = hashlib.md5(bytes(61), usedforsecurity=False).hexdigest().upper().encode()
    digest = hashlib.md5(usedforsecurity=False)
    for length in (3, 14, 17, 20, 24):
        digest.update(first_hex[:length])
    second_hex = digest.hexdigest().upper().encode()
    expected = hashlib.md5(b"12345678" + second_hex[16:24] + b"synthetic-suffix",
                           usedforsecurity=False).digest()
    decoded = decode_initialization(record(suffix="synthetic-suffix"))
    assert decoded.auth_digest == expected
    assert decoded.auth_digest != hashlib.md5(
        b"12345678" + first_hex[16:24] + b"synthetic-suffix", usedforsecurity=False).digest()


def test_suffix_truncation_and_one_byte_omission_match_vendor():
    empty = decode_initialization(record())
    assert decode_initialization(record(suffix="x")).auth_digest == empty.auth_digest
    assert decode_initialization(record(suffix="xy")).auth_digest != empty.auth_digest
    assert decode_initialization(record(suffix="abcdefghijklmnopTAIL")).auth_digest == (
        decode_initialization(record(suffix="abcdefghijklmnop")).auth_digest
    )


def test_short_rendezvous_descriptor_is_an_opaque_flag():
    _, _, _, marker = _initialization_material()
    fields = [marker.decode(), "das", "12345678", "none!", "192.0.2.1", "ANY"]
    decoded = decode_initialization(record(fields=fields))
    assert decoded.rendezvous_hosts == ()
    assert decoded.rendezvous_descriptor == "none!"


def test_rendezvous_hosts_use_plus_and_preserve_dns_hyphens():
    _, _, _, marker = _initialization_material()
    fields = [marker.decode(), "das", "12345678", "relay-one.example+relay-two.example", "192.0.2.1", "ANY"]
    decoded = decode_initialization(record(fields=fields))
    assert decoded.rendezvous_hosts == ("relay-one.example", "relay-two.example")


def test_optional_record_checksum_is_verified_or_fails_closed():
    value = record(checksum=True)
    with pytest.raises(VPError, match="requires protocol material"):
        decode_initialization(value)
    assert decode_initialization(value, checksum_salt=b"tests").record_number == 12345678
    with pytest.raises(VPError, match="record is invalid"):
        decode_initialization(value, checksum_salt=b"wrong")


@pytest.mark.parametrize("mutate", [
    lambda s: s.replace("DAS-", "VPS-"),
    lambda s: s[:-1],
    lambda s: s[:4] + "G" + s[5:],
    lambda s: s + ":",
    lambda s: s + ":a:b",
    lambda s: s + ":\nsecret",
    lambda s: s[:4] + "00" * 16,
])
def test_bad_ciphertext_and_envelope_are_sanitized(mutate):
    value = mutate(record())
    with pytest.raises(VPError) as caught:
        decode_initialization(value)
    assert value not in str(caught.value)
    assert "secret" not in str(caught.value)


@pytest.mark.parametrize("index,value", [
    (0, "wrong"), (1, "wrong"), (2, "-1"), (2, "2147483648"),
    (2, "1234567"), (2, "123456789"),
    (3, "bad host"), (4, "hostname.example"),
    (4, "192.0.2.1-192.0.2.2-192.0.2.3-192.0.2.4"),
    (5, "bad rule"),
])
def test_decrypted_schema_is_bounded(index, value):
    _, _, _, marker = _initialization_material()
    fields = [marker.decode(), "das", "12345678", "relay.example", "192.0.2.1", "ANY"]
    fields[index] = value
    with pytest.raises(VPError, match="record is invalid"):
        decode_initialization(record(fields=fields))


def test_channel_orders_packets_and_does_not_strip_prefix_twice():
    channel = VPChannelBuffer()
    assert channel.feed(1, b"123456def", header_bytes=6)
    assert channel.read(4) == b""
    assert channel.feed(0, b"!abc", header_bytes=1)
    assert channel.read(2) == b"ab"
    assert channel.read(2) == b"cd"
    assert channel.read(8) == b"ef"
    assert channel.next_sequence == 2
    assert channel.read(8) == b""


def test_channel_wrap_skips_reserved_sequence_and_ignores_stale_duplicates():
    channel = VPChannelBuffer(next_sequence=0xFFFE)
    channel.feed(0, b"!next", header_bytes=1)
    channel.feed(0xFFFE, b"!last", header_bytes=1)
    assert not channel.feed(0, b"!next", header_bytes=1)
    assert channel.read(8) == b"lastnext"
    assert channel.next_sequence == 1
    assert not channel.feed(0xFFFE, b"!last", header_bytes=1)
    with pytest.raises(VPError, match="packet is invalid"):
        channel.feed(0xFFFF, b"!reserved", header_bytes=1)


def test_channel_limits_and_conflicts_leave_existing_stream_intact():
    channel = VPChannelBuffer(window=2, max_bytes=5)
    channel.feed(0, b"!abcd", header_bytes=1)
    with pytest.raises(VPError, match="buffer limit"):
        channel.feed(1, b"!ef", header_bytes=1)
    with pytest.raises(VPError, match="duplicate conflicts"):
        channel.feed(0, b"!xxxx", header_bytes=1)
    with pytest.raises(VPError, match="reorder window"):
        channel.feed(2, b"!z", header_bytes=1)
    assert channel.read(5) == b"abcd"
    channel.feed(1, b"!ef", header_bytes=1)
    assert channel.read(5) == b"ef"


def test_channel_empty_payloads_and_teardown_do_not_leak_old_media():
    channel = VPChannelBuffer()
    channel.feed(0, b"123456", header_bytes=6)
    channel.feed(1, b"!media", header_bytes=1)
    assert channel.read(2) == b"me"
    channel.close()
    assert channel.read(10) == b""
    with pytest.raises(VPError, match="closed"):
        channel.feed(2, b"!new", header_bytes=1)


def video_record(payload, *, codec=0, keyframe=False):
    header = bytearray(32)
    if keyframe:
        header[:4] = b"\x55\xaa\x15\xa8"
    header[4] = codec
    header[16:20] = len(payload).to_bytes(4, "little")
    return bytes(header) + payload


def test_video_framing_preserves_fragmented_header_and_payload():
    parser = VPVideoFrames()
    first = video_record(b"first", keyframe=True)
    second = video_record(b"second")
    assert parser.feed(first[:17]) == []
    assert parser.feed(first[17:-2]) == []
    assert parser.feed(first[-2:] + video_record(b"") + second[:33]) == [(b"first", True)]
    assert parser.feed(second[33:]) == [(b"second", False)]
    parser.finish()


def test_ordered_channel_delivers_frames_across_packets():
    wire = video_record(b"independent-h264-bytes", keyframe=True)
    channel = VPChannelBuffer()
    parser = VPVideoFrames()
    channel.feed(1, b"123456" + wire[20:], header_bytes=6)
    channel.feed(0, b"!" + wire[:20], header_bytes=1)
    assert parser.feed(channel.read(10)) == []
    assert parser.feed(channel.read(100)) == [(b"independent-h264-bytes", True)]


def test_video_invalid_length_and_codec_poison_parser_instead_of_resynchronizing():
    bad_length = bytearray(32)
    bad_length[16:20] = (MAX_VIDEO_BYTES + 1).to_bytes(4, "little")
    for bad in (bytes(bad_length), video_record(b"bad", codec=0x11)):
        parser = VPVideoFrames()
        with pytest.raises(VPError):
            parser.feed(bad)
        with pytest.raises(VPError, match="closed"):
            parser.feed(video_record(b"later"))


def test_video_eof_reports_a_partial_header_or_body():
    frame = video_record(b"payload")
    for partial in (frame[:3], frame[:-1]):
        parser = VPVideoFrames()
        parser.feed(partial)
        with pytest.raises(VPError, match="incomplete frame"):
            parser.finish()
