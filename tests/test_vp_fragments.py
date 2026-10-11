"""Synthetic vectors for the recovered direct VP reliable packet layout."""
from dataclasses import replace

import pytest

from okam_native.vp import VPError
from okam_native.vp_wire import (
    FRAGMENT_BYTES, VPDataFragment, VPFragmentAssembler, decode_data_fragment,
    encode_data_fragment, encode_fragment_ack,
)


def fragment(**changes):
    return replace(VPDataFragment(18, 1, 0, 3, 0, 1, b"abc"), **changes)


def test_vendor_network_order_header_and_ack_vector():
    wire = bytes.fromhex("0d001201000003000b00000001") + b"abc"
    decoded = decode_data_fragment(wire)
    assert decoded == fragment()
    assert encode_data_fragment(decoded) == wire
    assert encode_fragment_ack(decoded, next_packet=19) == bytes.fromhex("0d0013080000030012")
    assert "abc" not in repr(decoded)


def test_out_of_order_fragments_and_identical_duplicates():
    assembly = VPFragmentAssembler()
    first = fragment(count=2, payload=b"a" * FRAGMENT_BYTES)
    last = fragment(packet_sequence=19, index=1, count=2, payload=b"end")
    assert assembly.feed(last) is None
    assert assembly.feed(last) is None
    assert assembly.feed(first) == b"a" * FRAGMENT_BYTES + b"end"
    assert assembly._bytes == 0
    assert not assembly._pending


def test_message_and_channel_isolation():
    assembly = VPFragmentAssembler()
    assert assembly.feed(fragment(count=2, payload=b"a" * FRAGMENT_BYTES)) is None
    assert assembly.feed(fragment(channel=0, payload=b"command")) == b"command"
    assert assembly.feed(fragment(message_sequence=4, payload=b"next")) == b"next"
    assert assembly.feed(fragment(index=1, count=2)) == b"a" * FRAGMENT_BYTES + b"abc"


def test_conflicting_count_or_content_does_not_corrupt_buffer():
    assembly = VPFragmentAssembler()
    first = fragment(count=2, payload=b"a" * FRAGMENT_BYTES)
    assembly.feed(first)
    for bad in (replace(first, count=3), replace(first, payload=b"b" * FRAGMENT_BYTES)):
        with pytest.raises(VPError, match="conflict"):
            assembly.feed(bad)
    assert assembly.feed(fragment(index=1, count=2)) == b"a" * FRAGMENT_BYTES + b"abc"


@pytest.mark.parametrize("changes", [
    {"packet_sequence": 65535}, {"packet_sequence": -1}, {"message_sequence": 65535},
    {"channel": 8}, {"flow_mask": 256}, {"index": 1}, {"count": 0},
    {"count": 2}, {"count": 16383}, {"payload": b""},
    {"payload": b"x" * 1101}, {"packet_sequence": True},
])
def test_invalid_fragment_fields(changes):
    with pytest.raises(VPError):
        encode_data_fragment(fragment(**changes))


@pytest.mark.parametrize("wire", [b"", b"\x0d", b"\x0c" + bytes(12),
                                      bytes.fromhex("0d001201000003000a00000001") + b"abc"])
def test_invalid_datagram_framing(wire):
    with pytest.raises(VPError):
        decode_data_fragment(wire)


def test_memory_and_incomplete_message_limits():
    assembly = VPFragmentAssembler(max_bytes=1100, max_messages=1)
    assembly.feed(fragment(count=2, payload=b"a" * 1100))
    with pytest.raises(VPError, match="message limit"):
        assembly.feed(fragment(channel=0))
    with pytest.raises(VPError, match="buffer limit"):
        assembly.feed(fragment(count=2, index=1))
    assembly.clear()
    assert assembly.feed(fragment()) == b"abc"


@pytest.mark.parametrize("sequence,mask", [(65535, 0), (-1, 0), (True, 0), (0, 256)])
def test_invalid_ack_fields(sequence, mask):
    with pytest.raises(VPError):
        encode_fragment_ack(fragment(), next_packet=sequence, flow_mask=mask)
