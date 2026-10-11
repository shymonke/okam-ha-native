import io
import json
import struct
from types import SimpleNamespace
from collections import Counter

import pytest

from okam_native import vp_helper as helper
from okam_native.vp import VPError
from okam_native.vp_commands import parse_authentication, read_command, read_video_frame
from okam_native.vp_session import VPTimeout


def test_structured_authentication_is_parsed_without_repr_disclosure():
    auth = parse_authentication('%%synthetic-user&synthetic-account&synthetic-token', 'synthetic-password')
    assert auth.user == 'synthetic-user'
    assert auth.account == 'synthetic-account'
    assert auth.token == 'synthetic-token'
    assert auth.password == 'synthetic-password'
    assert 'synthetic' not in repr(auth)


@pytest.mark.parametrize('value', ['plain', '%%a&b', '%%a&b&c&d', '%%a&b&c\n', '%%a&b&' + 'x'*256])
def test_structured_authentication_fails_closed(value):
    with pytest.raises(VPError):
        parse_authentication(value, 'synthetic-password')


@pytest.mark.parametrize('reader,header', [
    (read_command, struct.pack('<HHHH', 0x0a01, 0x6001, 9, 0x100)),
    (read_video_frame, bytes(16) + (9).to_bytes(4, 'little') + bytes(12)),
])
def test_consumed_header_then_missing_body_is_hard_failure(reader, header):
    class State:
        def read_exact(self, *_args, **_kwargs):
            if not getattr(self, 'used', False):
                self.used = True
                return header
            raise VPTimeout('synthetic timeout')
    with pytest.raises(VPError, match='body') as error:
        reader(State(), timeout=1)
    assert not isinstance(error.value, VPTimeout)


def prepare(monkeypatch, *, fail_media=False):
    monkeypatch.setattr(helper, 'split_connection_input', lambda _: SimpleNamespace(transport_id='synthetic', initialization_record='record'))
    monkeypatch.setattr(helper, 'decode_initialization', lambda *a, **kw: object())
    class State:
        def __init__(self, *_):
            self.counters = Counter()
            self.writes = []
            self.closed = False
            self.parts = [struct.pack('<HHHH', 0x0a01, 0x6001, 9, 0x100), b'result=0;']
        def connect(self, **_):
            pass
        def write(self, channel, data, **_):
            self.writes.append(data)
        def read_exact(self, *_, **__):
            return self.parts.pop(0)
        def close(self):
            self.closed = True
    state = State()
    def media(*_, **__):
        if fail_media:
            raise VPError('synthetic private failure')
        return b'\x00\x00\x00\x01\x65\x01', True, 0
    monkeypatch.setattr(helper, 'read_video_frame', media)
    config = dict(connection='synthetic', authentication='%%user&account&token',
                  password='synthetic-password', checksum_salt='abcde', max_frames=3)
    return config, state


def test_worker_outputs_media_and_stops_before_close(monkeypatch):
    config, state = prepare(monkeypatch)
    output = io.BytesIO()
    code, result = helper.run(config, output, session_factory=lambda *_: state)
    assert code == 0 and result['h264_frames'] == 3 and result['keyframe_seen']
    assert output.getvalue() == b'\x00\x00\x00\x01\x65\x01' * 3
    assert b'eye4_authentication.cgi?' in state.writes[1]
    assert b'check_user.cgi?' in state.writes[2]
    assert b'streamid=10' in state.writes[3]
    assert b'streamid=16' in state.writes[-1] and state.closed
    assert 'synthetic-password' not in json.dumps(result)


def test_worker_media_failure_stops_and_redacts(monkeypatch):
    config, state = prepare(monkeypatch, fail_media=True)
    code, result = helper.run(config, io.BytesIO(), session_factory=lambda *_: state)
    assert code == 1 and state.closed
    assert b'streamid=16' in state.writes[-1]
    assert 'private' not in json.dumps(result)


def test_worker_invalid_config_never_connects():
    def forbidden(*_):
        pytest.fail('invalid configuration must not open a session')
    code, result = helper.run({'private': 'DO_NOT_EMIT'}, io.BytesIO(), session_factory=forbidden)
    assert code == 1 and 'DO_NOT_EMIT' not in json.dumps(result)


def test_worker_process_receives_private_input_only_on_stdin(monkeypatch):
    class Pipe(io.BytesIO):
        def close(self):
            self.saved = self.getvalue()
            super().close()
    pipe = Pipe()
    process = SimpleNamespace(stdin=pipe, stdout=object(), stderr=object())
    def spawn(argv, **kwargs):
        assert argv == ['synthetic-python', '-m', 'okam_native.vp_helper']
        assert 'DO_NOT_EMIT' not in repr(argv)
        assert kwargs['bufsize'] == 0
        return process
    monkeypatch.setattr(helper.subprocess, 'Popen', spawn)
    assert helper.open_stream_process({'private': 'DO_NOT_EMIT'}, python='synthetic-python') is process
    assert json.loads(pipe.saved) == {'private': 'DO_NOT_EMIT'}
    assert process.stdin is None


def test_failure_codes_name_fixed_vp_messages_only():
    from okam_native.vp import VPError
    from okam_native.vp_helper import _error_code
    assert _error_code(VPError("VP camera command header is invalid")) == "camera_command_header_is_invalid"
    assert _error_code(VPError("VP value 10.0.0.1:443 leaked")) == "unclassified"
    assert _error_code(OSError("10.0.0.1 refused")) == "OSError"


def test_first_camera_command_allows_an_idle_camera_to_wake():
    import struct
    from collections import Counter
    from okam_native.vp_commands import (WAKE_TIMEOUT_SECONDS, VPAuthentication,
                                         start_authenticated_stream)

    class Session:
        counters = Counter()

        def __init__(self):
            body = b"result= 0;"
            self.incoming = struct.pack("<HHHH", 0x0A01, 0x6001, len(body), 0) + body
            self.writes = []

        def write(self, channel, payload, *, timeout):
            self.writes.append(timeout)

        def read_exact(self, channel, size, *, timeout):
            assert timeout > 5
            data, self.incoming = self.incoming[:size], self.incoming[size:]
            return data

    session = Session()
    start_authenticated_stream(session, VPAuthentication("admin", "pw", "123", "tok"))
    assert WAKE_TIMEOUT_SECONDS >= 20
    assert session.writes == [WAKE_TIMEOUT_SECONDS, 5, 5, 5]


def _two_lens_media(monkeypatch):
    frames = iter([(b'\x00\x00\x00\x01\x65\xa0', True, 0), (b'\x00\x00\x00\x01\x65\xb1', True, 1)] * 3)
    monkeypatch.setattr(helper, 'read_video_frame', lambda *_, **__: next(frames))


@pytest.mark.parametrize('lens, marker', [(0, b'\xa0'), (1, b'\xb1')])
def test_worker_plain_output_carries_one_lens_only(monkeypatch, lens, marker):
    config, state = prepare(monkeypatch)
    _two_lens_media(monkeypatch)
    output = io.BytesIO()
    code, result = helper.run({**config, 'lens': lens, 'max_frames': 2}, output,
                              session_factory=lambda *_: state)
    assert code == 0 and output.getvalue() == (b'\x00\x00\x00\x01\x65' + marker) * 2
    assert result['lens_frames'][str(lens)] == 2


def test_worker_framed_output_round_trips_both_lenses(monkeypatch):
    config, state = prepare(monkeypatch)
    _two_lens_media(monkeypatch)
    output = io.BytesIO()
    code, result = helper.run({**config, 'framed': True, 'max_frames': 4}, output,
                              session_factory=lambda *_: state)
    output.seek(0)
    records = list(helper.read_lens_records(output))
    assert code == 0 and [lens for lens, _ in records] == [0, 1, 0, 1]
    assert records[1][1].endswith(b'\xb1') and result['lens_frames'] == {'0': 2, '1': 2}


@pytest.mark.parametrize('extra', [{'lens': 4}, {'lens': True}, {'framed': 1}])
def test_worker_rejects_invalid_lens_options(extra):
    def forbidden(*_):
        pytest.fail('invalid configuration must not open a session')
    config = dict(connection='c', authentication='%%u&a&t', password='p', checksum_salt='abcde', **extra)
    code, result = helper.run(config, io.BytesIO(), session_factory=forbidden)
    assert code == 1 and result['failure_stage'] == 'configuration'


def test_lens_records_reject_truncation_and_bad_lens():
    with pytest.raises(VPError, match='truncated'):
        list(helper.read_lens_records(io.BytesIO(helper.encode_lens_record(0, b'abcdef')[:-2])))
    with pytest.raises(VPError, match='invalid'):
        list(helper.read_lens_records(io.BytesIO(struct.pack('>BI', 9, 1) + b'x')))


def test_video_lens_reads_header_offset_26():
    from okam_native.vp import video_lens
    header = bytearray(32)
    header[26] = 1
    assert video_lens(bytes(header)) == 1
    with pytest.raises(VPError):
        video_lens(b'short')
