import dataclasses
import hashlib
import json
from urllib.parse import parse_qs, urlsplit

import pytest

from okam_native.account import AccountDevice, AccountError, Eye4AccountClient
from okam_native.p2p import is_vp_account_record


def test_official_account_enumeration_flow() -> None:
    requests = []

    def opener(request, timeout: float) -> bytes:
        requests.append((request, timeout))
        path = urlsplit(request.full_url).path
        if path == "/user/summary":
            return json.dumps({"userid": 123456789}).encode()
        if path == "/login/token":
            return json.dumps({"token": "opaque-token"}).encode()
        if path == "/PC/device/show":
            return json.dumps(
                [{"uid": "sensitive-device-id", "nickname": "Cabin", "password": "secret"}]
            ).encode()
        raise AssertionError(path)

    devices = Eye4AccountClient(opener=opener).enumerate("viewer@example.com", "password")

    assert len(devices) == 1
    assert devices[0].name == "Cabin"
    assert "sensitive-device-id" not in repr(devices[0])
    assert "secret" not in repr(devices[0])
    assert [urlsplit(item[0].full_url).path for item in requests] == [
        "/user/summary",
        "/login/token",
        "/PC/device/show",
    ]
    assert parse_qs(requests[0][0].data.decode()) == {
        "name": ["viewer@example.com"],
        "oemid": ["VSTC"],
    }
    login_query = parse_qs(urlsplit(requests[1][0].full_url).query)
    assert login_query == {
        "userid": ["123456789"],
        "password": [hashlib.md5(b"password", usedforsecurity=False).hexdigest()],
        "type": ["PC"],
    }
    device_query = parse_qs(urlsplit(requests[2][0].full_url).query)
    assert device_query["userid"] == ["123456789"]
    assert device_query["pwd"] == [login_query["password"][0]]
    assert requests[0][0].headers["Client_version"] == "10.0.1"


def test_account_errors_never_include_credentials() -> None:
    def opener(_request, _timeout: float) -> bytes:
        raise OSError("network error containing viewer@example.com and secret")

    with pytest.raises(AccountError) as caught:
        Eye4AccountClient(opener=opener).enumerate("viewer@example.com", "secret")
    assert "viewer@example.com" not in str(caught.value)
    assert "secret" not in str(caught.value)


VP_SECURITY = "S" * 32
VP_SECURITY_SENTINEL = "SECRETSENTINEL" + "A" * 18  # exactly 32 characters


def _account_client(devices: object) -> Eye4AccountClient:
    def opener(request, timeout: float) -> bytes:
        path = urlsplit(request.full_url).path
        if path == "/user/summary":
            return json.dumps({"userid": 123456789}).encode()
        if path == "/login/token":
            return json.dumps({"token": "opaque-token"}).encode()
        if path == "/PC/device/show":
            return json.dumps(devices).encode()
        raise AssertionError(path)

    return Eye4AccountClient(opener=opener)


@pytest.fixture
def enumerate_devices():
    """Enumerate a caller-supplied device list through a fake account opener."""

    def run(devices: object) -> list[AccountDevice]:
        return _account_client(devices).enumerate("viewer@example.com", "password")

    return run


def test_documented_vp_record_reaches_the_discriminator(enumerate_devices) -> None:
    devices = enumerate_devices(
        [
            {
                "uid": "synthetic-vp-uid-0001",
                "nickname": "Parking",
                "password": "",
                "security": VP_SECURITY,
            },
            {
                "uid": "synthetic-legacy-uid-0002",
                "nickname": "Gate",
                "password": "secret",
            },
        ]
    )

    assert len(devices) == 2
    vp, legacy = devices
    assert vp.security == VP_SECURITY
    assert vp.device_password == ""
    assert is_vp_account_record(
        device_password=vp.device_password, security=vp.security
    ) is True
    assert legacy.security is None
    assert legacy.device_password == "secret"
    assert is_vp_account_record(
        device_password=legacy.device_password, security=legacy.security
    ) is False


@pytest.mark.parametrize(
    "security_value,present",
    [
        ("S" * 31, True),
        ("S" * 33, True),
        ("S" * 31 + "\n", True),
        ("S" * 31 + " ", True),
        ("S" * 31 + "\u00e9", True),
        (12345, True),
        (None, True),
        (["S" * 32], True),
        ({"value": "S" * 32}, True),
        ("S" * 32, False),  # key absent
    ],
)
def test_malformed_or_missing_security_fails_closed(
    enumerate_devices, security_value: object, present: bool
) -> None:
    item: dict[str, object] = {
        "uid": "synthetic-vp-uid-0003",
        "nickname": "Parking",
        "password": "",
    }
    if present:
        item["security"] = security_value

    devices = enumerate_devices([item])

    assert len(devices) == 1, "a bad security value must not drop the camera"
    device = devices[0]
    assert device.security is None
    assert is_vp_account_record(
        device_password=device.device_password, security=device.security
    ) is False


def test_vp_security_never_appears_in_repr(enumerate_devices) -> None:
    devices = enumerate_devices(
        [
            {
                "uid": "uid-sentinel-0001",
                "nickname": "Parking",
                "password": "password-sentinel",
                "security": VP_SECURITY_SENTINEL,
            }
        ]
    )
    device = devices[0]

    assert device.security == VP_SECURITY_SENTINEL
    for rendered in (repr(device), str(device), f"{device}"):
        assert VP_SECURITY_SENTINEL not in rendered
        assert "uid-sentinel-0001" not in rendered
        assert "password-sentinel" not in rendered

    fields = {field.name: field for field in dataclasses.fields(AccountDevice)}
    assert fields["security"].repr is False
    assert fields["uid"].repr is False
    assert fields["device_password"].repr is False


def test_account_error_does_not_echo_a_security_value() -> None:
    def opener(request, timeout: float) -> bytes:
        path = urlsplit(request.full_url).path
        if path == "/user/summary":
            return json.dumps({"userid": 123456789}).encode()
        if path == "/login/token":
            return json.dumps({"token": "opaque-token"}).encode()
        # A non-list device payload is rejected with a constant message.
        return json.dumps({"security": VP_SECURITY_SENTINEL}).encode()

    with pytest.raises(AccountError) as caught:
        Eye4AccountClient(opener=opener).enumerate("viewer@example.com", "password")
    assert VP_SECURITY_SENTINEL not in str(caught.value)
