"""Synthetic inputs only; no account, camera or vendor values."""
import hashlib

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from okam_native.vp import VPError
from okam_native.vp_credentials import (build_worker_inputs, decrypt_camera_password,
                                        select_checksum_salt, vp_authentication)
from test_vp import record

SALT = "_+example-salt"


def encrypt_password(password: bytes, double_check: str, salt: str = SALT) -> str:
    key = hashlib.md5((double_check + salt).encode(), usedforsecurity=False).digest()
    padding = 16 - len(password) % 16
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return (encryptor.update(password + bytes([padding]) * padding) + encryptor.finalize()).hex()


def test_camera_password_decrypts_with_account_check_value_and_salt():
    security = encrypt_password(b"Abc123def456ghi", "123456789")
    assert decrypt_camera_password(security, "123456789", SALT) == "Abc123def456ghi"
    assert decrypt_camera_password(security.upper(), "123456789", SALT) == "Abc123def456ghi"


@pytest.mark.parametrize("double_check, salt", [("123456780", SALT), ("123456789", "other")])
def test_wrong_key_inputs_fail_closed(double_check, salt):
    security = encrypt_password(b"Abc123def456ghi", "123456789")
    with pytest.raises(VPError, match="could not be decoded"):
        decrypt_camera_password(security, double_check, salt)


@pytest.mark.parametrize("security, double_check, salt", [
    ("00" * 15, "1", SALT), ("zz" * 16, "1", SALT), ("00" * 16, "abc", SALT), ("00" * 16, "1", ""),
])
def test_invalid_password_inputs_are_rejected(security, double_check, salt):
    with pytest.raises(VPError, match="inputs are invalid"):
        decrypt_camera_password(security, double_check, salt)


def test_unsafe_decrypted_password_is_rejected():
    security = encrypt_password(b"has&ampersand", "1")
    with pytest.raises(VPError, match="could not be decoded"):
        decrypt_camera_password(security, "1", SALT)


def test_vp_authentication_layout_and_validation():
    assert vp_authentication("123456789", "abc%2Fdef") == "%%admin&123456789&abc%2Fdef"
    for user_id, token in (("12a", "t"), ("1", "a&b"), ("1", ""), ("1", "x" * 256)):
        with pytest.raises(VPError):
            vp_authentication(user_id, token)


def test_checksum_salt_is_selected_from_any_library_window():
    connection = "TEST%%" + record(checksum=True)
    # The salt sits inside a longer printable run, as in the vendor library.
    library = b"\0\x7fnoise" + b"ABtestsXY" + b"\0more"
    assert select_checksum_salt(library, connection) == "tests"
    with pytest.raises(VPError, match="not found"):
        select_checksum_salt(b"\0nothing here\0", connection)


def test_records_without_checksum_need_no_library():
    assert len(select_checksum_salt(b"", "TEST%%" + record())) == 5


def test_build_worker_inputs_hides_values_and_forms_worker_config():
    inputs = build_worker_inputs(
        connection="TEST%%" + record(), user_id="123456789", token="tok",
        security=encrypt_password(b"Abc123def456ghi", "123456789"),
        password_salt=SALT, library=b"")
    assert "Abc123" not in repr(inputs) and "tok" not in repr(inputs)
    config = inputs.worker_config(max_frames=3)
    assert config["password"] == "Abc123def456ghi"
    assert config["authentication"] == "%%admin&123456789&tok"
    assert config["max_frames"] == 3


def _fake_client(*literals: str) -> bytes:
    # A synthetic stand-in for the PC client: printable noise strings and the
    # key literal, separated by non-printable bytes as compiled code would be.
    noise = [b"TForm1.ButtonClick", b"Microsoft Visual", b"%s:%d", b"0123456789ABCDEF"]
    parts = noise + [literal.encode() for literal in literals]
    return b"\x00\x01\xff".join(parts) + b"\x00"


def test_password_salt_is_found_blindly_in_the_client():
    from okam_native.vp_credentials import select_password_salt

    records = [(encrypt_password(b"Abc123def456ghi", "123456789"), "123456789")]
    assert select_password_salt(_fake_client(SALT), records) == SALT


def test_password_salt_requires_every_record_to_decode():
    from okam_native.vp_credentials import select_password_salt

    records = [
        (encrypt_password(b"Abc123def456ghi", "123456789"), "123456789"),
        (encrypt_password(b"Zyx987wvu654tsr", "123456789", "other-salt-value"), "123456789"),
    ]
    with pytest.raises(VPError):
        select_password_salt(_fake_client(SALT), records)


def test_password_salt_absent_from_the_client_fails_closed():
    from okam_native.vp_credentials import select_password_salt

    records = [(encrypt_password(b"Abc123def456ghi", "123456789"), "123456789")]
    with pytest.raises(VPError, match="not found"):
        select_password_salt(_fake_client(), records)
    with pytest.raises(VPError):
        select_password_salt(b"", records)


def test_configured_camera_password_overrides_the_account_password():
    inputs = build_worker_inputs(
        connection="TEST%%" + record(), user_id="123456789", token="tok",
        security=encrypt_password(b"Abc123def456ghi", "123456789"),
        password_salt=SALT, library=b"", password_override="ChangedOnCamera1")
    assert inputs.worker_config()["password"] == "ChangedOnCamera1"
