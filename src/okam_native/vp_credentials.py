"""Derive the VP worker's private inputs from the account and vendor artifacts.

Nothing here is logged. Vendor constants are never embedded: the checksum salt
is selected from the verified official SDK library by validating it against the
camera's own connection record, and the camera password key salt is supplied
through the app options.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from .vp import VPError, select_checksum_salt as _select_record_salt, split_connection_input

# The PC client and Android SDK use the fixed camera user for VP devices.
VP_CAMERA_USER = "admin"
# Records without a checksum field ignore the salt; the worker still expects
# five ASCII characters.
_UNUSED_SALT = "-----"


@dataclass(frozen=True)
class VPWorkerInputs:
    connection: str = field(repr=False)
    authentication: str = field(repr=False)
    password: str = field(repr=False)
    checksum_salt: str = field(repr=False)

    def worker_config(self, **extra: object) -> dict[str, object]:
        return {"connection": self.connection, "authentication": self.authentication,
                "password": self.password, "checksum_salt": self.checksum_salt, **extra}


def decrypt_camera_password(security: str, double_check: str, salt: str) -> str:
    """The PC client's securityPwd decoding (SuperIPCam FUN_005ca260/FUN_005ca0e4).

    The key is MD5 of the account check value followed by the vendor salt; the
    32-hex field is one AES-128-ECB block with PKCS#7 padding.
    """
    if (not isinstance(security, str) or not re.fullmatch(r"[0-9A-Fa-f]{32}", security)
            or not isinstance(double_check, str) or not double_check.isdigit()
            or not isinstance(salt, str) or not salt or len(salt) > 128 or not salt.isascii()):
        raise VPError("VP camera password inputs are invalid")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = hashlib.md5((double_check + salt).encode("ascii"), usedforsecurity=False).digest()
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    plain = decryptor.update(bytes.fromhex(security)) + decryptor.finalize()
    padding = plain[-1]
    if not 1 <= padding <= 16 or plain[-padding:] != bytes([padding]) * padding:
        raise VPError("VP camera password could not be decoded")
    password = plain[:-padding]
    if not password or any(byte < 33 or byte > 126 for byte in password) or b"&" in password:
        raise VPError("VP camera password could not be decoded")
    return password.decode("ascii")


def vp_authentication(user_id: str, token: str) -> str:
    """The structured %%user&account&token form passed to the camera channel."""
    if (not isinstance(user_id, str) or not user_id.isdigit() or len(user_id) > 63
            or not isinstance(token, str) or not 1 <= len(token) <= 255
            or any(ord(c) < 33 or ord(c) > 126 or c in "&?#" for c in token)):
        raise VPError("VP account authentication inputs are invalid")
    return f"%%{VP_CAMERA_USER}&{user_id}&{token}"


def _printable_windows(library: bytes):
    seen = set()
    for offset in range(len(library) - 4):
        window = library[offset:offset + 5]
        if window not in seen and all(33 <= byte <= 126 for byte in window):
            seen.add(window)
            yield window


def select_checksum_salt(library: bytes, connection: str) -> str:
    """Pick the 5-byte window of the SDK library that validates the record.

    The salt sits inside a longer string in the library, so every printable
    window is a candidate; the record's checksum selects the right one.
    """
    if not isinstance(library, bytes):
        raise VPError("VP SDK library is unavailable")
    record = split_connection_input(connection).initialization_record
    selected = _select_record_salt(record, _printable_windows(library))
    return _UNUSED_SALT if selected is None else selected.decode("ascii")


# The PC client's password key is a plain ASCII literal; this length range
# covers it with margin while keeping the one-time scan to a few seconds.
PASSWORD_SALT_LENGTHS = range(8, 29)


def _password_salt_candidates(client: bytes):
    """Every distinct printable-ASCII window of a plausible salt length."""
    seen = set()
    start = None
    for offset, byte in enumerate(client + b"\x00"):
        if 33 <= byte <= 126:
            if start is None:
                start = offset
            continue
        if start is not None:
            run = client[start:offset]
            for length in PASSWORD_SALT_LENGTHS:
                for begin in range(len(run) - length + 1):
                    window = run[begin:begin + length]
                    if window not in seen:
                        seen.add(window)
                        yield window.decode("ascii")
            start = None


def select_password_salt(client: bytes, records: list[tuple[str, str]]) -> str:
    """Find the camera-password key in the official PC client, blindly.

    No value is embedded: each candidate string from the client is tried
    against the account's own encrypted camera passwords (``security``,
    ``doubleCheck`` pairs). A wrong key almost never yields valid padding and
    a printable password (about one in a billion per candidate), and every
    record must decode for the candidate to count.
    """
    if not isinstance(client, bytes) or not client or not records:
        raise VPError("VP password key sources are unavailable")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    # Validate the inputs once, then screen candidates on the first record
    # with a bare decrypt; the full check confirms the rare survivors.
    for security, double_check in records:
        if (not isinstance(security, str) or not re.fullmatch(r"[0-9A-Fa-f]{32}", security)
                or not isinstance(double_check, str) or not double_check.isdigit()):
            raise VPError("VP camera password inputs are invalid")
    first_block = bytes.fromhex(records[0][0])
    prefix = hashlib.md5(records[0][1].encode("ascii"), usedforsecurity=False)
    passwords: dict[tuple[str, ...], str] = {}
    for candidate in _password_salt_candidates(client):
        digest = prefix.copy()
        digest.update(candidate.encode("ascii"))
        decryptor = Cipher(algorithms.AES(digest.digest()), modes.ECB()).decryptor()
        plain = decryptor.update(first_block) + decryptor.finalize()
        padding = plain[-1]
        if not 1 <= padding <= 15 or plain[-padding:] != bytes([padding]) * padding:
            continue
        try:
            decoded = tuple(
                decrypt_camera_password(security, double_check, candidate)
                for security, double_check in records
            )
        except VPError:
            continue
        passwords.setdefault(decoded, candidate)
        if len(passwords) > 1:
            raise VPError("VP password key is ambiguous")
    if not passwords:
        raise VPError("VP password key was not found")
    return next(iter(passwords.values()))


def build_worker_inputs(*, connection: str, user_id: str, token: str, security: str,
                        password_salt: str, library: bytes) -> VPWorkerInputs:
    return VPWorkerInputs(
        connection=connection,
        authentication=vp_authentication(user_id, token),
        password=decrypt_camera_password(security, user_id, password_salt),
        checksum_salt=select_checksum_salt(library, connection),
    )
