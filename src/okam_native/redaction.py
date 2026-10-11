"""Fail-closed redaction used by protocol-development tools."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


SENSITIVE_KEYS = re.compile(
    r"(?:user(?:name|id)?|email|pass(?:word)?|pwd|token|secret|access_?key|api_?key"
    r"|private_?key|auth|credential|cookie|did|uid|vuid|device_?id|security"
    r"|sign(?:ature)?|nonce|session_?id|service(?:_?parameter)?|init_?string"
    r"|address|node_?(?:ip|port)|supplier|cluster)",
    re.IGNORECASE,
)
URLISH = re.compile(r"^(?:https?|wss?)://", re.IGNORECASE)

# Explicit allowlists replace route-shape guessing. A host survives only when it
# belongs to a public vendor domain already documented in this repository; a
# path segment survives only when it is a known public route word. Everything
# else becomes a correlation tag, so an alphabetic secret cannot slip through
# by looking like a word.
# Exact hostnames already published in this repository. No wildcard: a
# subdomain that merely ends with a vendor domain is not assumed public, and
# no captured hostname is added here.
PUBLIC_HOSTS = frozenset({
    "api.eye4.cn",
    "authentication.eye4.cn",
    "vuid.eye4.cn",
    "vuid-vp.eye4.cn",
    "liteos-master.eye4.cn",
})
# Public route words already used by this project's own endpoints. Anything
# else in a path is treated as a value.
KNOWN_ROUTES = frozenset({
    "user", "summary", "login", "token", "pc", "device", "show",
    "getinitstring", "vuid", "query",
})
# Query parameter names already published in this repository. Unknown names are
# omitted rather than echoed, so a new parameter cannot leak through its key.
PUBLIC_QUERY_KEYS = frozenset({"userid", "type", "name", "oemid", "uid", "vuid", "password"})

MODULE_CATEGORIES = frozenset({
    "P2PAPI.dll", "PPCS_API.dll", "DevDll_925.dll", "SuperIPCam.exe", "other", "unknown",
})
CALLS_BY_DIRECTION = {
    "send": frozenset({"sendto", "WSASendTo", "send"}),
    "recv": frozenset({"recvfrom", "WSARecvFrom", "recv"}),
    "connect": frozenset({"connect"}),
}
BUCKETS = frozenset({"tiny<40", "small40-199", "mid200-999", "large>=1000"})
_PEER_TAG = re.compile(r"^peer-\d{1,6}$")
_SOCKET_TAG = re.compile(r"^socket-\d{1,6}$")
_PREFIX = re.compile(r"^[0-9a-f]{4}$")
_LEGACY_MODULE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_MAX_LENGTH = 65535
_MAX_TIMESTAMP_MS = 86_400_000
_TRANSPORT_FIELDS = frozenset({
    "direction", "call", "module", "peer", "socket", "length", "prefix", "bucket", "at",
})
_LEGACY_FIELDS = frozenset({
    "direction", "call", "module", "peer", "length", "prefix", "bucket", "at",
})
COVERAGE_SCHEMA = 2
_COVERAGE_FIELDS = frozenset({
    "event", "schema", "phase", "installed", "missing", "desired", "complete", "errors",
})
_COVERAGE_PHASES = frozenset({"installed", "symbol-missing", "attach-failed", "not-implemented"})
# Static Winsock imports in P2PAPI.dll include send/recv/connect as well as
# sendto/recvfrom, so sendto/recvfrom alone cannot exclude connected-socket
# traffic. All of these are listed so coverage stays honest.
DESIRED_HOOKS = frozenset({
    "sendto", "recvfrom", "send", "recv", "connect", "WSASendTo", "WSARecvFrom",
})

# P2PAPI control-flow tracing records only entry/exit and timing. The symbol
# allowlist is the set whose existence is verified locally, so an unexpected or
# renamed export can never appear in a capture. Argument types, arity, buffer
# ownership and callback signatures remain UNVERIFIED, so no field here can
# carry one.
P2PAPI_SYMBOLS = frozenset({
    "P2PAPI_CreateInstance", "P2PAPI_DestroyInstance", "P2PAPI_DestroyAllInstance",
    "P2PAPI_Initial", "P2PAPI_InitialWithServer", "P2PAPI_DeInitial",
    "P2PAPI_Connect", "P2PAPI_Close", "P2PAPI_CloseAll",
    "P2PAPI_SetAVDataCallBack", "P2PAPI_SetMessageCallBack",
    "P2PAPI_SetPlaybackAVDataCallBack", "P2PAPI_StartVideo", "P2PAPI_StopVideo",
    "P2PAPI_StartAudio", "P2PAPI_StartAudio2", "P2PAPI_StopAudio",
    "P2PAPI_StartTalk", "P2PAPI_StopTalk",
})
CALL_SCHEMA = 1
_CALL_PHASES = frozenset({"enter", "leave"})
_CALL_FIELDS = frozenset({
    "event", "schema", "call", "phase", "symbol", "caller", "thread", "at",
})
_CALL_COVERAGE_FIELDS = frozenset({
    "event", "schema", "installed", "missing", "complete", "errors",
})
_MAX_CALL_ID = 10_000_000
# A thread is reported as a local correlation tag. The raw OS thread id is
# never accepted, so it cannot be persisted or published.
_THREAD_TAG = re.compile(r"^thread-\d{1,6}$")

# WinINet discovery records only a closed URL-shape vocabulary. These values
# are shared with the in-process tracer so the host rejects any producer drift
# before a value can be persisted or summarized.
WININET_SCHEMA = 1
WININET_SCHEMES = frozenset({"http", "https", "other"})
WININET_HOSTS = PUBLIC_HOSTS | {"other"}
WININET_ROUTES = KNOWN_ROUTES | {"other"}
WININET_QUERY_KEYS = PUBLIC_QUERY_KEYS | {"other"}
WININET_MAX_SEGMENTS = 16
WININET_MAX_QUERY_KEYS = 16
_WININET_FIELDS = frozenset({"event", "schema", "scheme", "host", "path", "query", "at"})
# The one WinINet single-URL fetch entry point whose use is established for the
# client. Coverage is complete only when the tracer reports this hook installed;
# the desired set is fixed here, not taken from the producer.
WININET_DESIRED_HOOKS = frozenset({"InternetOpenUrlA"})
_WININET_COVERAGE_FIELDS = frozenset({
    "event", "schema", "installed", "missing", "complete", "errors",
})


def opaque_tag(value: str | bytes) -> str:
    """Return a correlation tag which cannot disclose the original value."""

    raw = value.encode("utf-8", "replace") if isinstance(value, str) else value
    return "sha256:" + hashlib.sha256(raw).hexdigest()[:12]


def _tag(value: str) -> str:
    return "<redacted:" + opaque_tag(value).split(":", 1)[1] + ">"


def public_host(host: str) -> bool:
    """True only for an exact, already-published vendor hostname."""

    return isinstance(host, str) and host.lower().split(":", 1)[0] in PUBLIC_HOSTS


def redact_url(value: str) -> str:
    parts = urlsplit(value)
    try:
        hostname = parts.hostname or ""
    except ValueError:
        hostname = ""
    # The port is not needed for diagnostics and is omitted entirely.
    netloc = hostname if public_host(hostname) else _tag(hostname or parts.netloc)
    path = "/".join(
        segment if segment.lower() in KNOWN_ROUTES else (_tag(segment) if segment else segment)
        for segment in parts.path.split("/")
    )
    query = []
    for key, item in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() not in PUBLIC_QUERY_KEYS:
            continue
        query.append((key, _tag(item) if item else ""))
    # Fragments are never needed for protocol diagnostics and can carry secrets.
    return urlunsplit((parts.scheme, netloc, path, urlencode(query), ""))


def sanitize(value: Any, *, key: str = "") -> Any:
    """Recursively sanitize an event before it can be serialized."""

    if SENSITIVE_KEYS.search(key):
        text = json.dumps(value, sort_keys=True, default=str)
        return {"redacted": True, "tag": opaque_tag(text), "length": len(text)}
    if isinstance(value, Mapping):
        return {str(name): sanitize(item, key=str(name)) for name, item in value.items()}
    if isinstance(value, (str, bytes)):
        text = value.decode("utf-8", "replace") if isinstance(value, bytes) else value
        if URLISH.match(text):
            return redact_url(text)
        return text
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [sanitize(item, key=key) for item in value]
    return value


def allowlisted(value: Any, allowed: Sequence[str]) -> dict[str, Any]:
    """Return only allowlisted fields from a mapping, sanitized.

    Tracing tools use this so an unexpected or newly added protocol field is
    dropped rather than serialized. An allowlisted name still passes through
    the sensitive-key check, so a name such as ``security`` stays redacted.
    """

    if not isinstance(value, Mapping):
        return {}
    names = {str(name) for name in allowed}
    return {
        str(name): sanitize(item, key=str(name))
        for name, item in value.items()
        if str(name) in names
    }


def safe_json_line(value: Any) -> str:
    return json.dumps(sanitize(value), sort_keys=True, separators=(",", ":"))


def bucket_for(length: int) -> str:
    """Length bucket used by the tracer and re-checked by the validator."""

    if length >= 1000:
        return "large>=1000"
    if length >= 200:
        return "mid200-999"
    if length >= 40:
        return "small40-199"
    return "tiny<40"


def _tagged(value: Any, pattern: re.Pattern[str], *, allow_unknown: bool = False) -> bool:
    return isinstance(value, str) and (
        bool(pattern.fullmatch(value)) or (allow_unknown and value == "unknown")
    )


def valid_transport_event(value: Any) -> dict[str, Any] | None:
    """Validate one current-schema transport event.

    Returns a normalized copy, or ``None`` when the value is not well formed.
    Scalar type checks come first, so a nested list or object is rejected
    without raising. Direction/call and length/bucket consistency are enforced,
    and the socket tag is required because the current schema always has one.
    """

    if not isinstance(value, Mapping):
        return None
    if any(not isinstance(name, str) or name not in _TRANSPORT_FIELDS for name in value):
        return None
    result: dict[str, Any] = {}
    direction = value.get("direction")
    if not isinstance(direction, str) or direction not in CALLS_BY_DIRECTION:
        return None
    result["direction"] = direction
    call = value.get("call")
    if not isinstance(call, str) or call not in CALLS_BY_DIRECTION[direction]:
        return None
    result["call"] = call
    module = value.get("module")
    if not isinstance(module, str) or module not in MODULE_CATEGORIES:
        return None
    result["module"] = module
    peer = value.get("peer")
    if not _tagged(peer, _PEER_TAG, allow_unknown=True):
        return None
    result["peer"] = peer
    socket = value.get("socket")
    if not _tagged(socket, _SOCKET_TAG, allow_unknown=True):
        return None
    result["socket"] = socket
    length = value.get("length")
    if not isinstance(length, int) or isinstance(length, bool) or not 0 <= length <= _MAX_LENGTH:
        return None
    result["length"] = length
    prefix = value.get("prefix")
    if not isinstance(prefix, str) or not (_PREFIX.fullmatch(prefix) or prefix == "unreadable"):
        return None
    # A packet shorter than two bytes cannot carry a two-byte prefix.
    if length < 2 and prefix != "unreadable":
        return None
    # A connection event carries no payload.
    if call == "connect" and (length != 0 or prefix != "unreadable"):
        return None
    result["prefix"] = prefix
    bucket = value.get("bucket")
    if not isinstance(bucket, str) or bucket not in BUCKETS or bucket != bucket_for(length):
        return None
    result["bucket"] = bucket
    at = value.get("at")
    if not isinstance(at, int) or isinstance(at, bool) or not 0 <= at <= _MAX_TIMESTAMP_MS:
        return None
    result["at"] = at
    return result


def valid_legacy_transport_event(value: Any) -> dict[str, Any] | None:
    """Validate the pre-socket capture schema.

    Legacy captures predate the socket tag and module categories, so they are
    accepted on their own terms and can never establish coverage.
    """

    if not isinstance(value, Mapping):
        return None
    if any(not isinstance(name, str) or name not in _LEGACY_FIELDS for name in value):
        return None
    result: dict[str, Any] = {}
    direction = value.get("direction")
    if not isinstance(direction, str) or direction not in CALLS_BY_DIRECTION:
        return None
    result["direction"] = direction
    call = value.get("call")
    if not isinstance(call, str) or call not in CALLS_BY_DIRECTION[direction]:
        return None
    result["call"] = call
    module = value.get("module")
    if not isinstance(module, str) or not _LEGACY_MODULE.fullmatch(module):
        return None
    # Legacy captures stored a raw module name. Normalize anything that is not
    # an already-known category so the summary never prints an arbitrary value.
    result["module"] = module if module in MODULE_CATEGORIES else "other"
    peer = value.get("peer")
    if not _tagged(peer, _PEER_TAG, allow_unknown=True):
        return None
    result["peer"] = peer
    length = value.get("length")
    if not isinstance(length, int) or isinstance(length, bool) or not 0 <= length <= _MAX_LENGTH:
        return None
    result["length"] = length
    prefix = value.get("prefix")
    if not isinstance(prefix, str) or not (_PREFIX.fullmatch(prefix) or prefix == "unreadable"):
        return None
    if length < 2 and prefix != "unreadable":
        return None
    result["prefix"] = prefix
    bucket = value.get("bucket")
    if not isinstance(bucket, str) or bucket not in BUCKETS or bucket != bucket_for(length):
        return None
    result["bucket"] = bucket
    at = value.get("at")
    if not isinstance(at, int) or isinstance(at, bool) or not 0 <= at <= _MAX_TIMESTAMP_MS:
        return None
    result["at"] = at
    return result


def valid_coverage(value: Any) -> dict[str, Any] | None:
    """Validate a coverage record against an explicit schema.

    Coverage messages carry no arbitrary keys or free strings: hook names must
    be known symbols and the phase must be one of the fixed transitions.
    """

    if not isinstance(value, Mapping):
        return None
    if any(not isinstance(name, str) or name not in _COVERAGE_FIELDS for name in value):
        return None
    if value.get("event") != "coverage":
        return None
    schema = value.get("schema")
    if not isinstance(schema, int) or isinstance(schema, bool) or schema != COVERAGE_SCHEMA:
        return None
    phase = value.get("phase")
    if not isinstance(phase, str) or phase not in _COVERAGE_PHASES:
        return None

    def hooks(item: Any) -> list[str] | None:
        if not isinstance(item, list) or len(item) > len(DESIRED_HOOKS):
            return None
        if not all(isinstance(name, str) and name in DESIRED_HOOKS for name in item):
            return None
        if len(set(item)) != len(item):
            return None
        return sorted(item)

    installed = hooks(value.get("installed"))
    missing = hooks(value.get("missing"))
    desired = hooks(value.get("desired"))
    if installed is None or missing is None or desired is None:
        return None
    # The desired set is fixed here, not taken from the producer, so a capture
    # cannot shrink it to look complete. The partition must be disjoint and
    # contained in that set.
    if set(desired) != DESIRED_HOOKS:
        return None
    if set(installed) & set(missing):
        return None
    if not (set(installed) | set(missing)) <= set(desired):
        return None
    complete = value.get("complete")
    if not isinstance(complete, bool):
        return None
    # Completeness is derived, never trusted. A producer that disagrees with
    # the derived value is rejected rather than believed.
    derived = set(installed) == set(desired)
    if complete != derived:
        return None
    errors = value.get("errors")
    if not isinstance(errors, int) or isinstance(errors, bool) or not 0 <= errors <= 1_000_000:
        return None
    return {
        "event": "coverage",
        "schema": schema,
        "phase": phase,
        "installed": installed,
        "missing": missing,
        "desired": desired,
        "complete": derived,
        "errors": errors,
    }


def valid_call_event(value: Any) -> dict[str, Any] | None:
    """Validate one P2PAPI control-flow event.

    The field set is closed, so an argument, pointer, address, payload or
    credential cannot pass even if a producer tried to add one. The symbol must
    be in the local allowlist and the caller must be a known category, so no
    arbitrary name or address is ever echoed.
    """

    if not isinstance(value, Mapping):
        return None
    if any(not isinstance(name, str) or name not in _CALL_FIELDS for name in value):
        return None
    if value.get("event") != "call":
        return None
    schema = value.get("schema")
    if not isinstance(schema, int) or isinstance(schema, bool) or schema != CALL_SCHEMA:
        return None
    phase = value.get("phase")
    if not isinstance(phase, str) or phase not in _CALL_PHASES:
        return None
    symbol = value.get("symbol")
    if not isinstance(symbol, str) or symbol not in P2PAPI_SYMBOLS:
        return None
    caller = value.get("caller")
    if not isinstance(caller, str) or caller not in MODULE_CATEGORIES:
        return None
    call = value.get("call")
    if not isinstance(call, int) or isinstance(call, bool) or not 0 < call <= _MAX_CALL_ID:
        return None
    thread = value.get("thread")
    if not _tagged(thread, _THREAD_TAG, allow_unknown=True):
        return None
    at = value.get("at")
    if not isinstance(at, int) or isinstance(at, bool) or not 0 <= at <= _MAX_TIMESTAMP_MS:
        return None
    return {
        "event": "call",
        "schema": schema,
        "call": call,
        "phase": phase,
        "symbol": symbol,
        "caller": caller,
        "thread": thread,
        "at": at,
    }


def valid_call_coverage(value: Any) -> dict[str, Any] | None:
    """Validate a P2PAPI control-flow coverage record.

    The desired set is the fixed local allowlist, not a producer value, so a
    capture cannot shrink it to look complete. Completeness is derived.
    """

    if not isinstance(value, Mapping):
        return None
    if any(not isinstance(name, str) or name not in _CALL_COVERAGE_FIELDS for name in value):
        return None
    if value.get("event") != "call-coverage":
        return None
    schema = value.get("schema")
    if not isinstance(schema, int) or isinstance(schema, bool) or schema != CALL_SCHEMA:
        return None

    def symbols(item: Any) -> list[str] | None:
        if not isinstance(item, list) or len(item) > len(P2PAPI_SYMBOLS):
            return None
        if not all(isinstance(name, str) and name in P2PAPI_SYMBOLS for name in item):
            return None
        if len(set(item)) != len(item):
            return None
        return sorted(item)

    installed = symbols(value.get("installed"))
    missing = symbols(value.get("missing"))
    if installed is None or missing is None:
        return None
    if set(installed) & set(missing):
        return None
    if set(installed) | set(missing) != P2PAPI_SYMBOLS:
        return None
    errors = value.get("errors")
    if not isinstance(errors, int) or isinstance(errors, bool) or not 0 <= errors <= 1_000_000:
        return None
    complete = value.get("complete")
    if not isinstance(complete, bool):
        return None
    derived = set(installed) == P2PAPI_SYMBOLS
    if complete != derived:
        return None
    return {
        "event": "call-coverage",
        "schema": schema,
        "installed": installed,
        "missing": missing,
        "complete": derived,
        "errors": errors,
    }


# P2PAPI AV-data callback measurement.
#
# The installed P2PAPI.dll delivers media by invoking a caller-supplied callback
# registered through P2PAPI_SetAVDataCallBack. The vendor cam_pc header
# (P2P_API_Define.h) declares that callback as
#
#     void (*AVDataCallback)(long nHandle, int bVideo, char *pData, int len, void *pParam)
#
# and its five-argument arity matches the installed DLL as measured offline.
# The measurement counts invocations, reduces the bVideo flag to a closed kind,
# and reduces the len argument to a broad size bucket. It never records the
# handle, the data pointer, the raw length, the parameter, or any frame byte.
# The field sets below are closed, so none of those can be serialized even if a
# producer tried.
#
# The len bucket vocabulary is the shared size vocabulary (BUCKETS) plus an
# ``unreadable`` sentinel for a length that could not be classified at all: a
# failed read, a negative 32-bit value (overflow), or a value above the vendor
# header's MAX_FRAME_BUF_SIZE (512 KiB), which is not a plausible media length.
AV_CALLBACK_SCHEMA = 2
AV_CALLBACK_EXPORT = "P2PAPI_SetAVDataCallBack"
AV_CALLBACK_KINDS = frozenset({"video", "audio", "other"})
AV_CALLBACK_STATES = frozenset({"set", "cleared"})
AV_CALLBACK_SIZE_BUCKETS = BUCKETS | frozenset({"unreadable"})
AV_CALLBACK_MAX_LEN = 512 * 1024
_AV_CALLBACK_EVENT_FIELDS = frozenset({"event", "schema", "kind", "size", "thread", "at"})
_AV_REGISTRATION_FIELDS = frozenset({"event", "schema", "state", "thread", "at"})
_AV_COVERAGE_FIELDS = frozenset({
    "event", "schema", "registration_hook", "registered", "callback_attached",
    "complete", "errors",
})


def valid_av_callback_event(value: Any) -> dict[str, Any] | None:
    """Validate one AV-data callback invocation.

    The field set is closed, so a handle, pointer, buffer, raw length,
    parameter, frame byte or credential cannot pass even if a producer tried.
    The kind is reduced from the bVideo flag and the size from the len argument,
    each to a fixed vocabulary.
    """

    if not isinstance(value, Mapping):
        return None
    if any(not isinstance(name, str) or name not in _AV_CALLBACK_EVENT_FIELDS for name in value):
        return None
    if value.get("event") != "av-callback":
        return None
    schema = value.get("schema")
    if not isinstance(schema, int) or isinstance(schema, bool) or schema != AV_CALLBACK_SCHEMA:
        return None
    kind = value.get("kind")
    if not isinstance(kind, str) or kind not in AV_CALLBACK_KINDS:
        return None
    size = value.get("size")
    if not isinstance(size, str) or size not in AV_CALLBACK_SIZE_BUCKETS:
        return None
    thread = value.get("thread")
    if not _tagged(thread, _THREAD_TAG, allow_unknown=True):
        return None
    at = value.get("at")
    if not isinstance(at, int) or isinstance(at, bool) or not 0 <= at <= _MAX_TIMESTAMP_MS:
        return None
    return {
        "event": "av-callback",
        "schema": schema,
        "kind": kind,
        "size": size,
        "thread": thread,
        "at": at,
    }


def valid_av_registration_event(value: Any) -> dict[str, Any] | None:
    """Validate one observed P2PAPI_SetAVDataCallBack call.

    Only whether a callback was set or cleared is retained; the callback
    pointer and its parameter never cross this boundary.
    """

    if not isinstance(value, Mapping):
        return None
    if any(not isinstance(name, str) or name not in _AV_REGISTRATION_FIELDS for name in value):
        return None
    if value.get("event") != "av-registration":
        return None
    schema = value.get("schema")
    if not isinstance(schema, int) or isinstance(schema, bool) or schema != AV_CALLBACK_SCHEMA:
        return None
    state = value.get("state")
    if not isinstance(state, str) or state not in AV_CALLBACK_STATES:
        return None
    thread = value.get("thread")
    if not _tagged(thread, _THREAD_TAG, allow_unknown=True):
        return None
    at = value.get("at")
    if not isinstance(at, int) or isinstance(at, bool) or not 0 <= at <= _MAX_TIMESTAMP_MS:
        return None
    return {
        "event": "av-registration",
        "schema": schema,
        "state": state,
        "thread": thread,
        "at": at,
    }


def valid_av_callback_coverage(value: Any) -> dict[str, Any] | None:
    """Validate the AV-callback tracer's coverage record.

    Completeness is derived, never trusted: the registration entry point must be
    hooked and a non-null callback must have been attached at least once. The
    current registration state is reported separately and may legitimately be
    false after the client clears its callback. An absent callback therefore
    yields an incomplete record rather than a false success.
    """

    if not isinstance(value, Mapping):
        return None
    if any(not isinstance(name, str) or name not in _AV_COVERAGE_FIELDS for name in value):
        return None
    if value.get("event") != "av-callback-coverage":
        return None
    schema = value.get("schema")
    if not isinstance(schema, int) or isinstance(schema, bool) or schema != AV_CALLBACK_SCHEMA:
        return None
    flags = {}
    for name in ("registration_hook", "registered", "callback_attached", "complete"):
        item = value.get(name)
        if not isinstance(item, bool):
            return None
        flags[name] = item
    errors = value.get("errors")
    if not isinstance(errors, int) or isinstance(errors, bool) or not 0 <= errors <= 1_000_000:
        return None
    derived = flags["registration_hook"] and flags["callback_attached"]
    if flags["complete"] != derived:
        return None
    return {
        "event": "av-callback-coverage",
        "schema": schema,
        "registration_hook": flags["registration_hook"],
        "registered": flags["registered"],
        "callback_attached": flags["callback_attached"],
        "complete": derived,
        "errors": errors,
    }


def valid_wininet_event(value: Any) -> dict[str, Any] | None:
    """Return a normalized WinINet URL-shape event, or fail closed.

    The validator deliberately accepts only tags from fixed local domains. A
    URL, unknown hostname/route/query name, credential, address, or extra field
    therefore cannot cross the tracer-to-capture boundary.
    """

    if not isinstance(value, Mapping) or set(value) != _WININET_FIELDS:
        return None
    if value.get("event") != "wininet":
        return None
    schema = value.get("schema")
    if not isinstance(schema, int) or isinstance(schema, bool) or schema != WININET_SCHEMA:
        return None
    scheme = value.get("scheme")
    host = value.get("host")
    if not isinstance(scheme, str) or scheme not in WININET_SCHEMES:
        return None
    if not isinstance(host, str) or host not in WININET_HOSTS:
        return None

    def tags(item: Any, allowed: frozenset[str], maximum: int) -> list[str] | None:
        if not isinstance(item, list) or len(item) > maximum:
            return None
        if not all(isinstance(tag, str) and tag in allowed for tag in item):
            return None
        return list(item)

    path = tags(value.get("path"), WININET_ROUTES, WININET_MAX_SEGMENTS)
    query = tags(value.get("query"), WININET_QUERY_KEYS, WININET_MAX_QUERY_KEYS)
    if path is None or query is None:
        return None
    at = value.get("at")
    if not isinstance(at, int) or isinstance(at, bool) or not 0 <= at <= _MAX_TIMESTAMP_MS:
        return None
    return {
        "event": "wininet",
        "schema": schema,
        "scheme": scheme,
        "host": host,
        "path": path,
        "query": query,
        "at": at,
    }


def valid_wininet_coverage(value: Any) -> dict[str, Any] | None:
    """Validate a WinINet tracer coverage record.

    The desired hook set is the fixed local value, not a producer value, so a
    capture cannot shrink it to look complete. Completeness is derived, never
    trusted. The field set is closed, so an arbitrary key or free-form string
    cannot cross the boundary.
    """

    if not isinstance(value, Mapping):
        return None
    if any(not isinstance(name, str) or name not in _WININET_COVERAGE_FIELDS for name in value):
        return None
    if value.get("event") != "wininet-coverage":
        return None
    schema = value.get("schema")
    if not isinstance(schema, int) or isinstance(schema, bool) or schema != WININET_SCHEMA:
        return None

    def hooks(item: Any) -> list[str] | None:
        if not isinstance(item, list) or len(item) > len(WININET_DESIRED_HOOKS):
            return None
        if not all(isinstance(name, str) and name in WININET_DESIRED_HOOKS for name in item):
            return None
        if len(set(item)) != len(item):
            return None
        return sorted(item)

    installed = hooks(value.get("installed"))
    missing = hooks(value.get("missing"))
    if installed is None or missing is None:
        return None
    if set(installed) & set(missing):
        return None
    if set(installed) | set(missing) != WININET_DESIRED_HOOKS:
        return None
    errors = value.get("errors")
    if not isinstance(errors, int) or isinstance(errors, bool) or not 0 <= errors <= 1_000_000:
        return None
    complete = value.get("complete")
    if not isinstance(complete, bool):
        return None
    derived = set(installed) == WININET_DESIRED_HOOKS
    if complete != derived:
        return None
    return {
        "event": "wininet-coverage",
        "schema": schema,
        "installed": installed,
        "missing": missing,
        "complete": derived,
        "errors": errors,
    }
