import pytest

from okam_native.redaction import (
    DESIRED_HOOKS,
    WININET_DESIRED_HOOKS,
    allowlisted,
    opaque_tag,
    safe_json_line,
    sanitize,
    valid_coverage,
    valid_legacy_transport_event,
    valid_transport_event,
    valid_wininet_coverage,
)


def test_sensitive_fields_are_fail_closed() -> None:
    source = {
        "username": "person@example.com",
        "password": "top-secret",
        "device_id": "CAMERA-123",
        "nested": {"token": "abc"},
    }
    result = sanitize(source)
    rendered = safe_json_line(source)
    assert result["password"]["redacted"] is True
    assert result["device_id"]["redacted"] is True
    assert "top-secret" not in rendered
    assert "CAMERA-123" not in rendered
    assert "person@example.com" not in rendered


def test_url_query_values_are_redacted_but_routes_remain() -> None:
    rendered = safe_json_line({"url": "https://api.eye4.cn/login/token?userid=42&code=secret"})
    assert "/login/token" in rendered
    assert "userid=42" not in rendered
    assert "code=secret" not in rendered


def test_tags_correlate_without_revealing_values() -> None:
    assert opaque_tag("same") == opaque_tag(b"same")
    assert "same" not in opaque_tag("same")


def test_vp_sensitive_fields_are_fail_closed() -> None:
    security = "S" * 32
    address = "A1B2C3" * 10
    service = "encoded-value:transport-key"
    source = {
        "security": security,
        "address": address,
        "service_parameter": service,
        "signature": "c2lnbmF0dXJl",
        "nested": {"vuid": "SYNTHETIC12345A", "cluster": 3},
    }
    rendered = safe_json_line(source)
    for sentinel in (security, address, service, "c2lnbmF0dXJl", "SYNTHETIC12345A"):
        assert sentinel not in rendered


def test_url_userinfo_and_path_values_are_redacted() -> None:
    rendered = safe_json_line(
        {"url": "https://person:hunter2@vuid-vp.eye4.cn/vuid/query?vuid=SYNTHETIC12345A&n=1"}
    )
    assert "person:hunter2" not in rendered
    assert "SYNTHETIC12345A" not in rendered
    assert "/vuid/query" in rendered
    assert "vuid-vp.eye4.cn" in rendered


def test_alphabetic_path_secret_is_redacted() -> None:
    secret = "AbCdEfGhIjKlMnOpQrSt"
    rendered = safe_json_line({"url": f"https://api.eye4.cn/PC/device/show/{secret}"})
    assert secret not in rendered
    assert "/PC/device/show" in rendered


def test_non_public_host_is_redacted() -> None:
    rendered = safe_json_line({"url": "https://camera.example.test/login/token"})
    assert "example.test" not in rendered
    assert "/login/token" in rendered


def test_url_fragment_is_dropped() -> None:
    rendered = safe_json_line({"url": "https://api.eye4.cn/login/token#FRAGMENT-SECRET"})
    assert "FRAGMENT-SECRET" not in rendered
    assert "/login/token" in rendered


def test_path_identifiers_are_redacted_but_routes_survive() -> None:
    rendered = safe_json_line({"url": "https://api.example.test/PC/device/show/SYNTHETIC12345A"})
    assert "/PC/device/show" in rendered
    assert "SYNTHETIC12345A" not in rendered


def test_allowlist_drops_unknown_payload_fields() -> None:
    event = {
        "length": 10,
        "prefix": "000d",
        "did": "SYNTHETIC12345A",
        "unexpected_payload": "raw-camera-bytes",
    }
    result = allowlisted(event, ["length", "prefix", "did"])
    assert set(result) == {"length", "prefix", "did"}
    assert result["length"] == 10
    assert result["did"]["redacted"] is True
    assert "raw-camera-bytes" not in safe_json_line(result)


def _event(**overrides) -> dict:
    event = {
        "direction": "send",
        "call": "sendto",
        "module": "P2PAPI.dll",
        "peer": "peer-1",
        "socket": "socket-1",
        "length": 9,
        "prefix": "0d04",
        "bucket": "tiny<40",
        "at": 12,
    }
    event.update(overrides)
    return event


def test_valid_transport_event_accepts_a_well_formed_event() -> None:
    assert valid_transport_event(_event()) == _event()


def test_valid_transport_event_rejects_nested_and_unknown_values() -> None:
    assert valid_transport_event(_event(module={"nested": "leak"})) is None
    assert valid_transport_event(_event(peer={"nested": "leak"})) is None
    assert valid_transport_event(_event(prefix=["0d", "04"])) is None
    # An unexpected field rejects the whole event rather than being dropped.
    assert valid_transport_event(_event(raw="payload-bytes")) is None


def test_valid_transport_event_rejects_malformed_fields() -> None:
    assert valid_transport_event("not-a-dict") is None
    assert valid_transport_event(_event(direction="sideways")) is None
    assert valid_transport_event(_event(call="printf")) is None
    assert valid_transport_event(_event(module="../etc/passwd")) is None
    assert valid_transport_event(_event(peer="192.168.1.5:1234")) is None
    assert valid_transport_event(_event(socket="192.168.1.5")) is None
    assert valid_transport_event(_event(length=-1)) is None
    assert valid_transport_event(_event(length=70000)) is None
    assert valid_transport_event(_event(length=True)) is None
    assert valid_transport_event(_event(prefix="0D04")) is None
    assert valid_transport_event(_event(bucket="huge")) is None
    assert valid_transport_event(_event(at=-5)) is None


def test_valid_transport_event_rejects_an_impossible_short_prefix() -> None:
    assert valid_transport_event(_event(length=1, prefix="0d")) is None
    assert valid_transport_event(_event(length=1, prefix="unreadable")) is not None


@pytest.mark.parametrize("field", [
    "direction", "call", "module", "peer", "socket", "length", "prefix", "bucket", "at",
])
def test_validator_rejects_nested_values_for_every_field(field: str) -> None:
    # A dict or list in any field must reject without raising TypeError.
    assert valid_transport_event(_event(**{field: {"nested": "leak"}})) is None
    assert valid_transport_event(_event(**{field: ["nested"]})) is None


def test_validator_enforces_direction_and_call_consistency() -> None:
    assert valid_transport_event(_event(direction="send", call="recvfrom")) is None
    assert valid_transport_event(_event(direction="recv", call="sendto")) is None
    assert valid_transport_event(_event(direction="recv", call="recvfrom")) is not None


def test_validator_enforces_bucket_and_length_consistency() -> None:
    assert valid_transport_event(_event(length=9, bucket="large>=1000")) is None
    assert valid_transport_event(_event(length=1500, bucket="large>=1000")) is not None


def test_validator_requires_the_current_socket_tag() -> None:
    without = _event()
    del without["socket"]
    assert valid_transport_event(without) is None


def _coverage(**overrides) -> dict:
    record = {
        "event": "coverage",
        "schema": 2,
        "phase": "installed",
        "installed": ["sendto"],
        "missing": sorted(DESIRED_HOOKS - {"sendto"}),
        "desired": sorted(DESIRED_HOOKS),
        "complete": False,
        "errors": 0,
    }
    record.update(overrides)
    return record


def test_coverage_completeness_is_derived_not_trusted() -> None:
    # Producer claims complete while hooks are missing.
    assert valid_coverage(_coverage(complete=True)) is None
    # Producer claims incomplete while everything is installed.
    full = sorted(DESIRED_HOOKS)
    assert valid_coverage(_coverage(installed=full, missing=[], complete=False)) is None
    # Consistent records are accepted and carry the derived value.
    accepted = valid_coverage(_coverage())
    assert accepted is not None and accepted["complete"] is False
    full_ok = valid_coverage(_coverage(installed=full, missing=[], complete=True))
    assert full_ok is not None and full_ok["complete"] is True


def test_coverage_rejects_a_shrunk_desired_set() -> None:
    # Synthetic record that would look complete if `desired` were trusted.
    assert valid_coverage({
        "event": "coverage", "schema": 2, "phase": "installed", "installed": [],
        "missing": ["sendto"], "desired": ["sendto"], "complete": True, "errors": 0,
    }) is None


def test_coverage_rejects_overlapping_partitions() -> None:
    assert valid_coverage(_coverage(installed=["sendto"], missing=["sendto"])) is None


def test_coverage_rejects_arbitrary_keys_and_phases() -> None:
    assert valid_coverage(_coverage(extra="value")) is None
    assert valid_coverage(_coverage(phase="invented")) is None
    assert valid_coverage(_coverage(installed=["not-a-hook"])) is None
    assert valid_coverage(_coverage(schema=1)) is None


def test_validator_accepts_connected_socket_calls() -> None:
    connect = _event(direction="connect", call="connect", length=0,
                     prefix="unreadable", bucket="tiny<40")
    assert valid_transport_event(connect) == connect
    assert valid_transport_event(_event(direction="send", call="send")) is not None
    assert valid_transport_event(_event(direction="recv", call="recv")) is not None


def test_validator_rejects_cross_direction_calls() -> None:
    assert valid_transport_event(_event(direction="connect", call="sendto")) is None
    assert valid_transport_event(_event(direction="send", call="connect")) is None
    assert valid_transport_event(_event(direction="connect", call="connect",
                                        length=9, prefix="0d04", bucket="tiny<40")) is None


def _legacy(**overrides) -> dict:
    record = {
        "direction": "send", "call": "sendto", "module": "P2PAPI.dll", "peer": "peer-1",
        "length": 9, "prefix": "000d", "bucket": "tiny<40", "at": 0,
    }
    record.update(overrides)
    return record


def test_legacy_module_values_are_normalized() -> None:
    assert valid_legacy_transport_event(_legacy())["module"] == "P2PAPI.dll"
    # An unknown legacy module must never be echoed into the summary.
    assert valid_legacy_transport_event(_legacy(module="PrivateSentinel.dll"))["module"] == "other"
    assert valid_legacy_transport_event(_legacy(module="../etc/passwd")) is None


def test_legacy_capture_is_not_a_current_event() -> None:
    assert valid_legacy_transport_event(_legacy()) is not None
    assert valid_transport_event(_legacy()) is None


def test_only_exact_public_hosts_survive() -> None:
    subdomain = safe_json_line({"url": "https://secret.eye4.cn/login/token"})
    assert "secret.eye4.cn" not in subdomain
    assert "/login/token" in subdomain
    exact = safe_json_line({"url": "https://vuid-vp.eye4.cn:8443/vuid/query?vuid=SYNTHETIC"})
    assert "vuid-vp.eye4.cn" in exact
    assert "8443" not in exact


def test_unknown_query_keys_are_omitted() -> None:
    rendered = safe_json_line({"url": "https://api.eye4.cn/login/token?userid=1&injected=secret"})
    assert "injected" not in rendered
    assert "userid" in rendered
    assert "secret" not in rendered


def _wininet_coverage(**overrides) -> dict:
    record = {
        "event": "wininet-coverage",
        "schema": 1,
        "installed": sorted(WININET_DESIRED_HOOKS),
        "missing": [],
        "complete": True,
        "errors": 0,
    }
    record.update(overrides)
    return record


def test_wininet_coverage_completeness_is_derived_not_trusted() -> None:
    # Claims complete while the required hook is missing.
    assert valid_wininet_coverage(
        _wininet_coverage(installed=[], missing=sorted(WININET_DESIRED_HOOKS), complete=True)
    ) is None
    # Claims incomplete while everything is installed.
    assert valid_wininet_coverage(_wininet_coverage(complete=False)) is None
    # Consistent records are accepted and carry the derived value.
    full = valid_wininet_coverage(_wininet_coverage())
    assert full is not None and full["complete"] is True
    partial = valid_wininet_coverage(
        _wininet_coverage(installed=[], missing=sorted(WININET_DESIRED_HOOKS), complete=False)
    )
    assert partial is not None and partial["complete"] is False


def test_wininet_coverage_rejects_unexpected_values() -> None:
    assert valid_wininet_coverage("not-a-dict") is None
    assert valid_wininet_coverage(_wininet_coverage(extra="leak")) is None
    assert valid_wininet_coverage(_wininet_coverage(installed=["not-a-hook"])) is None
    assert valid_wininet_coverage(_wininet_coverage(installed=["InternetOpenUrlA"] * 2)) is None
    assert valid_wininet_coverage(_wininet_coverage(schema=2)) is None
    assert valid_wininet_coverage(_wininet_coverage(errors=-1)) is None
    assert valid_wininet_coverage(_wininet_coverage(errors=True)) is None
    # A shrunk desired set cannot be smuggled through: the union must equal the
    # fixed local set, so a one-element subset is the only accepted partition.
    assert valid_wininet_coverage(
        _wininet_coverage(installed=[], missing=["InternetOpenUrlA"], complete=True)
    ) is None
    assert valid_wininet_coverage(
        _wininet_coverage(installed=[], missing=[], complete=False)
    ) is None
