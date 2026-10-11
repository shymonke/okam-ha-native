from pathlib import Path


ROOT = Path(__file__).parents[1]
COMPONENT = ROOT / "custom_components" / "okam"


def test_setup_translates_auth_before_connectivity_errors() -> None:
    source = (COMPONENT / "__init__.py").read_text(encoding="utf-8")
    setup = source.split("async def async_setup_entry(", 1)[1].split(
        "async def async_unload_entry(", 1
    )[0]
    assert "try:\n        await api.configure(camera_id, idle_timeout)" in setup
    assert "except OkamAuthError as exc:" in setup
    assert "raise ConfigEntryAuthFailed(str(exc)) from exc" in setup
    assert "except OkamApiError as exc:" in setup
    assert "raise ConfigEntryNotReady(str(exc)) from exc" in setup
    assert setup.index("except OkamAuthError") < setup.index("except OkamApiError")
    assert setup.index("raise ConfigEntryNotReady") < setup.index(
        "await coordinator.async_config_entry_first_refresh()"
    )


def test_polling_triggers_reauth_but_retries_connectivity_errors() -> None:
    source = (COMPONENT / "coordinator.py").read_text(encoding="utf-8")
    update = source.split("async def _async_update_data(", 1)[1]
    assert "return await self.api.status(self.camera_id)" in update
    assert "except OkamAuthError as exc:" in update
    assert "raise ConfigEntryAuthFailed(str(exc)) from exc" in update
    assert "except OkamApiError as exc:" in update
    assert "raise UpdateFailed(str(exc)) from exc" in update
    assert update.index("except OkamAuthError") < update.index("except OkamApiError")


def test_reconfigure_updates_identity_and_rejects_other_entries() -> None:
    source = (COMPONENT / "config_flow.py").read_text(encoding="utf-8")
    reconfigure = source.split("async def async_step_reconfigure(", 1)[1].split(
        "async def async_step_reauth(", 1
    )[0]
    assert 'unique_id = f"{data[CONF_BRIDGE_URL].lower()}#{data[CONF_CAMERA_ID]}"' in reconfigure
    assert "other.unique_id == unique_id and other.entry_id != entry.entry_id" in reconfigure
    assert "self._async_current_entries(include_ignore=False)" in reconfigure
    assert 'return self.async_abort(reason="already_configured")' in reconfigure
    assert "entry, data=data, unique_id=unique_id" in reconfigure
    assert reconfigure.index("other.unique_id == unique_id") < reconfigure.index(
        "self.async_update_reload_and_abort("
    )


def test_integration_translations_remain_identical() -> None:
    assert (COMPONENT / "strings.json").read_bytes() == (
        COMPONENT / "translations" / "en.json"
    ).read_bytes()
