
"""Tests for Phishalyzer application configuration."""

import pytest
from pydantic import ValidationError

from phishalyzer.core.config import Settings, get_settings


def test_default_settings(monkeypatch):
    """Verify default application settings."""
    for key in [
        "APP_NAME",
        "APP_ENV",
        "LOG_LEVEL",
        "REQUEST_TIMEOUT",
        "MAX_REDIRECTS",
    ]:
        monkeypatch.delenv(key, raising=False)

    settings = Settings(_env_file=None)

    assert settings.app_name == "Phishalyzer"
    assert settings.app_env == "development"
    assert settings.log_level == "INFO"
    assert settings.request_timeout == 10
    assert settings.max_redirects == 5


def test_environment_variable_loading(monkeypatch):
    """Verify settings load correctly from environment variables."""
    monkeypatch.setenv("APP_NAME", "Phishalyzer-Test")
    monkeypatch.setenv("REQUEST_TIMEOUT", "20")

    settings = Settings(_env_file=None)

    assert settings.app_name == "Phishalyzer-Test"
    assert settings.request_timeout == 20


@pytest.mark.parametrize("timeout", [0, -1, 61, 100])
def test_invalid_request_timeout(timeout):
    """Reject invalid HTTP request timeouts."""
    with pytest.raises(ValidationError):
        Settings(request_timeout=timeout, _env_file=None)


@pytest.mark.parametrize("redirects", [-1, 11, 100])
def test_invalid_max_redirects(redirects):
    """Reject invalid redirect limits."""
    with pytest.raises(ValidationError):
        Settings(max_redirects=redirects, _env_file=None)


def test_valid_risk_thresholds():
    """Accept correctly ordered risk thresholds."""
    settings = Settings(_env_file=None)

    settings.validate_risk_thresholds()


def test_invalid_risk_threshold_order():
    """Reject risk thresholds that are not strictly increasing."""
    settings = Settings(
        risk_low_max=50,
        risk_moderate_max=40,
        risk_high_max=74,
        risk_critical_max=100,
        _env_file=None,
    )

    with pytest.raises(ValueError, match="strictly increasing"):
        settings.validate_risk_thresholds()


def test_duplicate_risk_thresholds():
    """Reject duplicate risk thresholds."""
    settings = Settings(
        risk_low_max=24,
        risk_moderate_max=24,
        risk_high_max=74,
        risk_critical_max=100,
        _env_file=None,
    )

    with pytest.raises(ValueError, match="strictly increasing"):
        settings.validate_risk_thresholds()


def test_api_keys_are_secret():
    """Ensure API keys are not exposed in settings representations."""
    secret = "test-secret-api-key"

    settings = Settings(
        virustotal_api_key=secret,
        _env_file=None,
    )

    assert settings.virustotal_api_key.get_secret_value() == secret
    assert secret not in repr(settings)


def test_settings_cache(monkeypatch):
    """Verify that application settings are cached."""
    get_settings.cache_clear()

    monkeypatch.setenv("APP_NAME", "Phishalyzer-Cache-Test")

    try:
        first = get_settings()
        second = get_settings()

        assert first is second
        assert first.app_name == "Phishalyzer-Cache-Test"
    finally:
        get_settings.cache_clear()
