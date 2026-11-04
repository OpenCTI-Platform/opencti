"""Tests for boolean parsing in get_config_variable (issue #19065)."""

import pytest

from pycti.connector.opencti_connector_helper import (
    get_config_variable,
    parse_boolean_config,
)

ENV = "OPENCTI_TEST_BOOLEAN_SETTING"
YAML_PATH = ["opencti", "test_boolean_setting"]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv(ENV, raising=False)


@pytest.mark.parametrize(
    "raw",
    ["true", "True", "TRUE", "yes", "Yes", "YES", "on", "On", "ON", "1", " true "],
)
def test_env_truthy_values_with_bool_default(monkeypatch, raw):
    monkeypatch.setenv(ENV, raw)
    assert get_config_variable(ENV, YAML_PATH, {}, False, False) is True


@pytest.mark.parametrize(
    "raw",
    ["false", "False", "FALSE", "no", "No", "NO", "off", "Off", "OFF", "0", " 0 "],
)
def test_env_falsy_values_with_bool_default(monkeypatch, raw):
    monkeypatch.setenv(ENV, raw)
    assert get_config_variable(ENV, YAML_PATH, {}, False, True) is False


def test_issue_19065_reproduction(monkeypatch):
    # OPENCTI_JSON_LOGGING=0 must disable JSON logging (default True)
    monkeypatch.setenv("OPENCTI_JSON_LOGGING", "0")
    value = get_config_variable(
        "OPENCTI_JSON_LOGGING", ["opencti", "json_logging"], {}, False, True
    )
    assert value is False


@pytest.mark.parametrize("raw", ["maybe", "2", "enabled", "tru", "-1"])
def test_env_unknown_value_raises_value_error(monkeypatch, raw):
    monkeypatch.setenv(ENV, raw)
    with pytest.raises(ValueError) as error:
        get_config_variable(ENV, YAML_PATH, {}, False, True)
    assert ENV in str(error.value)
    assert repr(raw) in str(error.value)


@pytest.mark.parametrize(
    "yaml_value,expected", [(True, True), (False, False), (1, True), (0, False)]
)
def test_yaml_native_values_with_bool_default(yaml_value, expected):
    config = {"opencti": {"test_boolean_setting": yaml_value}}
    assert get_config_variable(ENV, YAML_PATH, config, default=False) is expected


@pytest.mark.parametrize("yaml_value,expected", [("off", False), ("YES", True)])
def test_yaml_string_values_with_bool_default(yaml_value, expected):
    config = {"opencti": {"test_boolean_setting": yaml_value}}
    assert get_config_variable(ENV, YAML_PATH, config, default=True) is expected


def test_yaml_unknown_value_raises_value_error():
    config = {"opencti": {"test_boolean_setting": 5}}
    with pytest.raises(ValueError, match=ENV):
        get_config_variable(ENV, YAML_PATH, config, default=False)


def test_missing_value_returns_bool_default():
    assert get_config_variable(ENV, YAML_PATH, {}, default=True) is True
    assert get_config_variable(ENV, YAML_PATH, {}, default=False) is False


def test_empty_value_returns_bool_default(monkeypatch):
    monkeypatch.setenv(ENV, "")
    assert get_config_variable(ENV, YAML_PATH, {}, default=True) is True


def test_explicit_is_boolean_without_default(monkeypatch):
    monkeypatch.setenv(ENV, "Off")
    assert get_config_variable(ENV, YAML_PATH, {}, isBoolean=True) is False
    monkeypatch.setenv(ENV, "nope")
    with pytest.raises(ValueError, match=ENV):
        get_config_variable(ENV, YAML_PATH, {}, isBoolean=True)


def test_explicit_is_boolean_missing_returns_none():
    assert get_config_variable(ENV, YAML_PATH, {}, isBoolean=True) is None


def test_explicit_is_boolean_required_raises_when_missing(monkeypatch):
    monkeypatch.setenv(ENV, "")
    with pytest.raises(ValueError, match="is required"):
        get_config_variable(ENV, YAML_PATH, {}, isBoolean=True, required=True)


def test_non_boolean_setting_keeps_legacy_behaviour(monkeypatch):
    # No bool default: strings are returned as-is, legacy spellings still map
    monkeypatch.setenv(ENV, "INFO")
    assert get_config_variable(ENV, YAML_PATH, {}, default="error") == "INFO"
    monkeypatch.setenv(ENV, "true")
    assert get_config_variable(ENV, YAML_PATH, {}) is True
    monkeypatch.setenv(ENV, "0")
    assert get_config_variable(ENV, YAML_PATH, {}) == "0"


def test_is_boolean_false_disables_inference(monkeypatch):
    monkeypatch.setenv(ENV, "/etc/ssl/ca.pem")
    value = get_config_variable(ENV, YAML_PATH, {}, False, False, isBoolean=False)
    assert value == "/etc/ssl/ca.pem"


def test_number_setting_unchanged(monkeypatch):
    monkeypatch.setenv(ENV, "42")
    assert get_config_variable(ENV, YAML_PATH, {}, isNumber=True, default=7) == 42


def test_parse_boolean_config_not_strict_keeps_unknown_value():
    path = "/etc/ssl/ca.pem"
    assert parse_boolean_config(ENV, "OFF", strict=False) is False
    assert parse_boolean_config(ENV, path, strict=False) == path


def test_parse_boolean_config_rejects_none_when_strict():
    with pytest.raises(ValueError, match=ENV):
        parse_boolean_config(ENV, None)
