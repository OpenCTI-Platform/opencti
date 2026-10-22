from pathlib import Path
from typing import Any, Dict

import pytest

from opencti_analytics.config import (
    DEFAULT_RELATIONSHIP_TYPES,
    Settings,
    load_config_file,
    load_settings,
)


def base_config(**analytics: Any) -> Dict[str, Any]:
    return {
        "opencti": {"url": "http://opencti:8080", "token": "file-token"},
        "analytics": analytics,
    }


class TestDefaults:
    def test_defaults(self) -> None:
        settings = load_settings(base_config())
        assert settings == Settings(
            opencti_url="http://opencti:8080", opencti_token="file-token"
        )
        assert settings.enabled is True
        assert settings.run_interval_hours == 24.0
        assert settings.run_on_start is True
        assert settings.min_edges == 50000
        assert settings.force is False
        assert settings.relationship_types == DEFAULT_RELATIONSHIP_TYPES
        assert "object" in settings.relationship_types
        assert settings.include_inferred is False
        assert settings.max_edges == 5_000_000
        assert settings.max_container_size == 500
        assert settings.max_node_degree == 10000
        assert settings.min_cluster_size == 3
        assert settings.max_cluster_size == 5000
        assert settings.betweenness_sample_size == 500
        assert settings.betweenness_cutoff is None
        assert settings.batch_size == 2000
        assert settings.engine == "auto"
        assert settings.telemetry_enabled is False
        assert settings.run_interval_seconds == 86400.0
        # The token sent has Bypass privileges: the certificate is verified by default
        assert settings.opencti_ssl_verify is True

    def test_certificate_verification_opt_out(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENCTI_SSL_VERIFY", "false")
        assert load_settings(base_config()).opencti_ssl_verify is False


class TestPrecedence:
    def test_file_values(self) -> None:
        settings = load_settings(
            base_config(
                min_edges=10,
                relationship_types=["uses", "object"],
                engine="networkx",
                run_interval_hours=0.5,
                betweenness_cutoff=4,
                force=True,
            )
        )
        assert settings.min_edges == 10
        assert settings.relationship_types == ("uses", "object")
        assert settings.engine == "networkx"
        assert settings.run_interval_seconds == 1800.0
        assert settings.betweenness_cutoff == 4
        assert settings.force is True

    def test_environment_overrides_file(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENCTI_TOKEN", "env-token")
        monkeypatch.setenv("ANALYTICS_MIN_EDGES", "123")
        monkeypatch.setenv("ANALYTICS_FORCE", "true")
        monkeypatch.setenv("ANALYTICS_RUN_ON_START", "false")
        monkeypatch.setenv("ANALYTICS_RELATIONSHIP_TYPES", "uses, object,uses,")
        monkeypatch.setenv("ANALYTICS_ENGINE", "IGRAPH")
        monkeypatch.setenv("ANALYTICS_BETWEENNESS_CUTOFF", "")
        settings = load_settings(
            base_config(min_edges=10, force=False, betweenness_cutoff=3)
        )
        assert settings.opencti_token == "env-token"
        assert settings.opencti_url == "http://opencti:8080"
        assert settings.min_edges == 123
        assert settings.force is True
        assert settings.run_on_start is False
        assert settings.relationship_types == ("uses", "object")
        assert settings.engine == "igraph"
        # pycti semantics: an empty variable means the default value
        assert settings.betweenness_cutoff is None

    def test_environment_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENCTI_URL", "http://env:8080")
        monkeypatch.setenv("OPENCTI_TOKEN", "env-token")
        monkeypatch.setenv("ANALYTICS_BATCH_SIZE", "5000")
        monkeypatch.setenv("ANALYTICS_TELEMETRY_ENABLED", "1")
        settings = load_settings({})
        assert settings.opencti_url == "http://env:8080"
        assert settings.batch_size == 5000
        assert settings.telemetry_enabled is True

    def test_zero_cutoff_disables_it(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANALYTICS_BETWEENNESS_CUTOFF", "0")
        assert load_settings(base_config()).betweenness_cutoff is None


class TestValidation:
    @pytest.mark.parametrize(
        "analytics",
        [
            {"engine": "graphx"},
            {"batch_size": 5001},
            {"batch_size": 0},
            {"cluster_batch_size": 1001},
            {"min_cluster_size": 1},
            {"min_cluster_size": 10, "max_cluster_size": 5},
            {"run_interval_hours": 0},
            {"min_edges": "many"},
            {"force": "maybe"},
            {"betweenness_sample_size": -1},
        ],
    )
    def test_invalid_values(self, analytics: Dict[str, Any]) -> None:
        with pytest.raises(ValueError):
            load_settings(base_config(**analytics))

    def test_url_and_token_are_required(self) -> None:
        with pytest.raises(ValueError, match="opencti.url"):
            load_settings({"opencti": {"token": "t"}})
        with pytest.raises(ValueError, match="opencti.token"):
            load_settings({"opencti": {"url": "http://x"}})


class TestConfigFile:
    def test_missing_file(self, tmp_path: Path) -> None:
        assert load_config_file(str(tmp_path / "config.yml")) == {}

    def test_sample_file_parses(self) -> None:
        sample = Path(__file__).parent.parent / "config.yml.sample"
        config = load_config_file(str(sample))
        config["opencti"]["token"] = "token"
        settings = load_settings(config)
        assert settings.relationship_types == DEFAULT_RELATIONSHIP_TYPES
        assert settings.betweenness_cutoff is None
        assert settings == Settings(
            opencti_url="http://localhost:8080", opencti_token="token"
        )

    def test_non_mapping_file(self, tmp_path: Path) -> None:
        path = tmp_path / "config.yml"
        path.write_text("- a\n- b\n", encoding="utf-8")
        assert load_config_file(str(path)) == {}
