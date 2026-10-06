"""Configuration: `config.yml` values, overridden by environment variables.

Every `analytics.<key>` entry can be set with the `ANALYTICS_<KEY>` environment
variable, every `opencti.<key>` entry with `OPENCTI_<KEY>`.
"""

import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import yaml
from pycti.connector.opencti_connector_helper import get_config_variable

DEFAULT_RELATIONSHIP_TYPES: Tuple[str, ...] = (
    "communicates-with",
    "resolves-to",
    "consists-of",
    "uses",
    "attributed-to",
    "related-to",
    "based-on",
    "object",
)
ENGINES: Tuple[str, ...] = ("auto", "igraph", "networkx")

# Limits enforced by the platform on graphAnalyticsUpsertMetrics
MAX_UPSERT_METRICS = 5000
MAX_UPSERT_CLUSTERS = 1000


@dataclass(frozen=True)
class Settings:  # pylint: disable=too-many-instance-attributes
    opencti_url: str = ""
    opencti_token: str = ""
    # The token sent has Bypass privileges: verified unless the operator opts out
    opencti_ssl_verify: bool = True
    opencti_json_logging: bool = True
    opencti_requests_timeout: int = 300
    opencti_custom_headers: Optional[str] = None
    log_level: str = "info"
    enabled: bool = True
    run_interval_hours: float = 24.0
    run_on_start: bool = True
    min_edges: int = 50000
    force: bool = False
    relationship_types: Tuple[str, ...] = DEFAULT_RELATIONSHIP_TYPES
    include_inferred: bool = False
    max_edges: int = 5_000_000
    max_container_size: int = 500
    max_node_degree: int = 10000
    min_cluster_size: int = 3
    max_cluster_size: int = 5000
    betweenness_sample_size: int = 500
    betweenness_cutoff: Optional[int] = None
    batch_size: int = 2000
    cluster_batch_size: int = 200
    engine: str = "auto"
    seed: int = 42
    telemetry_enabled: bool = False
    telemetry_prometheus_port: int = 14271
    telemetry_prometheus_host: str = "0.0.0.0"

    @property
    def run_interval_seconds(self) -> float:
        return self.run_interval_hours * 3600.0


def load_config_file(path: str) -> Dict[str, Any]:
    if not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        content = yaml.safe_load(f)
    return content if isinstance(content, dict) else {}


def _raw(section: str, key: str, config: Dict[str, Any]) -> Any:
    env_var = f"{section.upper()}_{key.upper()}"
    return get_config_variable(env_var, [section, key], config, default=None)


def _name(section: str, key: str) -> str:
    return f"{section}.{key} ({section.upper()}_{key.upper()})"


def _to_bool(value: Any, name: str, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("1", "yes", "true", "on"):
            return True
        if normalized in ("0", "no", "false", "off"):
            return False
    raise ValueError(f"Invalid boolean for {name}: {value!r}")


def _to_int(
    value: Any,
    name: str,
    default: Optional[int],
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
) -> Optional[int]:
    if value is None or (isinstance(value, str) and value.strip() == ""):
        return default
    if isinstance(value, bool):
        raise ValueError(f"Invalid integer for {name}: {value!r}")
    try:
        result = int(str(value).strip().replace("_", ""))
    except ValueError as e:
        raise ValueError(f"Invalid integer for {name}: {value!r}") from e
    if minimum is not None and result < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {result}")
    if maximum is not None and result > maximum:
        raise ValueError(f"{name} must be <= {maximum}, got {result}")
    return result


def _to_required_int(
    value: Any,
    name: str,
    default: int,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
) -> int:
    result = _to_int(value, name, default, minimum, maximum)
    return default if result is None else result


def _to_float(value: Any, name: str, default: float, minimum: float) -> float:
    if value is None or (isinstance(value, str) and value.strip() == ""):
        return default
    if isinstance(value, bool):
        raise ValueError(f"Invalid number for {name}: {value!r}")
    try:
        result = float(str(value).strip())
    except ValueError as e:
        raise ValueError(f"Invalid number for {name}: {value!r}") from e
    if result <= minimum:
        raise ValueError(f"{name} must be > {minimum}, got {result}")
    return result


def _to_list(value: Any, default: Tuple[str, ...]) -> Tuple[str, ...]:
    if value is None:
        return default
    items: List[str] = []
    if isinstance(value, str):
        items = [item.strip() for item in value.split(",")]
    elif isinstance(value, (list, tuple)):
        items = [str(item).strip() for item in value]
    else:
        items = [str(value).strip()]
    result: List[str] = []
    for item in items:
        if item and item not in result:
            result.append(item)
    return tuple(result) if result else default


def _to_str(value: Any, default: str) -> str:
    if value is None:
        return default
    return str(value).strip() or default


def load_settings(config: Dict[str, Any]) -> Settings:
    """Build the settings from the YAML config, environment variables win."""

    def raw(key: str) -> Any:
        return _raw("analytics", key, config)

    def name(key: str) -> str:
        return _name("analytics", key)

    defaults = Settings()
    opencti_url = _to_str(_raw("opencti", "url", config), "")
    opencti_token = _to_str(_raw("opencti", "token", config), "")
    if not opencti_url:
        raise ValueError(f"{_name('opencti', 'url')} is required")
    if not opencti_token:
        raise ValueError(f"{_name('opencti', 'token')} is required")
    custom_headers = _raw("opencti", "custom_headers", config)

    engine = _to_str(raw("engine"), defaults.engine).lower()
    if engine not in ENGINES:
        raise ValueError(f"{name('engine')} must be one of {', '.join(ENGINES)}")
    min_cluster_size = _to_required_int(
        raw("min_cluster_size"), name("min_cluster_size"), defaults.min_cluster_size, 2
    )
    max_cluster_size = _to_required_int(
        raw("max_cluster_size"),
        name("max_cluster_size"),
        defaults.max_cluster_size,
        min_cluster_size,
    )
    cutoff = _to_int(raw("betweenness_cutoff"), name("betweenness_cutoff"), None, 0)
    return Settings(
        opencti_url=opencti_url,
        opencti_token=opencti_token,
        opencti_ssl_verify=_to_bool(
            _raw("opencti", "ssl_verify", config),
            _name("opencti", "ssl_verify"),
            defaults.opencti_ssl_verify,
        ),
        opencti_json_logging=_to_bool(
            _raw("opencti", "json_logging", config),
            _name("opencti", "json_logging"),
            defaults.opencti_json_logging,
        ),
        opencti_requests_timeout=_to_required_int(
            _raw("opencti", "requests_timeout", config),
            _name("opencti", "requests_timeout"),
            defaults.opencti_requests_timeout,
            1,
        ),
        opencti_custom_headers=str(custom_headers) if custom_headers else None,
        log_level=_to_str(raw("log_level"), defaults.log_level).lower(),
        enabled=_to_bool(raw("enabled"), name("enabled"), defaults.enabled),
        run_interval_hours=_to_float(
            raw("run_interval_hours"),
            name("run_interval_hours"),
            defaults.run_interval_hours,
            0.0,
        ),
        run_on_start=_to_bool(
            raw("run_on_start"), name("run_on_start"), defaults.run_on_start
        ),
        min_edges=_to_required_int(
            raw("min_edges"), name("min_edges"), defaults.min_edges, 0
        ),
        force=_to_bool(raw("force"), name("force"), defaults.force),
        relationship_types=_to_list(
            raw("relationship_types"), defaults.relationship_types
        ),
        include_inferred=_to_bool(
            raw("include_inferred"), name("include_inferred"), defaults.include_inferred
        ),
        max_edges=_to_required_int(
            raw("max_edges"), name("max_edges"), defaults.max_edges, 1
        ),
        max_container_size=_to_required_int(
            raw("max_container_size"),
            name("max_container_size"),
            defaults.max_container_size,
            1,
        ),
        max_node_degree=_to_required_int(
            raw("max_node_degree"), name("max_node_degree"), defaults.max_node_degree, 1
        ),
        min_cluster_size=min_cluster_size,
        max_cluster_size=max_cluster_size,
        betweenness_sample_size=_to_required_int(
            raw("betweenness_sample_size"),
            name("betweenness_sample_size"),
            defaults.betweenness_sample_size,
            0,
        ),
        betweenness_cutoff=cutoff if cutoff else None,
        batch_size=_to_required_int(
            raw("batch_size"),
            name("batch_size"),
            defaults.batch_size,
            1,
            MAX_UPSERT_METRICS,
        ),
        cluster_batch_size=_to_required_int(
            raw("cluster_batch_size"),
            name("cluster_batch_size"),
            defaults.cluster_batch_size,
            1,
            MAX_UPSERT_CLUSTERS,
        ),
        engine=engine,
        seed=_to_required_int(raw("seed"), name("seed"), defaults.seed, 0),
        telemetry_enabled=_to_bool(
            raw("telemetry_enabled"),
            name("telemetry_enabled"),
            defaults.telemetry_enabled,
        ),
        telemetry_prometheus_port=_to_required_int(
            raw("telemetry_prometheus_port"),
            name("telemetry_prometheus_port"),
            defaults.telemetry_prometheus_port,
            1,
            65535,
        ),
        telemetry_prometheus_host=_to_str(
            raw("telemetry_prometheus_host"), defaults.telemetry_prometheus_host
        ),
    )
