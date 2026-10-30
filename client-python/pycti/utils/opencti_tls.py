"""Global TLS certificate verification switch for workers and connectors."""

import os
from typing import Dict, Optional

TLS_REJECT_UNAUTHORIZED_ENV = "OPENCTI_TLS_REJECT_UNAUTHORIZED"


_TRUE_VALUES = ["1", "true", "yes", "on"]
_FALSE_VALUES = ["0", "false", "no", "off"]


def _is_unset(value) -> bool:
    return value is None or (isinstance(value, str) and value.strip() == "")


def get_tls_reject_unauthorized(config: Optional[Dict] = None) -> bool:
    """Return the global TLS certificate verification setting.

    Used as the default of every TLS verification option of workers and
    connectors (OPENCTI_SSL_VERIFY, MQ_USE_SSL_REJECT_UNAUTHORIZED,
    WORKER_LISTEN_API_SSL_VERIFY and the OpenCTIApiClient ssl_verify).
    Looks up the OPENCTI_TLS_REJECT_UNAUTHORIZED environment variable, then
    the opencti.tls_reject_unauthorized key of the YAML configuration.
    Accepts 1/0, true/false, yes/no and on/off, case-insensitive.
    Disabled by default for now, it will be enabled by default in an
    upcoming version.

    :param config: Configuration dictionary loaded from YAML file
    :type config: Dict, optional

    :return: True if TLS certificates must be verified
    :rtype: bool
    :raises ValueError: if the value is not a boolean
    """
    value = os.getenv(TLS_REJECT_UNAUTHORIZED_ENV)
    source = TLS_REJECT_UNAUTHORIZED_ENV
    if _is_unset(value):
        value = ((config or {}).get("opencti") or {}).get("tls_reject_unauthorized")
        source = "opencti.tls_reject_unauthorized"
    if _is_unset(value):
        return False
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ValueError(
        "Invalid value "
        + repr(value)
        + " for "
        + source
        + ", expected one of: "
        + ", ".join(_TRUE_VALUES + _FALSE_VALUES)
    )


_tls_warning_logged = False


def log_tls_verification_disabled(app_logger, config: Optional[Dict] = None) -> None:
    """Warn once per process when the global TLS switch is not enabled.

    :param app_logger: Logger used to emit the warning
    :type app_logger: AppLogger
    :param config: Configuration dictionary loaded from YAML file
    :type config: Dict, optional
    """
    global _tls_warning_logged
    if _tls_warning_logged or get_tls_reject_unauthorized(config):
        return
    _tls_warning_logged = True
    app_logger.warning(
        "TLS certificate verification is disabled for the connections that do "
        "not set their own option (" + TLS_REJECT_UNAUTHORIZED_ENV + "=false). "
        "It will be enabled by default in an upcoming version: set "
        + TLS_REJECT_UNAUTHORIZED_ENV
        + "=true to opt in now."
    )
