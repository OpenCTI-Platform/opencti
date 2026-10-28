"""Global TLS certificate verification switch for workers and connectors."""

import os
from typing import Dict, Optional

TLS_REJECT_UNAUTHORIZED_ENV = "OPENCTI_TLS_REJECT_UNAUTHORIZED"


def get_tls_reject_unauthorized(config: Optional[Dict] = None) -> bool:
    """Return the global TLS certificate verification setting.

    Used as the default of every TLS verification option of workers and
    connectors (OPENCTI_SSL_VERIFY, MQ_USE_SSL_REJECT_UNAUTHORIZED,
    WORKER_LISTEN_API_SSL_VERIFY and the OpenCTIApiClient ssl_verify).
    Looks up the OPENCTI_TLS_REJECT_UNAUTHORIZED environment variable, then
    the opencti.tls_reject_unauthorized key of the YAML configuration.
    Disabled by default for now, it will be enabled by default in an
    upcoming version.

    :param config: Configuration dictionary loaded from YAML file
    :type config: Dict, optional

    :return: True if TLS certificates must be verified
    :rtype: bool
    """
    value = os.getenv(TLS_REJECT_UNAUTHORIZED_ENV)
    if value is None:
        value = ((config or {}).get("opencti") or {}).get("tls_reject_unauthorized")
    if isinstance(value, bool):
        return value
    return value in ["yes", "true", "True"]


_tls_warning_logged = False


def log_tls_verification_disabled(app_logger) -> None:
    """Warn once per process that TLS certificate verification is disabled.

    :param app_logger: Logger used to emit the warning
    :type app_logger: AppLogger
    """
    global _tls_warning_logged
    if _tls_warning_logged:
        return
    _tls_warning_logged = True
    app_logger.warning(
        "TLS certificate verification is disabled. It will be enabled by default "
        "in an upcoming version: set " + TLS_REJECT_UNAUTHORIZED_ENV + "=true "
        "to opt in now."
    )
