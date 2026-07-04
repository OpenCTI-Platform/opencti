# coding: utf-8
"""Singleton OpenCTIApiClient accessor.

Call :func:`get_client` anywhere inside tool/resource handlers to obtain the
shared pycti client that was initialised at server start-up.
"""

from __future__ import annotations

from pycti import OpenCTIApiClient

from opencti_mcp.config import Config

_client: OpenCTIApiClient | None = None


def init_client(cfg: Config) -> OpenCTIApiClient:
    """Initialise the module-level pycti client from *cfg*.

    This must be called once before :func:`get_client` is used.  Calling it
    again replaces the existing singleton (useful in tests).

    :param cfg: runtime configuration.
    :return: the newly created :class:`~pycti.OpenCTIApiClient` instance.
    """
    global _client
    _client = OpenCTIApiClient(
        url=cfg.opencti_url,
        token=cfg.opencti_token,
        log_level=cfg.log_level,
        ssl_verify=cfg.ssl_verify,
        perform_health_check=False,
    )
    return _client


def get_client() -> OpenCTIApiClient:
    """Return the shared pycti client.

    :raises RuntimeError: if :func:`init_client` has not been called yet.
    :return: the shared :class:`~pycti.OpenCTIApiClient` instance.
    """
    if _client is None:
        raise RuntimeError("OpenCTI client has not been initialised — call init_client() first")
    return _client
