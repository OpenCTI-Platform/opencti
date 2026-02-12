import random
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, Optional

import requests
from pycti import OpenCTIApiClient, __version__
from requests import RequestException, Timeout

ERROR_TYPE_BAD_GATEWAY = "Bad Gateway"
ERROR_TYPE_TIMEOUT = "Request timed out"

JWT_REFRESH_INTERVAL_SECONDS = 30 * 60  # 30 minutes


@dataclass(unsafe_hash=True)
class ListenHandler:
    logger: Any
    api: OpenCTIApiClient
    callback_uri: str
    listen_api_ssl_verify: bool
    listen_api_http_proxy: str
    listen_api_https_proxy: str
    _connector_jwt: Optional[str] = field(
        init=False, default=None, repr=False, hash=False, compare=False
    )
    _connector_jwt_issued_at: Optional[datetime] = field(
        init=False, default=None, repr=False, hash=False, compare=False
    )

    def _get_connector_jwt(self) -> str:
        """Return a cached connector JWT, refreshing it every 30 minutes."""
        now = datetime.now(timezone.utc)
        if (
            self._connector_jwt is None
            or self._connector_jwt_issued_at is None
            or (now - self._connector_jwt_issued_at).total_seconds()
            >= JWT_REFRESH_INTERVAL_SECONDS
        ):
            self._connector_jwt = self.api.connector_jwt()
            self._connector_jwt_issued_at = now
        return self._connector_jwt

    def handle_message(self, body: str) -> Literal["ack", "nack", "requeue"]:
        try:
            # Round trip with JWT service every 30 minutes with issueConnectorJWT
            connector_jwt = self._get_connector_jwt()
            response = requests.post(
                self.callback_uri,
                data=body,
                headers={
                    "User-Agent": f"pycti/{__version__}",
                    "Authorization": f"Bearer {connector_jwt}",
                    "Content-Type": "application/json",
                },
                verify=self.listen_api_ssl_verify,
                proxies={
                    "http": self.listen_api_http_proxy,
                    "https": self.listen_api_https_proxy,
                },
                timeout=300,
            )
            if response.status_code != 200 and response.status_code != 202:
                raise RequestException(response.status_code, response.text)

            return "ack"
        except (RequestException, Timeout):
            self.logger.error(
                "Error executing listen handling, a connection error or timeout occurred"
            )
            # Platform is under heavy load: wait for unlock & retry almost indefinitely.
            sleep_jitter = round(random.uniform(10, 30), 2)
            time.sleep(sleep_jitter)

            return "requeue"
        except Exception as ex:
            # Technical unmanaged exception
            self.logger.error("Error executing listen handling", {"reason": str(ex)})
            error_msg = traceback.format_exc()
            if ERROR_TYPE_BAD_GATEWAY in error_msg or ERROR_TYPE_TIMEOUT in error_msg:
                # Nack the message and requeue
                return "requeue"
            else:
                # Technical error, log and continue, Reject the message
                return "nack"
