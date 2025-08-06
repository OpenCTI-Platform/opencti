import random
import time
import traceback
from dataclasses import dataclass
from typing import Any, Literal
import requests
from pycti import __version__
from requests import RequestException, Timeout

ERROR_TYPE_BAD_GATEWAY = "Bad Gateway"
ERROR_TYPE_TIMEOUT = "Request timed out"

@dataclass(unsafe_hash=True)
class ListenHandler:
    logger: Any
    connector_token: str
    callback_uri: str
    listen_api_ssl_verify: bool
    listen_api_http_proxy: str
    listen_api_https_proxy: str

    def handle_message(self, body: str) -> Literal["ack", "nack", "requeue"]:
        try:
            response = requests.post(
                self.callback_uri,
                data=body,
                headers={
                    "User-Agent": f"pycti/{__version__}",
                    "Authorization": f"Bearer {self.connector_token}",
                },
                verify=self.listen_api_ssl_verify,
                proxies={
                    "http": self.listen_api_http_proxy,
                    "https": self.listen_api_https_proxy,
                },
                timeout=300,
            )
            if response.status_code != 202:
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
            self.logger.error(
                "Error executing listen handling", {"reason": str(ex)}
            )
            error_msg = traceback.format_exc()
            if ERROR_TYPE_BAD_GATEWAY in error_msg or ERROR_TYPE_TIMEOUT in error_msg:
                # Nack the message and requeue
                return "requeue"
            else:
                # Technical error, log and continue, Reject the message
                return "nack"
