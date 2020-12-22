import json
import logging

from typing import Dict, Any

from pycti.connector.opencti_connector import OpenCTIConnector


class OpenCTIApiConnector:
    """OpenCTIApiConnector"""

    def __init__(self, api):
        self.api = api

    def list(self) -> Dict:
        """list available connectors

        :return: return dict with connectors
        :rtype: dict
        """

        logging.info("Getting connectors ...")
        query = """
            query GetConnectors {
                connectors {
                    id
                    name
                    config {
                        connection {
                            host
                            port
                            user
                            pass
                        }
                        listen
                        push
                    }
                }
            }
        """
        result = self.api.query(query)
        return result["data"]["connectors"]

    def ping(self, connector_id: str, connector_state: Any) -> Dict:
        """pings a connector by id and state

        :param connector_id: the connectors id
        :type connector_id: str
        :param connector_state: state for the connector
        :type connector_state:
        :return: the response pingConnector data dict
        :rtype: dict
        """

        query = """
            mutation PingConnector($id: ID!, $state: String) {
                pingConnector(id: $id, state: $state) {
                    id
                    connector_state
                }
            }
           """
        result = self.api.query(
            query, {"id": connector_id, "state": json.dumps(connector_state)}
        )
        return result["data"]["pingConnector"]

    def register(self, connector: OpenCTIConnector) -> Dict:
        """register a connector with OpenCTI

        :param connector: `OpenCTIConnector` connector object
        :type connector: OpenCTIConnector
        :return: the response registerConnector data dict
        :rtype: dict
        """

        query = """
            mutation RegisterConnector($input: RegisterConnectorInput) {
                registerConnector(input: $input) {
                    id
                    connector_state
                    config {
                        connection {
                            host
                            port
                            user
                            pass
                        }
                        listen
                        listen_exchange
                        push
                        push_exchange
                    }
                    connector_user {
                        id
                    }
                }
            }
           """
        result = self.api.query(query, connector.to_input())
        return result["data"]["registerConnector"]
