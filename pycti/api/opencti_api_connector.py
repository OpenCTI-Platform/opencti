import json
from typing import Any, Dict

from pycti.api import LOGGER
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

        LOGGER.info("Getting connectors ...")
        query = """
            query GetConnectors {
                connectorsForWorker {
                    id
                    name
                    config {
                        connection {
                            host
                            vhost
                            use_ssl
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
        return result["data"]["connectorsForWorker"]

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
                            vhost
                            use_ssl
                            port
                            user
                            pass
                        }
                        listen
                        listen_routing
                        listen_exchange
                        push
                        push_routing
                        push_exchange
                    }
                    connector_user_id
                }
            }
           """
        result = self.api.query(query, connector.to_input())
        return result["data"]["registerConnector"]

    def unregister(self, _id: str) -> Dict:
        """unregister a connector with OpenCTI

        :param _id: `OpenCTIConnector` connector id
        :type _id: string
        :return: the response registerConnector data dict
        :rtype: dict
        """
        query = """
            mutation ConnectorDeletionMutation($id: ID!) {
                deleteConnector(id: $id)
            }
        """
        return self.api.query(query, {"id": _id})
