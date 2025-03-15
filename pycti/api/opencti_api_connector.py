import json
from typing import Any, Dict

from pycti.connector.opencti_connector import OpenCTIConnector


class OpenCTIApiConnector:
    """OpenCTIApiConnector"""

    def __init__(self, api):
        self.api = api

    def read(self, connector_id: str) -> Dict:
        """Reading the connector and its details

        :return: return all the connector details
        :rtype: dict
        """
        self.api.app_logger.info("[INFO] Getting connector details ...")
        query = """
            query GetConnector($id: String!) {
                connector(id: $id) {
                    id
                    name
                    active
                    auto
                    only_contextual
                    connector_type
                    connector_scope
                    connector_state
                    connector_queue_details {
                        messages_number
                        messages_size
                    }
                updated_at
                created_at
                config {
                    listen
                    listen_exchange
                    push
                    push_exchange
                    push_routing
                  }
                built_in
                }
              }
        """
        result = self.api.query(query, {"id": connector_id})
        return result["data"]["connector"]

    def list(self) -> Dict:
        """list available connectors

        :return: return dict with connectors
        :rtype: dict
        """

        self.api.app_logger.info("Getting connectors ...")
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
                        listen_exchange
                        listen_callback_uri
                        push
                        push_exchange
                        push_routing
                    }
                }
            }
        """
        result = self.api.query(query)
        return result["data"]["connectorsForWorker"]

    def ping(
        self, connector_id: str, connector_state: Any, connector_info: Dict
    ) -> Dict:
        """pings a connector by id and state

        :param connector_id: the connectors id
        :type connector_id: str
        :param connector_state: state for the connector
        :type connector_state:
        :param connector_info: all details connector
        :type connector_info: Dict
        :return: the response pingConnector data dict
        :rtype: dict
        """

        query = """
            mutation PingConnector($id: ID!, $state: String, $connectorInfo: ConnectorInfoInput ) {
                pingConnector(id: $id, state: $state, connectorInfo: $connectorInfo) {
                    id
                    connector_state
                    connector_info {
                        run_and_terminate
                        buffering
                        queue_threshold
                        queue_messages_size
                        next_run_datetime
                        last_run_datetime
                    }   
                }
            }
           """
        result = self.api.query(
            query,
            {
                "id": connector_id,
                "state": json.dumps(connector_state),
                "connectorInfo": connector_info,
            },
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
