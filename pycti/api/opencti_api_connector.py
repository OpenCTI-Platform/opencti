import logging

from pycti.connector.opencti_connector import OpenCTIConnector


class OpenCTIApiConnector:

    def __init__(self, api):
        self.api = api

    def list(self):
        logging.info('Getting connectors ...')
        query = """
            query GetConnectors {
                connectors {
                    id
                    name
                    config {
                        uri
                        listen
                        push
                    }
                }
            }
        """
        result = self.api.query(query)
        return result['data']['connectors']

    def ping(self, connector_id):
        query = """
            mutation PingConnector($id: ID!) {
                pingConnector(id: $id) {
                    id
                }
            }
           """
        self.api.query(query, {'id': connector_id})

    def register(self, connector: OpenCTIConnector):
        query = """
            mutation RegisterConnector($input: RegisterConnectorInput) {
                registerConnector(input: $input) {
                    id
                    config {
                        uri
                        listen
                        listen_exchange
                        push
                        push_exchange
                    }
                }
            }
           """
        result = self.api.query(query, connector.to_input())
        return result['data']['registerConnector']

