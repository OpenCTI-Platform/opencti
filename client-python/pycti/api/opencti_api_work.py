import time
from typing import Dict, List, Optional


class OpenCTIApiWork:
    """OpenCTI Work API class.

    Manages work/job operations for connectors.

    :param api: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type api: OpenCTIApiClient
    """

    def __init__(self, api):
        """Initialize the OpenCTIApiWork instance.

        :param api: OpenCTI API client instance
        :type api: OpenCTIApiClient
        """
        self.api = api

    def to_received(self, work_id: str, message: str):
        """Mark work as received.

        :param work_id: the work id
        :type work_id: str
        :param message: the message to report
        :type message: str
        :return: None
        :rtype: None
        """
        if self.api.bundle_send_to_queue:
            self.api.app_logger.info(
                "Reporting work update_received", {"work_id": work_id}
            )
            query = """
                mutation workToReceived($id: ID!, $message: String) {
                    workEdit(id: $id) {
                        toReceived (message: $message)
                    }
                }
               """
            self.api.query(query, {"id": work_id, "message": message}, True)

    def to_processed(self, work_id: str, message: str, in_error: bool = False):
        """Mark work as processed.

        :param work_id: the work id
        :type work_id: str
        :param message: the message to report
        :type message: str
        :param in_error: whether the work completed with error, defaults to False
        :type in_error: bool, optional
        :return: None
        :rtype: None
        """
        if self.api.bundle_send_to_queue:
            self.api.app_logger.info(
                "Reporting work update_processed", {"work_id": work_id}
            )
            query = """
                mutation workToProcessed($id: ID!, $message: String, $inError: Boolean) {
                    workEdit(id: $id) {
                        toProcessed (message: $message, inError: $inError)
                    }
                }
               """
            self.api.query(
                query, {"id": work_id, "message": message, "inError": in_error}, True
            )

    def ping(self, work_id: str):
        """Ping a work to keep it alive.

        :param work_id: the work id
        :type work_id: str
        :return: None
        :rtype: None
        """
        self.api.app_logger.info("Ping work", {"work_id": work_id})
        query = """
            mutation pingWork($id: ID!) {
                workEdit(id: $id) {
                    ping
                }
            }
           """
        self.api.query(query, {"id": work_id})

    def report_expectation(self, work_id: str, error):
        """Report a work expectation.

        :param work_id: the work id
        :type work_id: str
        :param error: the error to report (WorkErrorInput format)
        :type error: dict
        :return: None
        :rtype: None
        """
        if self.api.bundle_send_to_queue:
            self.api.app_logger.info("Report expectation", {"work_id": work_id})
            query = """
                mutation reportExpectation($id: ID!, $error: WorkErrorInput) {
                    workEdit(id: $id) {
                        reportExpectation(error: $error)
                    }
                }
               """
            try:
                self.api.query(query, {"id": work_id, "error": error}, True)
            except Exception:
                self.api.app_logger.error("Cannot report expectation")

    def add_expectations(self, work_id: str, expectations: int):
        """Add expectations to a work.

        :param work_id: the work id
        :type work_id: str
        :param expectations: the number of expectations to add
        :type expectations: int
        :return: None
        :rtype: None
        """
        if self.api.bundle_send_to_queue:
            self.api.app_logger.info(
                "Update action expectations",
                {"work_id": work_id, "expectations": expectations},
            )
            query = """
                mutation addExpectations($id: ID!, $expectations: Int) {
                    workEdit(id: $id) {
                        addExpectations(expectations: $expectations)
                    }
                }
               """
            try:
                self.api.query(
                    query, {"id": work_id, "expectations": expectations}, True
                )
            except Exception:
                self.api.app_logger.error("Cannot add expectations")

    def add_draft_context(self, work_id: str, draft_context: str):
        """Add draft context to a work.

        :param work_id: the work id
        :type work_id: str
        :param draft_context: the draft context to add
        :type draft_context: str
        :return: None
        :rtype: None
        """
        if self.api.bundle_send_to_queue:
            self.api.app_logger.info(
                "Update draft context",
                {"work_id": work_id, "draft_context": draft_context},
            )
            query = """
                mutation addDraftContext($id: ID!, $draftContext: String) {
                    workEdit(id: $id) {
                        addDraftContext(draftContext: $draftContext)
                    }
                }
               """
            try:
                self.api.query(
                    query, {"id": work_id, "draftContext": draft_context}, True
                )
            except Exception:
                self.api.app_logger.error("Cannot add draft context")

    def initiate_work(self, connector_id: str, friendly_name: str) -> Optional[str]:
        """Initiate a new work for a connector.

        :param connector_id: the connector id
        :type connector_id: str
        :param friendly_name: the friendly name for the work
        :type friendly_name: str
        :return: the work id or None if bundle_send_to_queue is False
        :rtype: str or None
        """
        if self.api.bundle_send_to_queue:
            self.api.app_logger.info("Initiate work", {"connector_id": connector_id})
            query = """
                mutation workAdd($connectorId: String!, $friendlyName: String) {
                    workAdd(connectorId: $connectorId, friendlyName: $friendlyName) {
                      id
                    }
                }
               """
            work = self.api.query(
                query,
                {"connectorId": connector_id, "friendlyName": friendly_name},
                True,
            )
            return work["data"]["workAdd"]["id"]
        return None

    def delete_work(self, work_id: str):
        """Delete a work.

        .. deprecated::
            Use :meth:`delete` instead.

        :param work_id: the work id
        :type work_id: str
        :return: the response data
        :rtype: dict
        """
        return self.delete(id=work_id)

    def delete(self, **kwargs):
        """Delete a work by id.

        :param id: the work id
        :type id: str
        :return: the response data
        :rtype: dict or None
        """
        work_id = kwargs.get("id", None)
        if work_id is None:
            self.api.admin_logger.error(
                "[opencti_work] Cannot delete work, missing parameter: id"
            )
            return None
        query = """
        mutation ConnectorWorksMutation($workId: ID!) {
            workEdit(id: $workId) {
                delete
            }
        }"""
        work = self.api.query(
            query,
            {"workId": work_id},
        )
        return work["data"]

    def wait_for_work_to_finish(self, work_id: str):
        """Wait for a work to finish.

        :param work_id: the work id
        :type work_id: str
        :return: empty string if error, None otherwise
        :rtype: str or None
        """
        status = ""
        cnt = 0
        while status != "complete":
            state = self.get_work(work_id=work_id)
            if len(state) > 0:
                status = state["status"]

                if state["errors"]:
                    self.api.app_logger.error(
                        "Unexpected connector error", {"state_errors": state["errors"]}
                    )
                    return ""

            time.sleep(1)
            cnt += 1

    def get_work(self, work_id: str) -> Dict:
        """Get a work by id.

        :param work_id: the work id
        :type work_id: str
        :return: the work data
        :rtype: dict
        """
        query = """
        query WorkQuery($id: ID!) {
            work(id: $id) {
                id
                name
                user {
                    name
                }
                timestamp
                status
                event_source_id
                received_time
                processed_time
                completed_time
                tracking {
                    import_expected_number
                    import_processed_number
                }
                messages {
                    timestamp
                    message
                    sequence
                    source
                }
                errors {
                    timestamp
                    message
                    sequence
                    source
                }
            }
        }
        """
        result = self.api.query(query, {"id": work_id}, True)
        return result["data"]["work"]

    def get_is_work_alive(self, work_id: str) -> bool:
        """Check if a work is alive.

        :param work_id: the work id
        :type work_id: str
        :return: whether the work is alive
        :rtype: bool
        """
        query = """
        query WorkAliveQuery($id: ID!) {
            isWorkAlive(id: $id)
        }
        """
        result = self.api.query(query, {"id": work_id}, True)
        return result["data"]["isWorkAlive"]

    def get_connector_works(self, connector_id: str) -> List[Dict]:
        """Get all works for a connector.

        :param connector_id: the connector id
        :type connector_id: str
        :return: list of work dictionaries sorted by timestamp
        :rtype: list[dict]
        """
        query = """
        query ConnectorWorksQuery(
            $count: Int
            $orderBy: WorksOrdering
            $orderMode: OrderingMode
            $filters: FilterGroup
        ) {
            works(
                first: $count
                orderBy: $orderBy
                orderMode: $orderMode
                filters: $filters
            ) {
                edges {
                    node {
                        id
                        name
                        user {
                            name
                        }
                        timestamp
                        status
                        event_source_id
                        received_time
                        processed_time
                        completed_time
                        tracking {
                            import_expected_number
                            import_processed_number
                        }
                        messages {
                            timestamp
                            message
                            sequence
                            source
                        }
                        errors {
                            timestamp
                            message
                            sequence
                            source
                        }
                    }
                }
            }
        }
        """
        result = self.api.query(
            query,
            {
                "count": 50,
                "filters": {
                    "mode": "and",
                    "filters": [{"key": "connector_id", "values": [connector_id]}],
                    "filterGroups": [],
                },
            },
            True,
        )
        result = result["data"]["works"]["edges"]
        return_value = []
        for node in result:
            node = node["node"]
            return_value.append(node)

        return sorted(return_value, key=lambda i: i["timestamp"])
