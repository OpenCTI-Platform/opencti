import time
from typing import Dict, List


class OpenCTIApiWork:
    """OpenCTIApiJob"""

    def __init__(self, api):
        self.api = api

    def to_received(self, work_id: str, message: str):
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
            self.api.query(query, {"id": work_id, "message": message})

    def to_processed(self, work_id: str, message: str, in_error: bool = False):
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
                query, {"id": work_id, "message": message, "inError": in_error}
            )

    def ping(self, work_id: str):
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
                self.api.query(query, {"id": work_id, "error": error})
            except:
                self.api.app_logger.error("Cannot report expectation")

    def add_expectations(self, work_id: str, expectations: int):
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
                self.api.query(query, {"id": work_id, "expectations": expectations})
            except:
                self.api.app_logger.error("Cannot report expectation")

    def add_draft_context(self, work_id: str, draft_context: str):
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
                self.api.query(query, {"id": work_id, "draftContext": draft_context})
            except:
                self.api.app_logger.error("Cannot report draft context")

    def initiate_work(self, connector_id: str, friendly_name: str) -> str:
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
                query, {"connectorId": connector_id, "friendlyName": friendly_name}
            )
            return work["data"]["workAdd"]["id"]

    def delete_work(self, work_id: str):
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
        result = self.api.query(
            query,
            {"id": work_id},
        )
        return result["data"]["work"]

    def get_connector_works(self, connector_id: str) -> List[Dict]:
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
        )
        result = result["data"]["works"]["edges"]
        return_value = []
        for node in result:
            node = node["node"]
            return_value.append(node)

        return sorted(return_value, key=lambda i: i["timestamp"])
