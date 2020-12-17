import logging


class OpenCTIApiWork:
    """OpenCTIApiJob"""

    def __init__(self, api):
        self.api = api

    def to_received(self, work_id: str, message: str):
        logging.info("Reporting work update_received " + work_id)
        query = """
            mutation workToReceived($id: ID!, $message: String) {
                workEdit(id: $id) {
                    toReceived (message: $message)
                }
            }
           """
        self.api.query(query, {"id": work_id, "message": message})

    def to_processed(self, work_id: str, message: str, in_error: bool = False):
        logging.info("Reporting work update_received " + work_id)
        query = """
            mutation workToProcessed($id: ID!, $message: String, $inError: Boolean) {
                workEdit(id: $id) {
                    toProcessed (message: $message, inError: $inError)
                }
            }
           """
        self.api.query(query, {"id": work_id, "message": message, "inError": in_error})

    def report_expectation(self, work_id: str, error):
        logging.info("Report expectation for " + work_id)
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
            self.api.log("error", "Cannot report expectation")

    def add_expectations(self, work_id: str, expectations: int):
        logging.info(
            "Update action expectations " + work_id + " - " + str(expectations)
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
            self.api.log("error", "Cannot report expectation")

    def initiate_work(self, connector_id: str, friendly_name: str) -> str:
        logging.info("Initiate work for " + connector_id)
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
