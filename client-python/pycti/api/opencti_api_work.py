import time
import traceback
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Dict, List, Optional

WORK_EXPECTATION_REPORT_BATCH_SIZE = 100


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
        self._expectation_batch_state = ContextVar(
            "work_expectation_batch_state", default=None
        )
        self._supports_batched_expectation_reporting = None

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

    @staticmethod
    def _validate_expectation_count(expectations: int):
        if (
            isinstance(expectations, bool)
            or not isinstance(expectations, int)
            or expectations <= 0
        ):
            raise ValueError("expectations must be a positive integer")

    @staticmethod
    def _is_unsupported_batched_expectation_error(error: Exception) -> bool:
        error_text = str(error)
        return "Unknown argument" in error_text and "expectations" in error_text

    def _report_single_expectation(self, work_id: str, error):
        self.api.app_logger.info("Report expectation", {"work_id": work_id})
        query = """
            mutation reportExpectation($id: ID!, $error: WorkErrorInput) {
                workEdit(id: $id) {
                    reportExpectation(error: $error)
                }
            }
           """
        self.api.query(query, {"id": work_id, "error": error}, True)

    def _report_expectations_now(self, work_id: str, error, expectations: int) -> bool:
        if expectations == 1:
            self._report_single_expectation(work_id, error)
            return True
        if self._supports_batched_expectation_reporting is False:
            return False

        self.api.app_logger.info(
            "Report expectations",
            {"work_id": work_id, "expectations": expectations},
        )
        query = """
            mutation reportExpectation($id: ID!, $error: WorkErrorInput, $expectations: Int) {
                workEdit(id: $id) {
                    reportExpectation(error: $error, expectations: $expectations)
                }
            }
           """
        try:
            self.api.query(
                query,
                {"id": work_id, "error": error, "expectations": expectations},
                True,
            )
            self._supports_batched_expectation_reporting = True
            return True
        except Exception as ex:
            if self._is_unsupported_batched_expectation_error(ex):
                self._supports_batched_expectation_reporting = False
                return False
            raise

    def _report_expectations_immediately(self, work_id: str, error, expectations: int):
        pending = expectations
        next_error = error
        while pending > 0:
            report_count = (
                1 if self._supports_batched_expectation_reporting is False else pending
            )
            if not self._report_expectations_now(work_id, next_error, report_count):
                continue
            pending -= report_count
            next_error = None

    @staticmethod
    def _set_pending_expectation_count(state, work_id: str, pending: int):
        if pending > 0:
            state["pending"][work_id] = pending
        else:
            state["pending"].pop(work_id, None)

    def _flush_pending_expectations(self, state, work_id: str, flush_all: bool):
        pending = state["pending"].get(work_id, 0)
        batch_size = state["batch_size"]
        while pending >= batch_size or (flush_all and pending > 0):
            chunk_pending = min(batch_size, pending)
            while chunk_pending > 0:
                report_count = (
                    1
                    if self._supports_batched_expectation_reporting is False
                    else chunk_pending
                )
                if not self._report_expectations_now(work_id, None, report_count):
                    continue
                pending -= report_count
                chunk_pending -= report_count
                self._set_pending_expectation_count(state, work_id, pending)

    def _try_flush_pending_expectations(self, state, work_id: str, flush_all: bool):
        try:
            self._flush_pending_expectations(state, work_id, flush_all)
        except Exception:
            self.api.app_logger.error("Cannot report expectation")

    def flush_expectations(self, work_id: str = None):
        """Flush pending batched successful expectation reports."""
        state = self._expectation_batch_state.get()
        if state is None:
            return
        if work_id is not None:
            self._try_flush_pending_expectations(state, work_id, flush_all=True)
            return
        for pending_work_id in list(state["pending"]):
            self._try_flush_pending_expectations(state, pending_work_id, flush_all=True)

    @contextmanager
    def expectation_batch(self, batch_size: int = WORK_EXPECTATION_REPORT_BATCH_SIZE):
        """Batch successful expectation reports within one import scope."""
        self._validate_expectation_count(batch_size)
        current_state = self._expectation_batch_state.get()
        if current_state is not None:
            yield
            return

        state = {"batch_size": batch_size, "pending": {}}
        token = self._expectation_batch_state.set(state)
        try:
            yield
        finally:
            try:
                self.flush_expectations()
            finally:
                self._expectation_batch_state.reset(token)

    def report_expectation(self, work_id: str, error, expectations: int = 1):
        """Report a work expectation.

        :param work_id: the work id
        :type work_id: str
        :param error: the error to report (WorkErrorInput format)
        :type error: dict
        :param expectations: number of processed expectations to report
        :type expectations: int
        :return: None
        :rtype: None
        """
        if self.api.bundle_send_to_queue:
            self._validate_expectation_count(expectations)
            try:
                batch_state = self._expectation_batch_state.get()
                if batch_state is not None and error is None:
                    pending = batch_state["pending"].get(work_id, 0) + expectations
                    batch_state["pending"][work_id] = pending
                    if pending >= batch_state["batch_size"]:
                        self._try_flush_pending_expectations(
                            batch_state, work_id, flush_all=False
                        )
                    return
                if batch_state is not None:
                    self._try_flush_pending_expectations(
                        batch_state, work_id, flush_all=True
                    )
                self._report_expectations_immediately(work_id, error, expectations)
            except Exception:
                self.api.app_logger.error("Cannot report expectation")

    def add_expectations(self, work_id: str, expectations: int):
        """Add expectations to a work.

        :param work_id: the work id
        :type work_id: str
        :param expectations: the number of expectations to add
        :type expectations: int
        :return: whether the work is still alive
        :rtype: bool
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
                error_msg = traceback.format_exc()
                if "WORK_NOT_ALIVE" in error_msg:
                    self.api.app_logger.info(
                        "Work no longer exists",
                        {"work_id": work_id},
                    )
                    return False
                else:
                    self.api.app_logger.error("Cannot add expectations")
        return True

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

    def initiate_work(
        self,
        connector_id: str,
        friendly_name: str,
        is_multipart: bool = False,
    ) -> Optional[str]:
        """Initiate a new work for a connector.

        :param connector_id:    the connector id
        :type connector_id:     str
        :param friendly_name:   the friendly name for the work
        :type friendly_name:    str
        :param is_multipart:    indicates whether multiple calls to `add_expectations`
                                are to be expected during the lifetime of the work.
                                In consequence the work won't automatically
                                transition to `complete` when the number of calls
                                to `report_expectation` matches the expectations
                                but only when an explicit call to `to_processed`
                                is made.
                                Should be set to `True` when sending multiple
                                STIX bundles consecutively via `send_stix2_bundle`
                                during the work's lifetime.
                                Defaults to `False`.
        :type is_multipart:     bool
        :return:                the work id or None if bundle_send_to_queue is False
        :rtype: str or None
        """
        if self.api.bundle_send_to_queue:
            self.api.app_logger.info(
                "Initiate work",
                {
                    "connector_id": connector_id,
                    "friendly_name": friendly_name,
                    "is_multipart": is_multipart,
                },
            )
            query = """
                mutation workAdd($connectorId: String!, $friendlyName: String, $isMultiPartWork: Boolean) {
                    workAdd(connectorId: $connectorId, friendlyName: $friendlyName, isMultiPartWork: $isMultiPartWork) {
                      id
                    }
                }
               """
            work = self.api.query(
                query,
                {
                    "connectorId": connector_id,
                    "friendlyName": friendly_name,
                    "isMultiPartWork": is_multipart,
                },
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
        while status != "complete":
            state = self.get_work(work_id=work_id)
            if len(state) > 0:
                status = state["status"]

                if state["errors"]:
                    self.api.app_logger.error(
                        "Unexpected connector error", {"state_errors": state["errors"]}
                    )
                    return ""
            if status == "complete":
                return
            time.sleep(1)

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
