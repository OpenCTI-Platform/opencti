import atexit
import threading
import time
import traceback
from typing import Dict, List, Optional, Tuple

import requests

REPORT_EXPECTATION_QUERY = """
    mutation reportExpectation($id: ID!, $error: WorkErrorInput) {
        workEdit(id: $id) {
            reportExpectation(error: $error)
        }
    }
"""
REPORT_EXPECTATIONS_QUERY = """
    mutation reportExpectations($id: ID!, $count: Int) {
        workEdit(id: $id) {
            reportExpectation(count: $count)
        }
    }
"""
# Headers of the message being processed that a report does not need: the report counts for the work,
# whoever the message was imported as
PER_MESSAGE_HEADERS = (
    "opencti-applicant-id",
    "opencti-playbook-id",
    "opencti-event-id",
    "synchronized-upsert",
    "previous-standard",
    "opencti-retry-number",
)


class ExpectationBatcher:
    """Success reports of works, sent together.

    The worker reports every object it imports. Sent one by one, each report is a
    second request per object, waited for before the message is acknowledged.
    Here, successes are counted per work (and draft) and sent as one
    ``reportExpectation`` with a count from a background thread, every
    ``interval`` seconds or as soon as ``max_pending`` are waiting. Pending
    reports are sent on ``flush`` and at exit; a hard kill loses at most one
    interval of counts. A send that fails is tried again with the next ones, up
    to ``max_attempts`` times. Errors are not batched: each carries its own
    message.

    :param api: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type api: OpenCTIApiClient
    :param interval: seconds between two sends, defaults to 1.0
    :type interval: float
    :param max_pending: pending reports that trigger a send, defaults to 500
    :type max_pending: int
    :param max_attempts: sends tried for a count before it is dropped, defaults to 3
    :type max_attempts: int
    """

    def __init__(
        self,
        api,
        interval: float = 1.0,
        max_pending: int = 500,
        max_attempts: int = 3,
    ):
        self.api = api
        self.interval = interval
        self.max_pending = max_pending
        self.max_attempts = max_attempts
        # Guards the pending counts, shared by the importing thread and the sender
        self._lock = threading.Lock()
        # One send at a time: the background sender, an explicit flush or the one at exit
        self._send_lock = threading.Lock()
        # Successes per (work id, draft id)
        self._pending: Dict[Tuple[str, Optional[str]], int] = {}
        self._attempts: Dict[Tuple[str, Optional[str]], int] = {}
        self._pending_total = 0
        self._wake = threading.Event()
        self._thread = None
        # Its own HTTP session: the client's is used by the import, from another thread
        self._session = requests.session()
        self._count_supported = True

    def add(self, work_id: str):
        """Count one object of the work as processed."""
        draft_id = self.api.request_headers.get("opencti-draft-id")
        key = (work_id, draft_id)
        with self._lock:
            self._pending[key] = self._pending.get(key, 0) + 1
            self._pending_total += 1
            full = self._pending_total >= self.max_pending
            if self._thread is None:
                self._thread = threading.Thread(
                    target=self._run, name="opencti-expectations", daemon=True
                )
                self._thread.start()
                atexit.register(self.flush)
        if full:
            self._wake.set()

    def _run(self):
        while True:
            self._wake.wait(self.interval)
            self._wake.clear()
            self.flush()

    def flush(self):
        """Send every pending report now."""
        with self._send_lock:
            with self._lock:
                pending, self._pending, self._pending_total = self._pending, {}, 0
            for key, count in pending.items():
                unsent = self._send(key[0], key[1], count)
                if unsent == 0:
                    self._attempts.pop(key, None)
                    continue
                # An unsent count goes back with the next reports, until it was tried max_attempts times
                attempts = self._attempts.get(key, 0) + 1
                if attempts >= self.max_attempts:
                    self._attempts.pop(key, None)
                    self.api.app_logger.error(
                        "Cannot report expectations, dropped",
                        {"work_id": key[0], "count": unsent, "attempts": attempts},
                    )
                    continue
                self._attempts[key] = attempts
                with self._lock:
                    self._pending[key] = self._pending.get(key, 0) + unsent
                    self._pending_total += unsent

    def _headers(self, work_id: str, draft_id: Optional[str]) -> Dict:
        """The client's headers for this work and draft, without those of the message being processed."""
        headers = {
            key: value
            for key, value in self.api.request_headers.items()
            if key not in PER_MESSAGE_HEADERS
        }
        headers["opencti-work-id"] = work_id
        headers["opencti-draft-id"] = draft_id
        return headers

    def _send(self, work_id: str, draft_id: Optional[str], count: int) -> int:
        """Send a count; returns how many are still unsent."""
        headers = self._headers(work_id, draft_id)
        unsent = count
        try:
            if self._count_supported:
                try:
                    self.api.query(
                        REPORT_EXPECTATIONS_QUERY,
                        {"id": work_id, "count": count},
                        True,
                        headers=headers,
                        session=self._session,
                    )
                    return 0
                except ValueError as err:
                    # A platform older than the count argument: report one by one from now on
                    if "count" not in str(err) or "Unknown argument" not in str(err):
                        raise
                    self._count_supported = False
            while unsent > 0:
                self.api.query(
                    REPORT_EXPECTATION_QUERY,
                    {"id": work_id, "error": None},
                    True,
                    headers=headers,
                    session=self._session,
                )
                unsent -= 1
            return 0
        except Exception as err:  # pylint: disable=broad-except
            self.api.app_logger.warning(
                "Cannot report expectations, will retry",
                {"work_id": work_id, "count": unsent, "error": str(err)},
            )
            return unsent


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
        self.expectations = ExpectationBatcher(api)

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

    def report_expectation_success(self, work_id: str):
        """Report one object of a work as processed, without waiting.

        Successes are sent in batches by :py:class:`ExpectationBatcher`;
        :py:meth:`flush_expectations` sends the pending ones.

        :param work_id: the work id
        :type work_id: str
        :return: None
        :rtype: None
        """
        if self.api.bundle_send_to_queue:
            self.expectations.add(work_id)

    def flush_expectations(self):
        """Send the pending success reports now.

        :return: None
        :rtype: None
        """
        self.expectations.flush()

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
