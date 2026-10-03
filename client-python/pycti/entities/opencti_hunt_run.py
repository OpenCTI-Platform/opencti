# coding: utf-8

import json

HUNT_RUN_STATUSES = ["queued", "running", "completed", "failed", "timeout"]
HUNT_RUN_REPORTABLE_STATUSES = ["running", "completed", "failed"]
HUNT_VERDICTS = ["pending", "true_positive", "benign", "inconclusive"]


class HuntRun:
    """Main HuntRun class for OpenCTI

    Manages hunt runs (OpenCTI Hunts): one execution of a hunt on one hunt
    connector over one time window, its outcome, evidence and verdict. Also
    registers the hunt platform of an INTERNAL_HUNT connector.

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type opencti: OpenCTIApiClient
    """

    def __init__(self, opencti):
        """Initialize the HuntRun instance.

        :param opencti: OpenCTI API client instance
        :type opencti: OpenCTIApiClient
        """
        self.opencti = opencti
        self.properties = """
            id
            standard_id
            entity_type
            hunt_id
            hunt {
                id
                name
            }
            hunt_run_status
            hunt_run_trigger
            hunt_run_mode
            security_platform_id
            securityPlatform {
                id
                standard_id
                name
            }
            connector_id
            connector_name
            work_id
            time_window_start
            time_window_end
            translated_query
            query_language
            hits_count
            distinct_entities
            evidence_sample {
                field
                value_hash
                value_preview
                count
            }
            result_ids
            verdict
            verdict_source
            analyst_feedback
            verdict_proposal
            verdict_proposal_confidence
            verdict_proposal_rationale
            incident_proposal
            incident_id
            draft_id
            aev_inject_id
            technique_id
            attempt
            next_retry_at
            started_at
            completed_at
            cost_ms
            error_message
            created_at
            updated_at
        """

    def list(self, **kwargs):
        """List HuntRun objects.

        :param filters: the filters to apply (hunt_id, hunt_run_status, verdict, ...)
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :param orderBy: field to order by (HuntRunsOrdering)
        :param orderMode: asc or desc
        :param customAttributes: custom attributes to return
        :param getAll: get all runs, page after page
        :param withPagination: return the pagination information
        :return: List of HuntRun objects
        :rtype: list
        """
        filters = kwargs.get("filters", None)
        first = kwargs.get("first", 100)
        custom_attributes = kwargs.get("customAttributes", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)
        variables = {
            "filters": filters,
            "search": kwargs.get("search", None),
            "first": first,
            "after": kwargs.get("after", None),
            "orderBy": kwargs.get("orderBy", None),
            "orderMode": kwargs.get("orderMode", None),
        }
        self.opencti.app_logger.info(
            "Listing Hunt runs with filters", {"filters": json.dumps(filters)}
        )
        query = (
            """
                query HuntRuns($filters: FilterGroup, $search: String, $first: Int, $after: ID, $orderBy: HuntRunsOrdering, $orderMode: OrderingMode) {
                    huntRuns(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
                        edges {
                            node {
                                """
            + (custom_attributes if custom_attributes is not None else self.properties)
            + """
                        }
                    }
                    pageInfo {
                        startCursor
                        endCursor
                        hasNextPage
                        hasPreviousPage
                        globalCount
                    }
                }
            }
        """
        )
        result = self.opencti.query(query, variables)
        if get_all:
            final_data = self.opencti.process_multiple(result["data"]["huntRuns"])
            while result["data"]["huntRuns"]["pageInfo"]["hasNextPage"]:
                variables["after"] = result["data"]["huntRuns"]["pageInfo"]["endCursor"]
                result = self.opencti.query(query, variables)
                final_data = final_data + self.opencti.process_multiple(
                    result["data"]["huntRuns"]
                )
            return final_data
        return self.opencti.process_multiple(
            result["data"]["huntRuns"], with_pagination
        )

    def read(self, **kwargs):
        """Read a HuntRun object.

        :param id: the id of the hunt run
        :type id: str
        :param customAttributes: custom attributes to return
        :type customAttributes: str
        :return: HuntRun object
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is None:
            self.opencti.app_logger.error("[opencti_hunt_run] Missing parameters: id")
            return None
        query = (
            """
                query HuntRun($id: String!) {
                    huntRun(id: $id) {
                        """
            + (custom_attributes if custom_attributes is not None else self.properties)
            + """
                }
            }
        """
        )
        result = self.opencti.query(query, {"id": id})
        return self.opencti.process_multiple_fields(result["data"]["huntRun"])

    def report(self, **kwargs):
        """Report the outcome of a hunt run (huntRunReport, hunt connectors only).

        :param id: the id of the hunt run
        :type id: str
        :param status: running, completed or failed
        :type status: str
        :param hits_count: (optional) number of hits
        :param distinct_entities: (optional) number of distinct entities in the hits
        :param evidence_sample: (optional) list of {field, value_hash, value_preview, count}
        :param translated_query: (optional) the query executed on the platform
        :param query_language: (optional) the language of the query
        :param cost_ms: (optional) execution duration in milliseconds
        :param result_ids: (optional) STIX ids of the result bundle objects
        :param error: (optional) the error of a failed run
        :return: the hunt run
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        status = kwargs.get("status", None)
        if id is None or status not in HUNT_RUN_REPORTABLE_STATUSES:
            self.opencti.app_logger.error(
                "[opencti_hunt_run] Missing parameters: id or a reportable status",
                {"status": status},
            )
            return None
        query = """
            mutation HuntRunReport($id: ID!, $input: HuntRunReportInput!) {
                huntRunReport(id: $id, input: $input) {
                    id
                    hunt_run_status
                    verdict
                }
            }
        """
        report_input = {
            "status": status,
            "hits_count": kwargs.get("hits_count", None),
            "distinct_entities": kwargs.get("distinct_entities", None),
            "evidence_sample": kwargs.get("evidence_sample", None),
            "translated_query": kwargs.get("translated_query", None),
            "query_language": kwargs.get("query_language", None),
            "cost_ms": kwargs.get("cost_ms", None),
            "result_ids": kwargs.get("result_ids", None),
            "error": kwargs.get("error", None),
        }
        result = self.opencti.query(query, {"id": id, "input": report_input})
        return result["data"]["huntRunReport"]

    def set_verdict(self, **kwargs):
        """Set the verdict of a completed hunt run (huntRunSetVerdict).

        :param id: the id of the hunt run
        :type id: str
        :param verdict: pending, true_positive, benign or inconclusive
        :type verdict: str
        :param analyst_feedback: (optional) the reasoning behind the verdict
        :type analyst_feedback: str
        :param source: (optional) analyst (default) or agent
        :type source: str
        :return: the hunt run
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        verdict = kwargs.get("verdict", None)
        if id is None or verdict not in HUNT_VERDICTS:
            self.opencti.app_logger.error(
                "[opencti_hunt_run] Missing parameters: id or a valid verdict",
                {"verdict": verdict},
            )
            return None
        query = """
            mutation HuntRunSetVerdict($id: ID!, $input: HuntRunVerdictInput!) {
                huntRunSetVerdict(id: $id, input: $input) {
                    id
                    verdict
                    verdict_source
                    incident_id
                    draft_id
                }
            }
        """
        result = self.opencti.query(
            query,
            {
                "id": id,
                "input": {
                    "verdict": verdict,
                    "analyst_feedback": kwargs.get("analyst_feedback", None),
                    "source": kwargs.get("source", None),
                },
            },
        )
        return result["data"]["huntRunSetVerdict"]

    def add_evidence(self, **kwargs):
        """Attach evidence found outside the run dispatch (huntRunEvidenceAdd).

        Allowed on any run status: result objects are merged, hits are added,
        the evidence sample is merged; status and verdict are never changed.

        :param id: the id of the hunt run
        :type id: str
        :param result_ids: STIX or internal ids of the sightings / observed data created for the run
        :type result_ids: list
        :param hits_count: (optional) hits added to the run
        :param evidence_sample: (optional) list of {field, value_hash, value_preview, count}
        :param security_platform_id: (optional) the platform where the evidence was observed
        :param observed_at: (optional) observation date
        :param source: (optional) where the evidence comes from (for example splunk-alert-action)
        :return: the hunt run
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        result_ids = kwargs.get("result_ids", None)
        if id is None or not result_ids:
            self.opencti.app_logger.error(
                "[opencti_hunt_run] Missing parameters: id or result_ids"
            )
            return None
        query = """
            mutation HuntRunEvidenceAdd($id: ID!, $input: HuntRunEvidenceAddInput!) {
                huntRunEvidenceAdd(id: $id, input: $input) {
                    id
                    hits_count
                    result_ids
                    evidence_sources
                    last_evidence_at
                }
            }
        """
        result = self.opencti.query(
            query,
            {
                "id": id,
                "input": {
                    "result_ids": result_ids,
                    "hits_count": kwargs.get("hits_count", None),
                    "evidence_sample": kwargs.get("evidence_sample", None),
                    "security_platform_id": kwargs.get("security_platform_id", None),
                    "observed_at": kwargs.get("observed_at", None),
                    "source": kwargs.get("source", None),
                },
            },
        )
        return result["data"]["huntRunEvidenceAdd"]

    def retry(self, **kwargs):
        """Retry a terminated hunt run on the same connector and window (huntRunRetry).

        :param id: the id of the hunt run
        :type id: str
        :return: the new hunt run
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        if id is None:
            self.opencti.app_logger.error("[opencti_hunt_run] Missing parameters: id")
            return None
        query = """
            mutation HuntRunRetry($id: ID!) {
                huntRunRetry(id: $id) {
                    id
                    hunt_run_status
                    attempt
                }
            }
        """
        result = self.opencti.query(query, {"id": id})
        return result["data"]["huntRunRetry"]

    def register_connector(self, **kwargs):
        """Register the hunt platform of an INTERNAL_HUNT connector (huntConnectorRegister).

        :param connector_id: the connector id
        :type connector_id: str
        :param platform: the platform slug (splunk, microsoft-sentinel, ..., internet)
        :type platform: str
        :param languages: the query languages the connector executes
        :type languages: list
        :param security_platform_name: (optional) the Security Platform it executes against (created when missing, none for internet)
        :param security_platform_type: (optional) SIEM (default), EDR, XDR, SOAR, NDR or ISPM
        :param supports_preview: (optional) whether translation previews are supported (default True)
        :param max_concurrent_runs: (optional) connector-side concurrency limit
        :return: the hunt connector
        :rtype: dict or None
        """
        connector_id = kwargs.get("connector_id", None)
        platform = kwargs.get("platform", None)
        languages = kwargs.get("languages", None)
        if connector_id is None or platform is None or not languages:
            self.opencti.app_logger.error(
                "[opencti_hunt_run] Missing parameters: connector_id, platform or languages"
            )
            return None
        query = """
            mutation HuntConnectorRegister($input: HuntConnectorRegisterInput!) {
                huntConnectorRegister(input: $input) {
                    id
                    name
                    active
                    platform
                    languages
                    supports_preview
                    max_concurrent_runs
                    securityPlatform {
                        id
                        standard_id
                        name
                    }
                }
            }
        """
        result = self.opencti.query(
            query,
            {
                "input": {
                    "connector_id": connector_id,
                    "platform": platform,
                    "languages": languages,
                    "security_platform_name": kwargs.get(
                        "security_platform_name", None
                    ),
                    "security_platform_type": kwargs.get(
                        "security_platform_type", None
                    ),
                    "supports_preview": kwargs.get("supports_preview", True),
                    "max_concurrent_runs": kwargs.get("max_concurrent_runs", None),
                }
            },
        )
        return result["data"]["huntConnectorRegister"]

    def list_connectors(self, **kwargs):
        """List the hunt connectors (huntConnectors).

        :param only_alive: (optional) only the connectors alive (default False)
        :type only_alive: bool
        :return: the hunt connectors
        :rtype: list
        """
        query = """
            query HuntConnectors($onlyAlive: Boolean) {
                huntConnectors(onlyAlive: $onlyAlive) {
                    id
                    name
                    active
                    platform
                    languages
                    supports_preview
                    max_concurrent_runs
                    securityPlatform {
                        id
                        standard_id
                        name
                    }
                }
            }
        """
        result = self.opencti.query(
            query, {"onlyAlive": kwargs.get("only_alive", False)}
        )
        return result["data"]["huntConnectors"]
