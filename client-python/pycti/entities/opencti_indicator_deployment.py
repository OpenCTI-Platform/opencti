# coding: utf-8

import threading
from typing import Dict, Iterator, List, Optional

DEPLOYMENT_STATUSES = ["pending", "deployed", "active", "failed", "removed"]
DEPLOYMENT_BATCH_MAX_SIZE = 500

_DEPLOYMENT_PROPERTIES = """
    id
    standard_id
    entity_type
    relationship_type
    revoked
    deployment_status
    external_id
    deployed_at
    last_sync_at
    removed_at
    hit_count
    first_hit_at
    last_hit_at
    last_hit_report_ids
    validation_status
    last_validation_at
    validation_run_id
    error_message
"""

_DEPLOYMENT_LIST_PROPERTIES = _DEPLOYMENT_PROPERTIES + """
    from {
        ... on Indicator {
            id
            standard_id
            name
            pattern
            pattern_type
            revoked
            valid_until
            x_opencti_main_observable_type
        }
    }
"""

_REPORT_MUTATION = (
    """
    mutation IndicatorReportDeployment(
        $indicatorId: StixRef!
        $platformId: StixRef!
        $status: IndicatorDeploymentStatus!
        $externalId: String
        $metadata: IndicatorDeploymentMetadataInput
    ) {
        indicatorReportDeployment(
            indicatorId: $indicatorId
            platformId: $platformId
            status: $status
            externalId: $externalId
            metadata: $metadata
        ) {
            """
    + _DEPLOYMENT_PROPERTIES
    + """
        }
    }
"""
)

_BATCH_MUTATION = """
    mutation IndicatorReportDeployments($platformId: StixRef!, $reports: [IndicatorDeploymentReportInput!]!) {
        indicatorReportDeployments(platformId: $platformId, reports: $reports) {
            processed
            created
            updated
            unchanged
            errors {
                indicatorId
                message
            }
        }
    }
"""

_HITS_MUTATION = """
    mutation IndicatorReportHits(
        $indicatorId: StixRef!
        $platformId: StixRef!
        $count: Int!
        $lastHit: DateTime
        $firstHit: DateTime
        $reportId: String
    ) {
        indicatorReportHits(
            indicatorId: $indicatorId
            platformId: $platformId
            count: $count
            lastHit: $lastHit
            firstHit: $firstHit
            reportId: $reportId
        ) {
            id
            standard_id
            attribute_count
            first_seen
            last_seen
        }
    }
"""

_MUTATION_FIELDS_QUERY = """
    query IndicatorDeploymentFeatureDetection {
        __type(name: "Mutation") {
            fields {
                name
            }
        }
    }
"""

_SECURITY_PLATFORM_UPSERT = """
    mutation SecurityPlatformUpsert($input: SecurityPlatformAddInput!) {
        securityPlatformAdd(input: $input) {
            id
            standard_id
            name
        }
    }
"""

_SECURITY_PLATFORM_READ = """
    query SecurityPlatformRead($id: String!) {
        securityPlatform(id: $id) {
            id
            standard_id
            name
        }
    }
"""

_DEPLOYMENTS_LIST = (
    """
    query IndicatorDeploymentsList($toId: [String], $first: Int, $after: ID, $filters: FilterGroup) {
        stixCoreRelationships(
            relationship_type: ["deployed-on"]
            toId: $toId
            first: $first
            after: $after
            filters: $filters
        ) {
            edges {
                node {
                    """
    + _DEPLOYMENT_LIST_PROPERTIES
    + """
                }
            }
            pageInfo {
                endCursor
                hasNextPage
            }
        }
    }
"""
)


def _compact(data: Dict) -> Dict:
    return {key: value for key, value in data.items() if value is not None}


def _batch_report_error(report) -> Optional[str]:
    """Why a batch report cannot be sent, or None when it can."""
    if not isinstance(report, dict):
        return "A deployment report must be a dictionary"
    if not report.get("indicator_id"):
        return "Missing indicator_id"
    if report.get("status") not in DEPLOYMENT_STATUSES:
        return "Unsupported deployment status: {}".format(report.get("status"))
    return None


class IndicatorDeployment:
    """Deployment write-back of indicators on security platforms (dissemination assurance).

    Stream connectors use it to report the lifecycle of the indicators they push
    (``deployed-on`` relationship Indicator -> Security Platform) and the hits observed.
    Every method degrades gracefully: on platforms without the feature, or on any API
    error, it logs and returns ``None`` instead of raising, so the dissemination itself
    is never interrupted.

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type opencti: OpenCTIApiClient
    """

    def __init__(self, opencti):
        """Initialize the IndicatorDeployment instance.

        :param opencti: OpenCTI API client instance
        :type opencti: OpenCTIApiClient
        """
        self.opencti = opencti
        self._supported_mutations: Optional[set] = None
        self._detection_lock = threading.Lock()
        self._platform_cache: Dict[str, Dict] = {}

    def _mutations(self) -> set:
        if self._supported_mutations is None:
            with self._detection_lock:
                if self._supported_mutations is None:
                    try:
                        result = self.opencti.query(_MUTATION_FIELDS_QUERY)
                        fields = ((result.get("data") or {}).get("__type") or {}).get(
                            "fields"
                        ) or []
                        self._supported_mutations = {field["name"] for field in fields}
                    except Exception as err:  # pylint: disable=broad-except
                        self.opencti.app_logger.warning(
                            "Cannot detect indicator deployment support",
                            {"error": str(err)},
                        )
                        return set()
                    if "indicatorReportDeployment" not in self._supported_mutations:
                        self.opencti.app_logger.info(
                            "Indicator deployment write-back is not supported by this platform, reporting is disabled"
                        )
        return self._supported_mutations

    def is_supported(self, mutation: str = "indicatorReportDeployment") -> bool:
        """Tell if the platform supports a write-back mutation (schema feature detection, cached).

        :param mutation: mutation name, defaults to ``indicatorReportDeployment``
        :type mutation: str
        :return: True when the mutation exists on the platform
        :rtype: bool
        """
        return mutation in self._mutations()

    def report(
        self,
        indicator_id: str,
        platform_id: str,
        status: str,
        external_id: Optional[str] = None,
        error_message: Optional[str] = None,
        deployed_at: Optional[str] = None,
        synced_at: Optional[str] = None,
        removed_at: Optional[str] = None,
    ) -> Optional[Dict]:
        """Report the deployment status of an indicator on a security platform.

        :param indicator_id: id (internal, standard or STIX) of the indicator
        :param platform_id: id of the security platform
        :param status: pending, deployed, active, failed or removed
        :param external_id: identifier of the indicator on the vendor side
        :param error_message: vendor error when status is failed
        :param deployed_at: ISO date of the deployment, defaults to now on the platform
        :param synced_at: ISO date of the observation, defaults to now on the platform
        :param removed_at: ISO date of the removal, defaults to now on the platform
        :return: the deployed-on relationship, or None when not supported / on error
        :rtype: dict or None
        """
        if status not in DEPLOYMENT_STATUSES:
            self.opencti.app_logger.warning(
                "Invalid indicator deployment status, report ignored",
                {"status": status},
            )
            return None
        if not self.is_supported("indicatorReportDeployment"):
            return None
        variables = {
            "indicatorId": indicator_id,
            "platformId": platform_id,
            "status": status,
            "externalId": external_id,
            "metadata": _compact(
                {
                    "deployed_at": deployed_at,
                    "last_sync_at": synced_at,
                    "removed_at": removed_at,
                    "error_message": error_message,
                }
            )
            or None,
        }
        try:
            result = self.opencti.query(_REPORT_MUTATION, variables)
            return result["data"]["indicatorReportDeployment"]
        except Exception as err:  # pylint: disable=broad-except
            self.opencti.app_logger.warning(
                "Cannot report indicator deployment",
                {"indicator_id": indicator_id, "status": status, "error": str(err)},
            )
            return None

    def report_batch(self, platform_id: str, reports: List[Dict]) -> Optional[Dict]:
        """Report many deployments of one security platform, chunked by 500.

        Report items: ``indicator_id``, ``status`` and optionally ``external_id``,
        ``error_message``, ``deployed_at``, ``synced_at``, ``removed_at``.

        :param platform_id: id of the security platform
        :param reports: list of report dictionaries
        :return: aggregated batch result (processed, created, updated, unchanged, errors) or None
        :rtype: dict or None
        """
        valid_reports = []
        # A rejected entry is reported like a server-side error, so the caller knows which ones were not sent
        rejected = []
        for report in reports:
            error = _batch_report_error(report)
            if error is None:
                valid_reports.append(report)
            else:
                rejected.append(
                    {
                        "indicatorId": (
                            report.get("indicator_id")
                            if isinstance(report, dict)
                            else None
                        ),
                        "message": error,
                    }
                )
        if len(valid_reports) == 0:
            return {
                "processed": 0,
                "created": 0,
                "updated": 0,
                "unchanged": 0,
                "errors": rejected,
            }
        if not self.is_supported("indicatorReportDeployments"):
            return None
        total = {
            "processed": 0,
            "created": 0,
            "updated": 0,
            "unchanged": 0,
            "errors": list(rejected),
        }
        for index in range(0, len(valid_reports), DEPLOYMENT_BATCH_MAX_SIZE):
            chunk = valid_reports[index : index + DEPLOYMENT_BATCH_MAX_SIZE]
            inputs = [
                _compact(
                    {
                        "indicatorId": report["indicator_id"],
                        "status": report["status"],
                        "externalId": report.get("external_id"),
                        "metadata": _compact(
                            {
                                "deployed_at": report.get("deployed_at"),
                                "last_sync_at": report.get("synced_at"),
                                "removed_at": report.get("removed_at"),
                                "error_message": report.get("error_message"),
                            }
                        )
                        or None,
                    }
                )
                for report in chunk
            ]
            try:
                result = self.opencti.query(
                    _BATCH_MUTATION, {"platformId": platform_id, "reports": inputs}
                )
                chunk_result = result["data"]["indicatorReportDeployments"]
                for key in ["processed", "created", "updated", "unchanged"]:
                    total[key] += chunk_result.get(key, 0)
                total["errors"].extend(chunk_result.get("errors") or [])
            except Exception as err:  # pylint: disable=broad-except
                self.opencti.app_logger.warning(
                    "Cannot report indicator deployments batch",
                    {"platform_id": platform_id, "size": len(chunk), "error": str(err)},
                )
                total["errors"].extend(
                    [
                        {"indicatorId": report["indicator_id"], "message": str(err)}
                        for report in chunk
                    ]
                )
        return total

    def report_hits(
        self,
        indicator_id: str,
        platform_id: str,
        count: int,
        last_hit: str,
        first_hit: Optional[str] = None,
        report_id: Optional[str] = None,
    ) -> Optional[Dict]:
        """Report new hits of an indicator on a security platform.

        Creates or increments the stable Indicator -> Security Platform sighting.
        A report whose ``last_hit`` is not after the last known hit is ignored by the platform,
        so ``last_hit`` is the idempotency watermark of the report: pass the vendor time of
        the newest hit, never the time of the call, so that a re-sent report is not counted twice.
        Two distinct reports can end at the same instant: give each a stable ``report_id``
        (the same one when the report is re-sent) so that the second one is counted too.

        :param indicator_id: id of the indicator
        :param platform_id: id of the security platform
        :param count: number of new hits (>= 1)
        :param last_hit: ISO date of the most recent hit (required)
        :param first_hit: ISO date of the oldest new hit, defaults to last_hit
        :param report_id: stable id of the report, telling apart reports ending at the same instant
        :return: the hits sighting, or None
        :rtype: dict or None
        """
        if not isinstance(count, int) or count < 1:
            return None
        if not last_hit:
            self.opencti.app_logger.warning(
                "Cannot report indicator hits without the time of the last hit",
                {"indicator_id": indicator_id, "count": count},
            )
            return None
        if not self.is_supported("indicatorReportHits"):
            return None
        variables = {
            "indicatorId": indicator_id,
            "platformId": platform_id,
            "count": count,
            "lastHit": last_hit,
            "firstHit": first_hit,
            "reportId": report_id,
        }
        try:
            result = self.opencti.query(_HITS_MUTATION, variables)
            return result["data"]["indicatorReportHits"]
        except Exception as err:  # pylint: disable=broad-except
            self.opencti.app_logger.warning(
                "Cannot report indicator hits",
                {"indicator_id": indicator_id, "count": count, "error": str(err)},
            )
            return None

    def get_or_create_security_platform(
        self,
        name: Optional[str] = None,
        security_platform_type: Optional[str] = None,
        description: Optional[str] = None,
        platform_id: Optional[str] = None,
    ) -> Optional[Dict]:
        """Resolve the security platform a connector reports to (cached).

        :param name: name of the security platform, upserted when no id is given
        :param security_platform_type: vocabulary security_platform_type_ov (EDR, XDR, SIEM, ...)
        :param description: optional description used at creation
        :param platform_id: existing security platform id, takes precedence over the name
        :return: dict with id, standard_id and name, or None
        :rtype: dict or None
        """
        cache_key = platform_id or (name or "").strip().lower()
        if not cache_key:
            return None
        if cache_key in self._platform_cache:
            return self._platform_cache[cache_key]
        try:
            if platform_id:
                result = self.opencti.query(
                    _SECURITY_PLATFORM_READ, {"id": platform_id}
                )
                platform = result["data"]["securityPlatform"]
            else:
                result = self.opencti.query(
                    _SECURITY_PLATFORM_UPSERT,
                    {
                        "input": _compact(
                            {
                                "name": name.strip(),
                                "security_platform_type": security_platform_type,
                                "description": description,
                                "update": True,
                            }
                        )
                    },
                )
                platform = result["data"]["securityPlatformAdd"]
        except Exception as err:  # pylint: disable=broad-except
            self.opencti.app_logger.warning(
                "Cannot resolve the security platform",
                {"name": name, "platform_id": platform_id, "error": str(err)},
            )
            return None
        if platform is not None:
            self._platform_cache[cache_key] = platform
        return platform

    def list_for_platform(
        self,
        platform_id: str,
        statuses: Optional[List[str]] = None,
        page_size: int = 500,
    ) -> Iterator[Dict]:
        """Iterate over the deployed-on relationships of a security platform (reconciliation).

        :param platform_id: id of the security platform
        :param statuses: optional deployment statuses to keep
        :param page_size: page size, defaults to 500
        :return: generator of deployed-on relationships with their indicator in ``from``
        :rtype: Iterator[dict]
        """
        if not self.is_supported("indicatorReportDeployment"):
            return
        filters = None
        if statuses:
            filters = {
                "mode": "and",
                "filters": [{"key": "deployment_status", "values": statuses}],
                "filterGroups": [],
            }
        after = None
        while True:
            try:
                result = self.opencti.query(
                    _DEPLOYMENTS_LIST,
                    {
                        "toId": [platform_id],
                        "first": page_size,
                        "after": after,
                        "filters": filters,
                    },
                )
            except Exception as err:  # pylint: disable=broad-except
                self.opencti.app_logger.warning(
                    "Cannot list indicator deployments",
                    {"platform_id": platform_id, "error": str(err)},
                )
                return
            connection = result["data"]["stixCoreRelationships"]
            for edge in connection["edges"]:
                yield edge["node"]
            page_info = connection["pageInfo"]
            if not page_info["hasNextPage"]:
                return
            after = page_info["endCursor"]
