# coding: utf-8

import json
import uuid

from stix2.canonicalization.Canonicalize import canonicalize

HUNT_FIELDS = [
    "hypothesis",
    "hunt_type",
    "hunt_status",
    "hunt_source_kind",
    "sigma_rule",
    "native_queries",
    "hunt_ioc_filters",
    "hunt_ioc_values",
    "hunt_scope",
    "hunt_schedule",
    "trigger_filters",
    "hunt_pir_activation",
    "time_window_hours",
    "expected_observables",
    "benign_patterns",
    "escalation_threshold",
    "escalate_manual_runs",
    "hunt_max_results",
]


class Hunt:
    """Main Hunt class for OpenCTI

    Manages hunts (OpenCTI Hunts): a falsifiable hypothesis, a canonical Sigma
    rule with per-platform native queries, the threats and techniques it
    targets and its execution guardrails.

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type opencti: OpenCTIApiClient
    """

    def __init__(self, opencti):
        """Initialize the Hunt instance.

        :param opencti: OpenCTI API client instance
        :type opencti: OpenCTIApiClient
        """
        self.opencti = opencti
        self.properties = """
            id
            standard_id
            entity_type
            parent_types
            spec_version
            created_at
            updated_at
            created
            modified
            confidence
            name
            description
            hypothesis
            hunt_type
            hunt_status
            hunt_source_kind
            sigma_rule
            native_queries {
                platform
                language
                query
                pipeline
            }
            hunt_ioc_filters
            hunt_ioc_values {
                observable_type
                value
            }
            hunt_scope
            hunt_schedule
            trigger_filters
            hunt_pir_activation
            hunt_pir_armed
            time_window_hours
            expected_observables
            benign_patterns
            escalation_threshold
            escalate_manual_runs
            hunt_max_results
            last_run_at
            last_run_status
            last_hits_count
            next_run_at
            createdBy {
                ... on Identity {
                    id
                    standard_id
                    entity_type
                    name
                }
            }
            objectMarking {
                id
                standard_id
                entity_type
                definition_type
                definition
                x_opencti_order
                x_opencti_color
            }
            objectLabel {
                id
                value
                color
            }
            huntTargets {
                id
                standard_id
                entity_type
            }
            huntTechniques {
                id
                standard_id
                x_mitre_id
                name
            }
            huntSources {
                id
                standard_id
                entity_type
            }
        """

    @staticmethod
    def generate_id(name):
        """Generate a STIX ID for a Hunt.

        :param name: The name of the hunt
        :type name: str
        :return: STIX ID for the hunt
        :rtype: str
        """
        data = {"name": name.lower().strip()}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "hunt--" + id

    @staticmethod
    def generate_id_from_data(data):
        """Generate a STIX ID from hunt data.

        :param data: Dictionary containing a 'name' key
        :type data: dict
        :return: STIX ID for the hunt
        :rtype: str
        """
        return Hunt.generate_id(data["name"])

    def list(self, **kwargs):
        """List Hunt objects.

        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :param orderBy: field to order by (HuntsOrdering)
        :param orderMode: asc or desc
        :param customAttributes: custom attributes to return
        :param getAll: get all hunts, page after page
        :param withPagination: return the pagination information
        :return: List of Hunt objects
        :rtype: list
        """
        filters = kwargs.get("filters", None)
        search = kwargs.get("search", None)
        first = kwargs.get("first", 100)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        custom_attributes = kwargs.get("customAttributes", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)

        self.opencti.app_logger.info(
            "Listing Hunts with filters", {"filters": json.dumps(filters)}
        )
        query = (
            """
                query Hunts($filters: FilterGroup, $search: String, $first: Int, $after: ID, $orderBy: HuntsOrdering, $orderMode: OrderingMode) {
                    hunts(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
        variables = {
            "filters": filters,
            "search": search,
            "first": first,
            "after": after,
            "orderBy": order_by,
            "orderMode": order_mode,
        }
        result = self.opencti.query(query, variables)
        if get_all:
            final_data = self.opencti.process_multiple(result["data"]["hunts"])
            while result["data"]["hunts"]["pageInfo"]["hasNextPage"]:
                variables["after"] = result["data"]["hunts"]["pageInfo"]["endCursor"]
                self.opencti.app_logger.info(
                    "Listing Hunts", {"after": variables["after"]}
                )
                result = self.opencti.query(query, variables)
                final_data = final_data + self.opencti.process_multiple(
                    result["data"]["hunts"]
                )
            return final_data
        return self.opencti.process_multiple(result["data"]["hunts"], with_pagination)

    def read(self, **kwargs):
        """Read a Hunt object.

        :param id: the id of the Hunt
        :type id: str
        :param filters: the filters to apply if no id provided
        :type filters: dict
        :param customAttributes: custom attributes to return
        :type customAttributes: str
        :return: Hunt object
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.app_logger.info("Reading Hunt", {"id": id})
            query = (
                """
                    query Hunt($id: String!) {
                        hunt(id: $id) {
                            """
                + (
                    custom_attributes
                    if custom_attributes is not None
                    else self.properties
                )
                + """
                    }
                }
             """
            )
            result = self.opencti.query(query, {"id": id})
            return self.opencti.process_multiple_fields(result["data"]["hunt"])
        if filters is not None:
            result = self.list(filters=filters)
            return result[0] if len(result) > 0 else None
        self.opencti.app_logger.error(
            "[opencti_hunt] Missing parameters: id or filters"
        )
        return None

    def create(self, **kwargs):
        """Create a Hunt object.

        :param name: the name of the Hunt (required)
        :type name: str
        :param description: (optional) description
        :param hypothesis: (optional) the falsifiable hypothesis
        :param hunt_type: (optional) telemetry (default), infrastructure or indicators
        :param hunt_status: (optional) draft, active (default), paused or retired
        :param hunt_source_kind: (optional) analyst (default), agent or hub
        :param sigma_rule: (optional) the canonical Sigma rule (YAML)
        :param native_queries: (optional) list of {platform, language, query, pipeline}
        :param hunt_ioc_filters: (optional) indicator hunts: filter group (JSON)
            over indicators and observables
        :param hunt_ioc_values: (optional) indicator hunts: pasted values, list of
            {observable_type, value}
        :param hunt_scope: (optional) filter group (JSON) over Security Platforms
        :param hunt_schedule: (optional) manual (default), standing or a 5-field cron
        :param trigger_filters: (optional) filter group (JSON) re-running a standing hunt
        :param hunt_pir_activation: (optional) arm the hunt while a target is in a PIR
        :param time_window_hours: (optional) time window of a run
        :param expected_observables: (optional) observable types expected in results
        :param benign_patterns: (optional) known benign patterns
        :param escalation_threshold: (optional) hits opening an Incident draft
        :param escalate_manual_runs: (optional) whether the runs started by hand
            also open the Incident draft above the threshold (default False)
        :param hunt_max_results: (optional) maximum results per run
        :param huntTargets: (optional) ids of the targeted threats
        :param huntTechniques: (optional) ids or ATT&CK ids of the covered techniques
        :param huntSources: (optional) ids of the source indicators and reports
        :param createdBy: (optional) the author ID
        :param objectMarking: (optional) list of marking definition IDs
        :param objectLabel: (optional) list of label IDs
        :param externalReferences: (optional) list of external reference IDs
        :param confidence: (optional) confidence
        :param stix_id: (optional) the STIX ID
        :param x_opencti_stix_ids: (optional) other STIX IDs
        :param update: (optional) upsert an existing hunt
        :return: Hunt object
        :rtype: dict or None
        """
        name = kwargs.get("name", None)
        if name is None:
            self.opencti.app_logger.error("[opencti_hunt] Missing parameters: name")
            return None
        hunt_input = {
            "stix_id": kwargs.get("stix_id", None),
            "x_opencti_stix_ids": kwargs.get("x_opencti_stix_ids", None),
            "name": name,
            "description": kwargs.get("description", None),
            "createdBy": kwargs.get("createdBy", None),
            "objectMarking": kwargs.get("objectMarking", None),
            "objectLabel": kwargs.get("objectLabel", None),
            "externalReferences": kwargs.get("externalReferences", None),
            "confidence": kwargs.get("confidence", None),
            "created": kwargs.get("created", None),
            "modified": kwargs.get("modified", None),
            "huntTargets": kwargs.get("huntTargets", None),
            "huntTechniques": kwargs.get("huntTechniques", None),
            "huntSources": kwargs.get("huntSources", None),
            "update": kwargs.get("update", False),
        }
        for field in HUNT_FIELDS:
            hunt_input[field] = kwargs.get(field, None)
        self.opencti.app_logger.info("Creating Hunt", {"name": name})
        query = """
            mutation HuntAdd($input: HuntAddInput!) {
                huntAdd(input: $input) {
                    id
                    standard_id
                    entity_type
                    parent_types
                }
            }
        """
        result = self.opencti.query(query, {"input": hunt_input})
        return self.opencti.process_multiple_fields(result["data"]["huntAdd"])

    def start_runs(self, **kwargs):
        """Run a hunt now (huntRunStart): one run per hunt connector of its scope.

        :param id: the id of the Hunt
        :type id: str
        :param security_platform_ids: (optional) restrict the runs to these Security Platforms
        :type security_platform_ids: list
        :param time_window_hours: (optional) time window of the runs
        :type time_window_hours: int
        :return: the created hunt runs
        :rtype: list
        """
        id = kwargs.get("id", None)
        if id is None:
            self.opencti.app_logger.error("[opencti_hunt] Missing parameters: id")
            return None
        query = """
            mutation HuntRunStart($id: ID!, $input: HuntRunStartInput) {
                huntRunStart(id: $id, input: $input) {
                    id
                    hunt_run_status
                    hunt_run_trigger
                    connector_name
                }
            }
        """
        result = self.opencti.query(
            query,
            {
                "id": id,
                "input": {
                    "security_platform_ids": kwargs.get("security_platform_ids", None),
                    "time_window_hours": kwargs.get("time_window_hours", None),
                },
            },
        )
        return result["data"]["huntRunStart"]

    def preview(self, **kwargs):
        """Translate a hunt for a platform without executing it (huntTestQuery).

        :param id: the id of the Hunt
        :type id: str
        :param security_platform_id: (optional) the Security Platform to translate for
        :type security_platform_id: str
        :return: the preview hunt run (poll it with hunt_run.read)
        :rtype: dict
        """
        id = kwargs.get("id", None)
        if id is None:
            self.opencti.app_logger.error("[opencti_hunt] Missing parameters: id")
            return None
        query = """
            mutation HuntTestQuery($id: ID!, $securityPlatformId: ID) {
                huntTestQuery(id: $id, securityPlatformId: $securityPlatformId) {
                    id
                    hunt_run_status
                    hunt_run_mode
                }
            }
        """
        result = self.opencti.query(
            query,
            {"id": id, "securityPlatformId": kwargs.get("security_platform_id", None)},
        )
        return result["data"]["huntTestQuery"]

    def export_pack(self, **kwargs):
        """Export hunts as a hunt pack (STIX 2.1 bundle).

        :param ids: the ids of the hunts
        :type ids: list
        :return: the STIX 2.1 bundle
        :rtype: dict or None
        """
        ids = kwargs.get("ids", None)
        if not ids:
            self.opencti.app_logger.error("[opencti_hunt] Missing parameters: ids")
            return None
        query = """
            query HuntPackExport($ids: [ID!]!) {
                huntPackExport(ids: $ids)
            }
        """
        result = self.opencti.query(query, {"ids": ids})
        bundle = result["data"]["huntPackExport"]
        return json.loads(bundle) if bundle else None

    def import_from_stix2(self, **kwargs):
        """Import a Hunt from a STIX2 object.

        :param stixObject: the STIX2 hunt object
        :type stixObject: dict
        :param extras: extra parameters including created_by_id, object_marking_ids, etc.
        :type extras: dict
        :param update: whether to update if the entity already exists
        :type update: bool
        :return: Hunt object
        :rtype: dict or None
        """
        stix_object = kwargs.get("stixObject", None)
        extras = kwargs.get("extras", {})
        update = kwargs.get("update", False)
        if stix_object is None:
            self.opencti.app_logger.error(
                "[opencti_hunt] Missing parameters: stixObject"
            )
            return None
        if "x_opencti_stix_ids" not in stix_object:
            stix_object["x_opencti_stix_ids"] = self.opencti.get_attribute_in_extension(
                "stix_ids", stix_object
            )
        fields = {field: stix_object.get(field) for field in HUNT_FIELDS}
        # The platform exports an empty filter for the hunts that have none
        fields["hunt_ioc_filters"] = fields["hunt_ioc_filters"] or None
        return self.create(
            stix_id=stix_object["id"],
            name=stix_object["name"],
            description=(
                self.opencti.stix2.convert_markdown(stix_object["description"])
                if "description" in stix_object
                else None
            ),
            huntTargets=stix_object.get("target_refs"),
            huntTechniques=stix_object.get("technique_refs"),
            huntSources=stix_object.get("source_refs"),
            confidence=stix_object.get("confidence"),
            created=stix_object.get("created"),
            modified=stix_object.get("modified"),
            createdBy=extras.get("created_by_id"),
            objectMarking=extras.get("object_marking_ids"),
            objectLabel=extras.get("object_label_ids"),
            externalReferences=extras.get("external_references_ids"),
            x_opencti_stix_ids=stix_object.get("x_opencti_stix_ids"),
            update=update,
            **fields,
        )

    def delete(self, **kwargs):
        """Delete a Hunt object.

        :param id: the Hunt id
        :type id: str
        """
        id = kwargs.get("id", None)
        if id is None:
            self.opencti.app_logger.error("[opencti_hunt] Missing parameters: id")
            return None
        self.opencti.app_logger.info("Deleting Hunt", {"id": id})
        query = """
            mutation HuntDelete($id: ID!) {
                huntDelete(id: $id)
            }
        """
        self.opencti.query(query, {"id": id})
        return None
