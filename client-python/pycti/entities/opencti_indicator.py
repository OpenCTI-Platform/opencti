# coding: utf-8

import json
import uuid

from stix2.canonicalization.Canonicalize import canonicalize

from .indicator.opencti_indicator_properties import (
    INDICATOR_PROPERTIES,
    INDICATOR_PROPERTIES_WITH_FILES,
)


class Indicator:
    """Main Indicator class for OpenCTI

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    """

    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = INDICATOR_PROPERTIES
        self.properties_with_files = INDICATOR_PROPERTIES_WITH_FILES

    @staticmethod
    def generate_id(pattern):
        data = {"pattern": pattern.strip()}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "indicator--" + id

    @staticmethod
    def generate_id_from_data(data):
        return Indicator.generate_id(data["pattern"])

    def list(self, **kwargs):
        """List Indicator objects

        The list method accepts the following kwargs:

        :param list filters: (optional) the filters to apply
        :param str search: (optional) a search keyword to apply for the listing
        :param int first: (optional) return the first n rows from the `after` ID
                            or the beginning if not set
        :param str after: (optional) OpenCTI object ID of the first row for pagination
        :param str orderBy: (optional) the field to order the response on
        :param bool orderMode: (optional) either "`asc`" or "`desc`"
        :param list customAttributes: (optional) list of attributes keys to return
        :param bool getAll: (optional) switch to return all entries (be careful to use this without any other filters)
        :param bool withPagination: (optional) switch to use pagination
        :param bool toStix: (optional) get in STIX

        :return: List of Indicators
        :rtype: list
        """

        filters = kwargs.get("filters", None)
        search = kwargs.get("search", None)
        first = kwargs.get("first", 500)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        custom_attributes = kwargs.get("customAttributes", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)
        with_files = kwargs.get("withFiles", False)
        to_stix = kwargs.get("toStix", False)

        self.opencti.app_logger.info(
            "Listing Indicators with filters", {"filters": json.dumps(filters)}
        )
        query = (
            """
                query Indicators($filters: FilterGroup, $search: String, $first: Int, $after: ID, $orderBy: IndicatorsOrdering, $orderMode: OrderingMode, $toStix: Boolean) {
                    indicators(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode, toStix: $toStix) {
                        edges {
                            node {
                                """
            + (
                "toStix"
                if to_stix
                else (
                    custom_attributes
                    if custom_attributes is not None
                    else (self.properties_with_files if with_files else self.properties)
                )
            )
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
        result = self.opencti.query(
            query,
            {
                "filters": filters,
                "search": search,
                "first": first,
                "after": after,
                "orderBy": order_by,
                "orderMode": order_mode,
                "toStix": to_stix,
            },
        )
        if get_all:
            final_data = []
            data = self.opencti.process_multiple(result["data"]["indicators"])
            final_data = final_data + data
            while result["data"]["indicators"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["indicators"]["pageInfo"]["endCursor"]
                self.opencti.app_logger.info("Listing Indicators", {"after": after})
                result = self.opencti.query(
                    query,
                    {
                        "filters": filters,
                        "search": search,
                        "first": first,
                        "after": after,
                        "orderBy": order_by,
                        "orderMode": order_mode,
                    },
                )
                data = self.opencti.process_multiple(result["data"]["indicators"])
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["indicators"], with_pagination
            )

    def read(self, **kwargs):
        """Read an Indicator object

        read can be either used with a known OpenCTI entity `id` or by using a
        valid filter to search and return a single Indicator entity or None.

        The list method accepts the following kwargs.

        Note: either `id` or `filters` is required.

        :param str id: the id of the Threat-Actor-Group
        :param list filters: the filters to apply if no id provided

        :return: Indicator object
        :rtype: Indicator
        """

        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        with_files = kwargs.get("withFiles", False)
        if id is not None:
            self.opencti.app_logger.info("Reading Indicator", {"id": id})
            query = (
                """
                    query Indicator($id: String!) {
                        indicator(id: $id) {
                            """
                + (
                    custom_attributes
                    if custom_attributes is not None
                    else (self.properties_with_files if with_files else self.properties)
                )
                + """
                    }
                }
             """
            )
            result = self.opencti.query(query, {"id": id})
            return self.opencti.process_multiple_fields(result["data"]["indicator"])
        elif filters is not None:
            result = self.list(filters=filters, customAttributes=custom_attributes)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.app_logger.error(
                "[opencti_indicator] Missing parameters: id or filters"
            )
            return None

    def create(self, **kwargs):
        """
        Create an Indicator object

        :param str name: the name of the Indicator
        :param str pattern: stix indicator pattern
        :param str x_opencti_main_observable_type: type of the observable

        :return: Indicator object
        :rtype: Indicator
        """
        stix_id = kwargs.get("stix_id", None)
        created_by = kwargs.get("createdBy", None)
        object_marking = kwargs.get("objectMarking", None)
        object_label = kwargs.get("objectLabel", None)
        external_references = kwargs.get("externalReferences", None)
        revoked = kwargs.get("revoked", None)
        confidence = kwargs.get("confidence", None)
        lang = kwargs.get("lang", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        pattern_type = kwargs.get("pattern_type", None)
        pattern_version = kwargs.get("pattern_version", None)
        pattern = kwargs.get("pattern", None)
        name = kwargs.get("name", kwargs.get("pattern", None))
        description = kwargs.get("description", None)
        indicator_types = kwargs.get("indicator_types", None)
        valid_from = kwargs.get("valid_from", None)
        valid_until = kwargs.get("valid_until", None)
        x_opencti_score = kwargs.get("x_opencti_score", 50)
        x_opencti_detection = kwargs.get("x_opencti_detection", False)
        x_opencti_main_observable_type = kwargs.get(
            "x_opencti_main_observable_type", None
        )
        x_mitre_platforms = kwargs.get("x_mitre_platforms", None)
        kill_chain_phases = kwargs.get("killChainPhases", None)
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        create_observables = kwargs.get("x_opencti_create_observables", False)
        granted_refs = kwargs.get("objectOrganization", None)
        x_opencti_workflow_id = kwargs.get("x_opencti_workflow_id", None)
        update = kwargs.get("update", False)

        if (
            name is not None
            and pattern is not None
            and pattern_type is not None
            and x_opencti_main_observable_type is not None
        ):
            if x_opencti_main_observable_type == "File":
                x_opencti_main_observable_type = "StixFile"
            self.opencti.app_logger.info("Creating Indicator", {"name": name})
            query = """
                mutation IndicatorAdd($input: IndicatorAddInput!) {
                    indicatorAdd(input: $input) {
                        id
                        standard_id
                        entity_type
                        parent_types
                        observables {
                            edges {
                                node {
                                    id
                                    standard_id
                                    entity_type
                                }
                            }
                        }
                    }
                }
            """
            result = self.opencti.query(
                query,
                {
                    "input": {
                        "stix_id": stix_id,
                        "createdBy": created_by,
                        "objectMarking": object_marking,
                        "objectLabel": object_label,
                        "objectOrganization": granted_refs,
                        "externalReferences": external_references,
                        "revoked": revoked,
                        "confidence": confidence,
                        "lang": lang,
                        "created": created,
                        "modified": modified,
                        "pattern_type": pattern_type,
                        "pattern_version": pattern_version,
                        "pattern": pattern,
                        "name": name,
                        "description": description,
                        "indicator_types": indicator_types,
                        "valid_until": valid_until,
                        "valid_from": valid_from,
                        "x_opencti_score": x_opencti_score,
                        "x_opencti_detection": x_opencti_detection,
                        "x_opencti_main_observable_type": x_opencti_main_observable_type,
                        "x_mitre_platforms": x_mitre_platforms,
                        "x_opencti_stix_ids": x_opencti_stix_ids,
                        "killChainPhases": kill_chain_phases,
                        "createObservables": create_observables,
                        "x_opencti_workflow_id": x_opencti_workflow_id,
                        "update": update,
                    }
                },
            )
            return self.opencti.process_multiple_fields(result["data"]["indicatorAdd"])
        else:
            self.opencti.app_logger.error(
                "[opencti_indicator] Missing parameters: "
                "name or pattern or pattern_type or x_opencti_main_observable_type"
            )

    """
        Update an Indicator object field

        :param id: the Indicator id
        :param input: the input of the field
    """

    def update_field(self, **kwargs):
        id = kwargs.get("id", None)
        input = kwargs.get("input", None)
        if id is not None and input is not None:
            self.opencti.app_logger.info("Updating Indicator", {"id": id})
            query = """
                        mutation IndicatorFieldPatch($id: ID!, $input: [EditInput!]!) {
                            indicatorFieldPatch(id: $id, input: $input) {
                                id
                                standard_id
                                entity_type
                            }
                        }
                    """
            result = self.opencti.query(
                query,
                {
                    "id": id,
                    "input": input,
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["indicatorFieldPatch"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_stix_domain_object] Cant update indicator field, missing parameters: id and input"
            )
            return None

    def add_stix_cyber_observable(self, **kwargs):
        """
        Add a Stix-Cyber-Observable object to Indicator object (based-on)

        :param id: the id of the Indicator
        :param indicator: Indicator object
        :param stix_cyber_observable_id: the id of the Stix-Observable

        :return: Boolean True if there has been no import error
        """
        id = kwargs.get("id", None)
        indicator = kwargs.get("indicator", None)
        stix_cyber_observable_id = kwargs.get("stix_cyber_observable_id", None)
        if id is not None and stix_cyber_observable_id is not None:
            if indicator is None:
                indicator = self.read(id=id)
            if indicator is None:
                self.opencti.app_logger.error(
                    "[opencti_indicator] Cannot add Object Ref, indicator not found"
                )
                return False
            if stix_cyber_observable_id in indicator["observablesIds"]:
                return True
            else:
                self.opencti.app_logger.info(
                    "Adding Stix-Observable to Indicator",
                    {"observable": stix_cyber_observable_id, "indicator": id},
                )
                query = """
                    mutation StixCoreRelationshipAdd($input: StixCoreRelationshipAddInput!) {
                        stixCoreRelationshipAdd(input: $input) {
                            id
                        }
                    }
                """
                self.opencti.query(
                    query,
                    {
                        "id": id,
                        "input": {
                            "fromId": id,
                            "toId": stix_cyber_observable_id,
                            "relationship_type": "based-on",
                        },
                    },
                )
                return True
        else:
            self.opencti.app_logger.error(
                "[opencti_indicator] Missing parameters: id and stix cyber_observable_id"
            )
            return False

    def import_from_stix2(self, **kwargs):
        """
        Import an Indicator object from a STIX2 object

        :param stixObject: the Stix-Object Indicator
        :param extras: extra dict
        :param bool update: set the update flag on import

        :return: Indicator object
        :rtype: Indicator
        """
        stix_object = kwargs.get("stixObject", None)
        extras = kwargs.get("extras", {})
        update = kwargs.get("update", False)
        if stix_object is not None:
            # Search in extensions
            if "x_opencti_score" not in stix_object:
                stix_object["x_opencti_score"] = (
                    self.opencti.get_attribute_in_extension("score", stix_object)
                )
            if "x_opencti_detection" not in stix_object:
                stix_object["x_opencti_detection"] = (
                    self.opencti.get_attribute_in_extension("detection", stix_object)
                )
            if (
                "x_opencti_main_observable_type" not in stix_object
                and self.opencti.get_attribute_in_extension(
                    "main_observable_type", stix_object
                )
                is not None
            ):
                stix_object["x_opencti_main_observable_type"] = (
                    self.opencti.get_attribute_in_extension(
                        "main_observable_type", stix_object
                    )
                )
            if "x_opencti_create_observables" not in stix_object:
                stix_object["x_opencti_create_observables"] = (
                    self.opencti.get_attribute_in_extension(
                        "create_observables", stix_object
                    )
                )
            if "x_opencti_stix_ids" not in stix_object:
                stix_object["x_opencti_stix_ids"] = (
                    self.opencti.get_attribute_in_extension("stix_ids", stix_object)
                )
            if "x_opencti_granted_refs" not in stix_object:
                stix_object["x_opencti_granted_refs"] = (
                    self.opencti.get_attribute_in_extension("granted_refs", stix_object)
                )
            if "x_opencti_workflow_id" not in stix_object:
                stix_object["x_opencti_workflow_id"] = (
                    self.opencti.get_attribute_in_extension("workflow_id", stix_object)
                )
            if "x_mitre_platforms" not in stix_object:
                stix_object["x_mitre_platforms"] = (
                    self.opencti.get_attribute_in_mitre_extension(
                        "platforms", stix_object
                    )
                )

            return self.create(
                stix_id=stix_object["id"],
                createdBy=(
                    extras["created_by_id"] if "created_by_id" in extras else None
                ),
                objectMarking=(
                    extras["object_marking_ids"]
                    if "object_marking_ids" in extras
                    else None
                ),
                objectLabel=(
                    extras["object_label_ids"] if "object_label_ids" in extras else None
                ),
                externalReferences=(
                    extras["external_references_ids"]
                    if "external_references_ids" in extras
                    else None
                ),
                revoked=stix_object["revoked"] if "revoked" in stix_object else None,
                confidence=(
                    stix_object["confidence"] if "confidence" in stix_object else None
                ),
                lang=stix_object["lang"] if "lang" in stix_object else None,
                created=stix_object["created"] if "created" in stix_object else None,
                modified=stix_object["modified"] if "modified" in stix_object else None,
                pattern_type=(
                    stix_object["pattern_type"]
                    if "pattern_type" in stix_object
                    else None
                ),
                pattern_version=(
                    stix_object["pattern_version"]
                    if "pattern_version" in stix_object
                    else None
                ),
                pattern=stix_object["pattern"] if "pattern" in stix_object else "",
                name=(
                    stix_object["name"]
                    if "name" in stix_object
                    else stix_object["pattern"]
                ),
                description=(
                    self.opencti.stix2.convert_markdown(stix_object["description"])
                    if "description" in stix_object
                    else None
                ),
                indicator_types=(
                    stix_object["indicator_types"]
                    if "indicator_types" in stix_object
                    else None
                ),
                valid_from=(
                    stix_object["valid_from"] if "valid_from" in stix_object else None
                ),
                valid_until=(
                    stix_object["valid_until"] if "valid_until" in stix_object else None
                ),
                x_opencti_score=(
                    stix_object["x_opencti_score"]
                    if "x_opencti_score" in stix_object
                    else 50
                ),
                x_opencti_detection=(
                    stix_object["x_opencti_detection"]
                    if "x_opencti_detection" in stix_object
                    else False
                ),
                x_mitre_platforms=(
                    stix_object["x_mitre_platforms"]
                    if "x_mitre_platforms" in stix_object
                    else None
                ),
                x_opencti_main_observable_type=(
                    stix_object["x_opencti_main_observable_type"]
                    if "x_opencti_main_observable_type" in stix_object
                    else "Unknown"
                ),
                killChainPhases=(
                    extras["kill_chain_phases_ids"]
                    if "kill_chain_phases_ids" in extras
                    else None
                ),
                x_opencti_stix_ids=(
                    stix_object["x_opencti_stix_ids"]
                    if "x_opencti_stix_ids" in stix_object
                    else None
                ),
                x_opencti_create_observables=(
                    stix_object["x_opencti_create_observables"]
                    if "x_opencti_create_observables" in stix_object
                    else False
                ),
                objectOrganization=(
                    stix_object["x_opencti_granted_refs"]
                    if "x_opencti_granted_refs" in stix_object
                    else None
                ),
                x_opencti_workflow_id=(
                    stix_object["x_opencti_workflow_id"]
                    if "x_opencti_workflow_id" in stix_object
                    else None
                ),
                update=update,
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_indicator] Missing parameters: stixObject"
            )
