# coding: utf-8

import json
import uuid

from stix2.canonicalization.Canonicalize import canonicalize


class SecurityCoverage:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            standard_id
            entity_type
            parent_types
            spec_version
            created_at
            updated_at
            external_uri
            objectCovered {
                __typename
                ... on StixCoreObject {
                  id
                }
            }
            objectMarking {
                id
                standard_id
                entity_type
                definition_type
                definition
                created
                modified
                x_opencti_order
                x_opencti_color
            }
        """

    @staticmethod
    def generate_id(covered_ref):
        data = {"covered_ref": covered_ref.lower().strip()}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "security-coverage--" + id

    @staticmethod
    def generate_id_from_data(data):
        return SecurityCoverage.generate_id(data["covered_ref"])

    """
        List securityCoverage objects

        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of SecurityCoverage objects
    """

    def list(self, **kwargs):
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
            "Listing SecurityCoverage with filters", {"filters": json.dumps(filters)}
        )
        query = (
            """
                query SecurityCoverage($filters: FilterGroup, $search: String, $first: Int, $after: ID, $orderBy: SecurityCoverageOrdering, $orderMode: OrderingMode) {
                    securityCoverages(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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

        if get_all:
            final_data = []
            data = self.opencti.process_multiple(result["data"]["securityCoverages"])
            final_data = final_data + data
            while result["data"]["securityCoverages"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["securityCoverages"]["pageInfo"]["endCursor"]
                self.opencti.app_logger.info(
                    "Listing SecurityCoverage", {"after": after}
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
                    },
                )
                data = self.opencti.process_multiple(
                    result["data"]["securityCoverages"]
                )
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["securityCoverages"], with_pagination
            )

    """
        Read a SecurityCoverage object

        :param id: the id of the SecurityCoverage
        :param filters: the filters to apply if no id provided
        :return SecurityCoverage object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.app_logger.info("Reading SecurityCoverage", {"id": id})
            query = (
                """
                    query SecurityCoverage($id: String!) {
                        securityCoverage(id: $id) {
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
            return self.opencti.process_multiple_fields(
                result["data"]["securityCoverage"]
            )
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.app_logger.error(
                "[opencti_security_coverage] Missing parameters: id or filters"
            )
            return None

    """
        Create a Security coverage object

        :return Security Coverage object
    """

    def create(self, **kwargs):
        stix_id = kwargs.get("stix_id", None)
        name = kwargs.get("name", None)
        description = kwargs.get("description", None)
        created_by = kwargs.get("createdBy", None)
        object_marking = kwargs.get("objectMarking", None)
        object_label = kwargs.get("objectLabel", None)
        object_covered = kwargs.get("objectCovered", None)
        external_references = kwargs.get("externalReferences", None)
        external_uri = kwargs.get("external_uri", None)
        coverage_last_result = kwargs.get("coverage_last_result", None)
        coverage_valid_from = kwargs.get("coverage_valid_from", None)
        coverage_valid_to = kwargs.get("coverage_valid_to", None)
        coverage_information = kwargs.get("coverage_information", None)
        auto_enrichment_disable = kwargs.get("auto_enrichment_disable", None)

        if name is not None and object_covered is not None:
            self.opencti.app_logger.info("Creating Security Coverage", {"name": name})
            query = """
                mutation SecurityCoverageAdd($input: SecurityCoverageAddInput!) {
                    securityCoverageAdd(input: $input) {
                        id
                        standard_id
                        entity_type
                        parent_types
                    }
                }
            """
            result = self.opencti.query(
                query,
                {
                    "input": {
                        "stix_id": stix_id,
                        "name": name,
                        "description": description,
                        "createdBy": created_by,
                        "objectMarking": object_marking,
                        "objectLabel": object_label,
                        "objectCovered": object_covered,
                        "external_uri": external_uri,
                        "externalReferences": external_references,
                        "coverage_last_result": coverage_last_result,
                        "coverage_valid_from": coverage_valid_from,
                        "coverage_valid_to": coverage_valid_to,
                        "coverage_information": coverage_information,
                        "auto_enrichment_disable": auto_enrichment_disable,
                    }
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["securityCoverageAdd"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_security_coverage] "
                "Missing parameters: name or object_covered"
            )

    """
        Import a Security coverage from a STIX2 object

        :param stixObject: the Stix-Object Security coverage
        :return Security coverage object
    """

    def import_from_stix2(self, **kwargs):
        stix_object = kwargs.get("stixObject", None)
        extras = kwargs.get("extras", {})
        if stix_object is not None:
            # Search in extensions
            if "x_opencti_stix_ids" not in stix_object:
                stix_object["x_opencti_stix_ids"] = (
                    self.opencti.get_attribute_in_extension("stix_ids", stix_object)
                )
            if "x_opencti_granted_refs" not in stix_object:
                stix_object["x_opencti_granted_refs"] = (
                    self.opencti.get_attribute_in_extension("granted_refs", stix_object)
                )

            raw_coverages = stix_object["coverage"] if "coverage" in stix_object else []
            coverage_information = list(
                map(
                    lambda cov: {
                        "coverage_name": cov["name"],
                        "coverage_score": cov["score"],
                    },
                    raw_coverages,
                )
            )

            return self.create(
                stix_id=stix_object["id"],
                name=stix_object["name"],
                external_uri=(
                    stix_object["external_uri"]
                    if "external_uri" in stix_object
                    else None
                ),
                auto_enrichment_disable=(
                    stix_object["auto_enrichment_disable"]
                    if "auto_enrichment_disable" in stix_object
                    else False
                ),
                coverage_last_result=(
                    stix_object["last_result"] if "last_result" in stix_object else None
                ),
                coverage_valid_from=(
                    stix_object["valid_from"] if "valid_from" in stix_object else None
                ),
                coverage_valid_to=(
                    stix_object["valid_to"] if "valid_to" in stix_object else None
                ),
                coverage_information=coverage_information,
                description=(
                    self.opencti.stix2.convert_markdown(stix_object["description"])
                    if "description" in stix_object
                    else None
                ),
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
                objectCovered=(
                    stix_object["covered_ref"] if "covered_ref" in stix_object else None
                ),
                externalReferences=(
                    extras["external_references_ids"]
                    if "external_references_ids" in extras
                    else None
                ),
                x_opencti_stix_ids=(
                    stix_object["x_opencti_stix_ids"]
                    if "x_opencti_stix_ids" in stix_object
                    else None
                ),
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_security_coverage] Missing parameters: stixObject"
            )
