# coding: utf-8

import json
import uuid

from stix2.canonicalization.Canonicalize import canonicalize


class SecurityCoverageResult:
    """Main SecurityCoverageResult class for OpenCTI

    Manages security coverage results in the OpenCTI platform.

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type opencti: OpenCTIApiClient
    """

    def __init__(self, opencti):
        """Initialize the SecurityCoverageResult instance.

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
            external_uri
            coverage_last_result
            coverage_valid_from
            coverage_valid_to
            coverage_information {
                coverage_name
                coverage_score
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
    def generate_id(name, external_uri, result_of_ref):
        """Generate a STIX ID for a Security Coverage Result.

        :param name: The name of the security coverage result (can be None)
        :type name: str or None
        :param external_uri: The external URI of the result (can be None)
        :type external_uri: str or None
        :param result_of_ref: The standard_id of the parent SecurityCoverage
        :type result_of_ref: str
        :return: STIX ID for the security coverage result
        :rtype: str
        """
        data = {"result_of_ref": result_of_ref.strip()}
        if name is not None:
            data["name"] = name.lower().strip()
        if external_uri is not None:
            data["external_uri"] = external_uri.strip()
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "security-coverage-result--" + id

    @staticmethod
    def generate_id_from_data(data):
        """Generate a STIX ID from security coverage result data.

        :param data: Dictionary containing 'result_of_ref', and optionally 'name' and 'external_uri'
        :type data: dict
        :return: STIX ID for the security coverage result
        :rtype: str
        """
        return SecurityCoverageResult.generate_id(
            # Using .get instead of direct access because can be None
            data.get("name"),
            data.get("external_uri"),
            data["result_of_ref"],
        )

    def list(self, **kwargs):
        """List SecurityCoverageResult objects.

        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return: List of SecurityCoverageResult objects
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
            "Listing SecurityCoverageResult with filters",
            {"filters": json.dumps(filters)},
        )
        query = (
            """
                query SecurityCoverageResults($filters: FilterGroup, $search: String, $first: Int, $after: ID, $orderBy: SecurityCoverageResultOrdering, $orderMode: OrderingMode) {
                    securityCoverageResults(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
            data = self.opencti.process_multiple(
                result["data"]["securityCoverageResults"]
            )
            final_data = final_data + data
            while result["data"]["securityCoverageResults"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["securityCoverageResults"]["pageInfo"][
                    "endCursor"
                ]
                self.opencti.app_logger.info(
                    "Listing SecurityCoverageResult", {"after": after}
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
                    result["data"]["securityCoverageResults"]
                )
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["securityCoverageResults"], with_pagination
            )

    def read(self, **kwargs):
        """Read a SecurityCoverageResult object.

        :param id: the id of the SecurityCoverageResult
        :type id: str
        :param filters: the filters to apply if no id provided
        :type filters: dict
        :param customAttributes: custom attributes to return
        :type customAttributes: str
        :return: SecurityCoverageResult object
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.app_logger.info("Reading SecurityCoverageResult", {"id": id})
            query = (
                """
                    query SecurityCoverageResult($id: String!) {
                        securityCoverageResult(id: $id) {
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
                result["data"]["securityCoverageResult"]
            )
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.app_logger.error(
                "[opencti_security_coverage_result] Missing parameters: id or filters"
            )
            return None

    def create(self, **kwargs):
        """Create a Security Coverage Result object.

        :param name: the name of the Security Coverage Result (optional)
        :type name: str or None
        :param resultOf: the parent SecurityCoverage ID (required)
        :type resultOf: str
        :param stix_id: (optional) the STIX ID
        :type stix_id: str
        :param description: (optional) description
        :type description: str
        :param createdBy: (optional) the author ID
        :type createdBy: str
        :param objectMarking: (optional) list of marking definition IDs
        :type objectMarking: list
        :param objectLabel: (optional) list of label IDs
        :type objectLabel: list
        :param externalReferences: (optional) list of external reference IDs
        :type externalReferences: list
        :param external_uri: (optional) external URI
        :type external_uri: str
        :param coverage_last_result: (optional) last result date
        :type coverage_last_result: str
        :param coverage_valid_from: (optional) valid from date
        :type coverage_valid_from: str
        :param coverage_valid_to: (optional) valid to date
        :type coverage_valid_to: str
        :param coverage_information: (optional) coverage information
        :type coverage_information: list
        :param files: (optional) list of File objects to attach
        :type files: list
        :param filesMarkings: (optional) list of lists of marking definition IDs for each file
        :type filesMarkings: list
        :return: Security Coverage Result object
        :rtype: dict or None
        """
        stix_id = kwargs.get("stix_id", None)
        name = kwargs.get("name", None)
        description = kwargs.get("description", None)
        created_by = kwargs.get("createdBy", None)
        object_marking = kwargs.get("objectMarking", None)
        object_label = kwargs.get("objectLabel", None)
        result_of = kwargs.get("resultOf", None)
        external_references = kwargs.get("externalReferences", None)
        external_uri = kwargs.get("external_uri", None)
        coverage_last_result = kwargs.get("coverage_last_result", None)
        coverage_valid_from = kwargs.get("coverage_valid_from", None)
        coverage_valid_to = kwargs.get("coverage_valid_to", None)
        coverage_information = kwargs.get("coverage_information", None)
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        files = kwargs.get("files", None)
        files_markings = kwargs.get("filesMarkings", None)
        no_trigger_import = kwargs.get("noTriggerImport", None)
        embedded = kwargs.get("embedded", None)

        if result_of is not None:
            self.opencti.app_logger.info(
                "Creating Security Coverage Result", {"name": name}
            )
            query = (
                """
                mutation SecurityCoverageResultAdd($input: SecurityCoverageResultAddInput!) {
                    securityCoverageResultAdd(input: $input) {"""
                + self.properties
                + """
                    }
                }
            """
            )
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
                        "resultOf": result_of,
                        "external_uri": external_uri,
                        "externalReferences": external_references,
                        "coverage_last_result": coverage_last_result,
                        "coverage_valid_from": coverage_valid_from,
                        "coverage_valid_to": coverage_valid_to,
                        "coverage_information": coverage_information,
                        "x_opencti_stix_ids": x_opencti_stix_ids,
                        "files": files,
                        "filesMarkings": files_markings,
                        "noTriggerImport": no_trigger_import,
                        "embedded": embedded,
                    }
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["securityCoverageResultAdd"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_security_coverage_result] " "Missing parameters: result_of"
            )
            return None

    def import_from_stix2(self, **kwargs):
        """Import a Security Coverage Result from a STIX2 object.

        :param stixObject: the STIX2 Security Coverage Result object
        :type stixObject: dict
        :param extras: extra parameters including created_by_id, object_marking_ids, etc.
        :type extras: dict
        :param update: whether to update if the entity already exists
        :type update: bool
        :return: Security Coverage Result object
        :rtype: dict or None
        """
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
                coverage_last_result=(
                    stix_object["coverage_last_result"]
                    if "coverage_last_result" in stix_object
                    else None
                ),
                coverage_valid_from=(
                    stix_object["coverage_valid_from"]
                    if "coverage_valid_from" in stix_object
                    else None
                ),
                coverage_valid_to=(
                    stix_object["coverage_valid_to"]
                    if "coverage_valid_to" in stix_object
                    else None
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
                resultOf=(
                    stix_object["result_of_ref"]
                    if "result_of_ref" in stix_object
                    else None
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
                files=extras.get("files"),
                filesMarkings=extras.get("filesMarkings"),
                noTriggerImport=extras.get("noTriggerImport", None),
                embedded=extras.get("embedded", None),
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_security_coverage_result] Missing parameters: stixObject"
            )
            return None
