# coding: utf-8

import json
import uuid

from stix2.canonicalization.Canonicalize import canonicalize


class ObservedData:
    """Main ObservedData class for OpenCTI

    Manages observed data and raw intelligence in the OpenCTI platform.

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type opencti: OpenCTIApiClient
    """

    def __init__(self, opencti):
        """Initialize the ObservedData instance.

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
            status {
                id
                template {
                  id
                  name
                  color
                }
            }
            createdBy {
                ... on Identity {
                    id
                    standard_id
                    entity_type
                    parent_types
                    spec_version
                    identity_class
                    name
                    description
                    roles
                    contact_information
                    x_opencti_aliases
                    created
                    modified
                    objectLabel {
                        id
                        value
                        color
                    }
                }
                ... on Organization {
                    x_opencti_organization_type
                    x_opencti_reliability
                }
                ... on Individual {
                    x_opencti_firstname
                    x_opencti_lastname
                }
            }
            objectOrganization {
                id
                standard_id
                name
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
            objectLabel {
                id
                value
                color
            }
            externalReferences {
                edges {
                    node {
                        id
                        standard_id
                        entity_type
                        source_name
                        description
                        url
                        hash
                        external_id
                        created
                        modified
                    }
                }
            }
            revoked
            confidence
            created
            modified
            first_observed
            last_observed
            number_observed
            objects(all: true) {
                edges {
                    node {
                        ... on BasicObject {
                            id
                            entity_type
                            parent_types
                        }
                        ... on BasicRelationship {
                            id
                            entity_type
                            parent_types
                        }
                        ... on StixObject {
                            standard_id
                            spec_version
                            created_at
                            updated_at
                        }
                        ... on AttackPattern {
                            name
                        }
                        ... on Campaign {
                            name
                        }
                        ... on CourseOfAction {
                            name
                        }
                        ... on Individual {
                            name
                        }
                        ... on Organization {
                            name
                        }
                        ... on Sector {
                            name
                        }
                        ... on System {
                            name
                        }
                        ... on Indicator {
                            name
                        }
                        ... on Infrastructure {
                            name
                        }
                        ... on IntrusionSet {
                            name
                        }
                        ... on Position {
                            name
                        }
                        ... on City {
                            name
                        }
                        ... on Country {
                            name
                        }
                        ... on Region {
                            name
                        }
                        ... on Malware {
                            name
                        }
                        ... on ThreatActor {
                            name
                        }
                        ... on Tool {
                            name
                        }
                        ... on Vulnerability {
                            name
                        }
                        ... on Incident {
                            name
                        }
                        ... on Event {
                            name
                        }
                        ... on Channel {
                            name
                        }
                        ... on Narrative {
                            name
                        }
                        ... on Language {
                            name
                        }
                        ... on DataComponent {
                            name
                        }
                        ... on DataSource {
                            name
                        }
                        ... on Case {
                            name
                        }
                        ... on StixCyberObservable {
                            observable_value
                        }
                        ... on StixCoreRelationship {
                            standard_id
                            spec_version
                            created_at
                            updated_at
                        }
                       ... on StixSightingRelationship {
                            standard_id
                            spec_version
                            created_at
                            updated_at
                        }
                    }
                }
            }
        """
        self.properties_with_files = """
            id
            standard_id
            entity_type
            parent_types
            spec_version
            created_at
            updated_at
            status {
                id
                template {
                  id
                  name
                  color
                }
            }
            createdBy {
                ... on Identity {
                    id
                    standard_id
                    entity_type
                    parent_types
                    spec_version
                    identity_class
                    name
                    description
                    roles
                    contact_information
                    x_opencti_aliases
                    created
                    modified
                    objectLabel {
                        id
                        value
                        color
                    }
                }
                ... on Organization {
                    x_opencti_organization_type
                    x_opencti_reliability
                }
                ... on Individual {
                    x_opencti_firstname
                    x_opencti_lastname
                }
            }
            objectOrganization {
                id
                standard_id
                name
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
            objectLabel {
                id
                value
                color
            }
            externalReferences {
                edges {
                    node {
                        id
                        standard_id
                        entity_type
                        source_name
                        description
                        url
                        hash
                        external_id
                        created
                        modified
                        importFiles {
                            edges {
                                node {
                                    id
                                    name
                                    size
                                    metaData {
                                        mimetype
                                        version
                                    }
                                }
                            }
                        }
                    }
                }
            }
            revoked
            confidence
            created
            modified
            first_observed
            last_observed
            number_observed
            objects(all: true) {
                edges {
                    node {
                        ... on BasicObject {
                            id
                            entity_type
                            parent_types
                        }
                        ... on BasicRelationship {
                            id
                            entity_type
                            parent_types
                        }
                        ... on StixObject {
                            standard_id
                            spec_version
                            created_at
                            updated_at
                        }
                        ... on AttackPattern {
                            name
                        }
                        ... on Campaign {
                            name
                        }
                        ... on CourseOfAction {
                            name
                        }
                        ... on Individual {
                            name
                        }
                        ... on Organization {
                            name
                        }
                        ... on Sector {
                            name
                        }
                        ... on System {
                            name
                        }
                        ... on Indicator {
                            name
                        }
                        ... on Infrastructure {
                            name
                        }
                        ... on IntrusionSet {
                            name
                        }
                        ... on Position {
                            name
                        }
                        ... on City {
                            name
                        }
                        ... on Country {
                            name
                        }
                        ... on Region {
                            name
                        }
                        ... on Malware {
                            name
                        }
                        ... on ThreatActor {
                            name
                        }
                        ... on Tool {
                            name
                        }
                        ... on Vulnerability {
                            name
                        }
                        ... on Incident {
                            name
                        }
                        ... on Event {
                            name
                        }
                        ... on Channel {
                            name
                        }
                        ... on Narrative {
                            name
                        }
                        ... on Language {
                            name
                        }
                        ... on DataComponent {
                            name
                        }
                        ... on DataSource {
                            name
                        }
                        ... on Case {
                            name
                        }
                        ... on StixCyberObservable {
                            observable_value
                        }
                        ... on StixCoreRelationship {
                            standard_id
                            spec_version
                            created_at
                            updated_at
                        }
                       ... on StixSightingRelationship {
                            standard_id
                            spec_version
                            created_at
                            updated_at
                        }
                    }
                }
            }
            importFiles {
                edges {
                    node {
                        id
                        name
                        size
                        metaData {
                            mimetype
                            version
                        }
                    }
                }
            }
        """

    @staticmethod
    def generate_id(object_ids):
        """Generate a STIX ID for an Observed Data object.

        :param object_ids: list of object IDs contained in the observed data
        :type object_ids: list
        :return: STIX ID for the Observed Data
        :rtype: str
        """
        data = {"objects": object_ids}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "observed-data--" + id

    @staticmethod
    def generate_id_from_data(data):
        """Generate a STIX ID from Observed Data data.

        :param data: Dictionary containing an 'object_refs' key
        :type data: dict
        :return: STIX ID for the Observed Data
        :rtype: str
        """
        return ObservedData.generate_id(data["object_refs"])

    def list(self, **kwargs):
        """List ObservedData objects.

        :param filters: the filters to apply
        :type filters: dict
        :param search: the search keyword
        :type search: str
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :type first: int
        :param after: ID of the first row for pagination
        :type after: str
        :return: List of ObservedData objects
        :rtype: list
        """
        filters = kwargs.get("filters", None)
        search = kwargs.get("search", None)
        first = kwargs.get("first", 500)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        custom_attributes = kwargs.get("customAttributes", None)
        with_pagination = kwargs.get("withPagination", False)
        with_files = kwargs.get("withFiles", False)

        self.opencti.app_logger.info(
            "Listing ObservedDatas with filters", {"filters": json.dumps(filters)}
        )
        query = (
            """
            query ObservedDatas($filters: FilterGroup, $search: String, $first: Int, $after: ID, $orderBy: ObservedDatasOrdering, $orderMode: OrderingMode) {
                observedDatas(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
                    edges {
                        node {
                            """
            + (
                custom_attributes
                if custom_attributes is not None
                else (self.properties_with_files if with_files else self.properties)
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
            },
        )
        return self.opencti.process_multiple(
            result["data"]["observedDatas"], with_pagination
        )

    def read(self, **kwargs):
        """Read an ObservedData object.

        :param id: the id of the ObservedData
        :type id: str
        :param filters: the filters to apply if no id provided
        :type filters: dict
        :return: ObservedData object
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        with_files = kwargs.get("withFiles", False)
        if id is not None:
            self.opencti.app_logger.info("Reading ObservedData", {"id": id})
            query = (
                """
                query ObservedData($id: String!) {
                    observedData(id: $id) {
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
            return self.opencti.process_multiple_fields(result["data"]["observedData"])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.app_logger.error(
                "[opencti_observed_data] Missing parameters: id or filters"
            )
            return None

    def contains_stix_object_or_stix_relationship(self, **kwargs):
        """Check if an observedData already contains a STIX entity.

        :param id: the id of the ObservedData
        :type id: str
        :param stixObjectOrStixRelationshipId: the id of the STIX entity
        :type stixObjectOrStixRelationshipId: str
        :return: True if contained, False otherwise
        :rtype: bool or None
        """
        id = kwargs.get("id", None)
        stix_object_or_stix_relationship_id = kwargs.get(
            "stixObjectOrStixRelationshipId", None
        )
        if id is not None and stix_object_or_stix_relationship_id is not None:
            self.opencti.app_logger.info(
                "Checking StixObjectOrStixRelationship in ObservedData",
                {
                    "id": id,
                    "stixObjectOrStixRelationshipId": stix_object_or_stix_relationship_id,
                },
            )
            query = """
                query ObservedDataContainsStixObjectOrStixRelationship($id: String!, $stixObjectOrStixRelationshipId: String!) {
                    observedDataContainsStixObjectOrStixRelationship(id: $id, stixObjectOrStixRelationshipId: $stixObjectOrStixRelationshipId)
                }
            """
            result = self.opencti.query(
                query,
                {
                    "id": id,
                    "stixObjectOrStixRelationshipId": stix_object_or_stix_relationship_id,
                },
            )
            return result["data"]["observedDataContainsStixObjectOrStixRelationship"]
        else:
            self.opencti.app_logger.error(
                "[opencti_observed_data] Missing parameters: id or entity_id"
            )
            return None

    def create(self, **kwargs):
        """Create an ObservedData object.

        :param stix_id: the STIX ID (optional)
        :type stix_id: str
        :param createdBy: the author ID (optional)
        :type createdBy: str
        :param objects: list of STIX object IDs (required)
        :type objects: list
        :param objectMarking: list of marking definition IDs (optional)
        :type objectMarking: list
        :param objectLabel: list of label IDs (optional)
        :type objectLabel: list
        :param externalReferences: list of external reference IDs (optional)
        :type externalReferences: list
        :param revoked: whether the observed data is revoked (optional)
        :type revoked: bool
        :param confidence: confidence level 0-100 (optional)
        :type confidence: int
        :param lang: language (optional)
        :type lang: str
        :param created: creation date (optional)
        :type created: str
        :param modified: modification date (optional)
        :type modified: str
        :param first_observed: the first observed datetime (required)
        :type first_observed: str
        :param last_observed: the last observed datetime (required)
        :type last_observed: str
        :param number_observed: number of times observed (optional)
        :type number_observed: int
        :param x_opencti_stix_ids: list of additional STIX IDs (optional)
        :type x_opencti_stix_ids: list
        :param objectOrganization: list of organization IDs (optional)
        :type objectOrganization: list
        :param x_opencti_workflow_id: workflow ID (optional)
        :type x_opencti_workflow_id: str
        :param x_opencti_modified_at: custom modification date (optional)
        :type x_opencti_modified_at: str
        :param update: whether to update if exists (default: False)
        :type update: bool
        :param files: (optional) list of File objects to attach
        :type files: list
        :param filesMarkings: (optional) list of lists of marking definition IDs for each file
        :type filesMarkings: list
        :return: ObservedData object
        :rtype: dict or None
        """
        stix_id = kwargs.get("stix_id", None)
        created_by = kwargs.get("createdBy", None)
        objects = kwargs.get("objects", None)
        object_marking = kwargs.get("objectMarking", None)
        object_label = kwargs.get("objectLabel", None)
        external_references = kwargs.get("externalReferences", None)
        revoked = kwargs.get("revoked", None)
        confidence = kwargs.get("confidence", None)
        lang = kwargs.get("lang", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        first_observed = kwargs.get("first_observed", None)
        last_observed = kwargs.get("last_observed", None)
        number_observed = kwargs.get("number_observed", None)
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        granted_refs = kwargs.get("objectOrganization", None)
        x_opencti_workflow_id = kwargs.get("x_opencti_workflow_id", None)
        x_opencti_modified_at = kwargs.get("x_opencti_modified_at", None)
        update = kwargs.get("update", False)
        files = kwargs.get("files", None)
        files_markings = kwargs.get("filesMarkings", None)
        upsert_operations = kwargs.get("upsert_operations", None)

        if (
            first_observed is not None
            and last_observed is not None
            and objects is not None
        ):
            self.opencti.app_logger.info("Creating ObservedData")

            query = """
                mutation ObservedDataAdd($input: ObservedDataAddInput!) {
                    observedDataAdd(input: $input) {
                        id
                        standard_id
                        entity_type
                        parent_types
                    }
                }
            """
            input_variables = {
                "stix_id": stix_id,
                "createdBy": created_by,
                "objectMarking": object_marking,
                "objectLabel": object_label,
                "objectOrganization": granted_refs,
                "objects": objects,
                "externalReferences": external_references,
                "revoked": revoked,
                "confidence": confidence,
                "lang": lang,
                "created": created,
                "modified": modified,
                "first_observed": first_observed,
                "last_observed": last_observed,
                "number_observed": number_observed,
                "x_opencti_stix_ids": x_opencti_stix_ids,
                "x_opencti_workflow_id": x_opencti_workflow_id,
                "x_opencti_modified_at": x_opencti_modified_at,
                "update": update,
                "files": files,
                "filesMarkings": files_markings,
                "upsertOperations": upsert_operations,
            }
            result = self.opencti.query(query, {"input": input_variables})
            return self.opencti.process_multiple_fields(
                result["data"]["observedDataAdd"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_observed_data] Missing parameters: "
                "first_observed, last_observed or objects"
            )
            return None

    def add_stix_object_or_stix_relationship(self, **kwargs):
        """Add a Stix-Core-Object or stix_relationship to ObservedData object (object).

        :param id: the id of the ObservedData
        :type id: str
        :param stixObjectOrStixRelationshipId: the id of the Stix-Core-Object or stix_relationship
        :type stixObjectOrStixRelationshipId: str
        :return: True if successful, False otherwise
        :rtype: bool
        """
        id = kwargs.get("id", None)
        stix_object_or_stix_relationship_id = kwargs.get(
            "stixObjectOrStixRelationshipId", None
        )
        if id is not None and stix_object_or_stix_relationship_id is not None:
            if self.contains_stix_object_or_stix_relationship(
                id=id,
                stixObjectOrStixRelationshipId=stix_object_or_stix_relationship_id,
            ):
                return True
            self.opencti.app_logger.info(
                "Adding StixObjectOrStixRelationship to ObservedData",
                {
                    "id": id,
                    "stixObjectOrStixRelationshipId": stix_object_or_stix_relationship_id,
                },
            )
            query = """
               mutation ObservedDataEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
                   observedDataEdit(id: $id) {
                        relationAdd(input: $input) {
                            id
                        }
                   }
               }
            """
            self.opencti.query(
                query,
                {
                    "id": id,
                    "input": {
                        "toId": stix_object_or_stix_relationship_id,
                        "relationship_type": "object",
                    },
                },
            )
            return True
        else:
            self.opencti.app_logger.error(
                "[opencti_observed_data] Missing parameters: "
                "id and stix_object_or_stix_relationship_id"
            )
            return False

    def remove_stix_object_or_stix_relationship(self, **kwargs):
        """Remove a Stix-Core-Object or stix_relationship from Observed-Data object.

        :param id: the id of the Observed-Data
        :type id: str
        :param stixObjectOrStixRelationshipId: the id of the Stix-Core-Object or stix_relationship
        :type stixObjectOrStixRelationshipId: str
        :return: True if successful, False otherwise
        :rtype: bool
        """
        id = kwargs.get("id", None)
        stix_object_or_stix_relationship_id = kwargs.get(
            "stixObjectOrStixRelationshipId", None
        )
        if id is not None and stix_object_or_stix_relationship_id is not None:
            self.opencti.app_logger.info(
                "Removing StixObjectOrStixRelationship from Observed-Data",
                {
                    "id": id,
                    "stixObjectOrStixRelationshipId": stix_object_or_stix_relationship_id,
                },
            )
            query = """
               mutation ObservedDataEditRelationDelete($id: ID!, $toId: StixRef!, $relationship_type: String!) {
                   observedDataEdit(id: $id) {
                        relationDelete(toId: $toId, relationship_type: $relationship_type) {
                            id
                        }
                   }
               }
            """
            self.opencti.query(
                query,
                {
                    "id": id,
                    "toId": stix_object_or_stix_relationship_id,
                    "relationship_type": "object",
                },
            )
            return True
        else:
            self.opencti.app_logger.error(
                "[opencti_observed_data] Missing parameters: id and entity_id"
            )
            return False

    def import_from_stix2(self, **kwargs):
        """Import an ObservedData object from a STIX2 object.

        :param stixObject: the Stix-Object ObservedData
        :type stixObject: dict
        :param extras: additional parameters like created_by_id, object_marking_ids
        :type extras: dict
        :param update: whether to update existing object
        :type update: bool
        :return: ObservedData object
        :rtype: dict or None
        """
        stix_object = kwargs.get("stixObject", None)
        extras = kwargs.get("extras", {})
        update = kwargs.get("update", False)
        object_refs = extras["object_ids"] if "object_ids" in extras else []

        if "objects" in stix_object:
            stix_observable_results = []
            for key, observable_item in stix_object["objects"].items():
                stix_observable_results.append(
                    self.opencti.stix_cyber_observable.create(
                        observableData=observable_item,
                        createdBy=(
                            extras["created_by_id"]
                            if "created_by_id" in extras
                            else None
                        ),
                        objectMarking=(
                            extras["object_marking_ids"]
                            if "object_marking_ids" in extras
                            else None
                        ),
                        objectLabel=(
                            extras["object_label_ids"]
                            if "object_label_ids" in extras
                            else None
                        ),
                        objectOrganization=(
                            extras["granted_refs_ids"]
                            if "granted_refs_ids" in extras
                            else None
                        ),
                    )
                )
                for item in stix_observable_results:
                    object_refs.append(item["standard_id"])

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
            if "x_opencti_workflow_id" not in stix_object:
                stix_object["x_opencti_workflow_id"] = (
                    self.opencti.get_attribute_in_extension("workflow_id", stix_object)
                )
            if "x_opencti_modified_at" not in stix_object:
                stix_object["x_opencti_modified_at"] = (
                    self.opencti.get_attribute_in_extension("modified_at", stix_object)
                )
            if "opencti_upsert_operations" not in stix_object:
                stix_object["opencti_upsert_operations"] = (
                    self.opencti.get_attribute_in_extension(
                        "opencti_upsert_operations", stix_object
                    )
                )

            observed_data_result = self.create(
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
                objects=object_refs,
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
                first_observed=(
                    stix_object["first_observed"]
                    if "first_observed" in stix_object
                    else None
                ),
                last_observed=(
                    stix_object["last_observed"]
                    if "last_observed" in stix_object
                    else None
                ),
                number_observed=(
                    stix_object["number_observed"]
                    if "number_observed" in stix_object
                    else None
                ),
                x_opencti_stix_ids=(
                    stix_object["x_opencti_stix_ids"]
                    if "x_opencti_stix_ids" in stix_object
                    else None
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
                x_opencti_modified_at=(
                    stix_object["x_opencti_modified_at"]
                    if "x_opencti_modified_at" in stix_object
                    else None
                ),
                update=update,
                files=extras.get("files"),
                filesMarkings=extras.get("filesMarkings"),
                upsert_operations=(
                    stix_object["opencti_upsert_operations"]
                    if "opencti_upsert_operations" in stix_object
                    else None
                ),
            )

            return observed_data_result
        else:
            self.opencti.app_logger.error(
                "[opencti_observed_data] Missing parameters: stixObject"
            )
            return None
