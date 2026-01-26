# coding: utf-8

import datetime
import uuid

from stix2.canonicalization.Canonicalize import canonicalize


class StixCoreRelationship:
    """Main StixCoreRelationship class for OpenCTI

    Manages STIX relationships between entities in the OpenCTI platform.

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type opencti: OpenCTIApiClient
    """

    def __init__(self, opencti):
        """Initialize the StixCoreRelationship instance.

        :param opencti: OpenCTI API client instance
        :type opencti: OpenCTIApiClient
        """
        self.opencti = opencti
        self.properties = """
            id
            entity_type
            parent_types
            spec_version
            created_at
            updated_at
            standard_id
            relationship_type
            description
            start_time
            stop_time
            revoked
            confidence
            lang
            created
            modified
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
            objectOrganization {
                id
                standard_id
                name
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
            from {
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
                    description
                }
                ... on Channel {
                    name
                    description
                }
                ... on Narrative {
                    name
                    description
                }
                ... on Language {
                    name
                }
                ... on DataComponent {
                    name
                    description
                }
                ... on DataSource {
                    name
                    description
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
            }
            to {
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
                    description
                }
                ... on Channel {
                    name
                    description
                }
                ... on Narrative {
                    name
                    description
                }
                ... on Language {
                    name
                }
                ... on DataComponent {
                    name
                    description
                }
                ... on DataSource {
                    name
                    description
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
            }
        """

    @staticmethod
    def generate_id(
        relationship_type, source_ref, target_ref, start_time=None, stop_time=None
    ):
        """Generate a STIX ID for a relationship.

        :param relationship_type: The type of relationship
        :type relationship_type: str
        :param source_ref: The source entity reference ID
        :type source_ref: str
        :param target_ref: The target entity reference ID
        :type target_ref: str
        :param start_time: (optional) The start time of the relationship
        :type start_time: str or datetime.datetime or None
        :param stop_time: (optional) The stop time of the relationship
        :type stop_time: str or datetime.datetime or None
        :return: STIX ID for the relationship
        :rtype: str
        """
        if isinstance(start_time, datetime.datetime):
            start_time = start_time.isoformat()
        if isinstance(stop_time, datetime.datetime):
            stop_time = stop_time.isoformat()

        if start_time is not None and stop_time is not None:
            data = {
                "relationship_type": relationship_type,
                "source_ref": source_ref,
                "target_ref": target_ref,
                "start_time": start_time,
                "stop_time": stop_time,
            }
        elif start_time is not None:
            data = {
                "relationship_type": relationship_type,
                "source_ref": source_ref,
                "target_ref": target_ref,
                "start_time": start_time,
            }
        else:
            data = {
                "relationship_type": relationship_type,
                "source_ref": source_ref,
                "target_ref": target_ref,
            }
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "relationship--" + id

    @staticmethod
    def generate_id_from_data(data):
        """Generate a STIX ID from relationship data.

        :param data: Dictionary containing relationship_type, source_ref, target_ref, and optionally start_time/stop_time
        :type data: dict
        :return: STIX ID for the relationship
        :rtype: str
        """
        return StixCoreRelationship.generate_id(
            data["relationship_type"],
            data["source_ref"],
            data["target_ref"],
            data.get("start_time"),
            data.get("stop_time"),
        )

    def list(self, **kwargs):
        """List stix_core_relationship objects.

        :param fromOrToId: the id of an entity (source or target)
        :type fromOrToId: str
        :param elementWithTargetTypes: filter by target types
        :type elementWithTargetTypes: list
        :param fromId: the id of the source entity of the relation
        :type fromId: str
        :param fromTypes: filter by source entity types
        :type fromTypes: list
        :param toId: the id of the target entity of the relation
        :type toId: str
        :param toTypes: filter by target entity types
        :type toTypes: list
        :param relationship_type: the relation type
        :type relationship_type: str
        :param startTimeStart: the start_time date start filter
        :type startTimeStart: str
        :param startTimeStop: the start_time date stop filter
        :type startTimeStop: str
        :param stopTimeStart: the stop_time date start filter
        :type stopTimeStart: str
        :param stopTimeStop: the stop_time date stop filter
        :type stopTimeStop: str
        :param filters: additional filters to apply
        :type filters: dict
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :type first: int
        :param after: ID of the first row for pagination
        :type after: str
        :param orderBy: field to order results by
        :type orderBy: str
        :param orderMode: ordering mode (asc/desc)
        :type orderMode: str
        :param customAttributes: custom attributes to return
        :type customAttributes: str
        :param getAll: whether to retrieve all results
        :type getAll: bool
        :param withPagination: whether to include pagination info
        :type withPagination: bool
        :param search: search keyword
        :type search: str
        :return: List of stix_core_relationship objects
        :rtype: list
        """
        from_or_to_id = kwargs.get("fromOrToId", None)
        element_with_target_types = kwargs.get("elementWithTargetTypes", None)
        from_id = kwargs.get("fromId", None)
        from_types = kwargs.get("fromTypes", None)
        to_id = kwargs.get("toId", None)
        to_types = kwargs.get("toTypes", None)
        relationship_type = kwargs.get("relationship_type", None)
        start_time_start = kwargs.get("startTimeStart", None)
        start_time_stop = kwargs.get("startTimeStop", None)
        stop_time_start = kwargs.get("stopTimeStart", None)
        stop_time_stop = kwargs.get("stopTimeStop", None)
        filters = kwargs.get("filters", None)
        first = kwargs.get("first", 100)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        custom_attributes = kwargs.get("customAttributes", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)
        search = kwargs.get("search", None)

        self.opencti.app_logger.info(
            "Listing stix_core_relationships",
            {
                "relationship_type": relationship_type,
                "from_or_to_id": from_or_to_id,
                "from_id": from_id,
                "to_id": to_id,
                "element_with_target_types": element_with_target_types,
                "from_types": from_types,
                "to_types": to_types,
                "search": search,
            },
        )
        query = (
            """
                query StixCoreRelationships($fromOrToId: [String], $elementWithTargetTypes: [String], $fromId: [String], $fromTypes: [String], $toId: [String], $toTypes: [String], $relationship_type: [String], $startTimeStart: DateTime, $startTimeStop: DateTime, $stopTimeStart: DateTime, $stopTimeStop: DateTime, $filters: FilterGroup, $first: Int, $after: ID, $orderBy: StixCoreRelationshipsOrdering, $orderMode: OrderingMode, $search: String) {
                    stixCoreRelationships(fromOrToId: $fromOrToId, elementWithTargetTypes: $elementWithTargetTypes, fromId: $fromId, fromTypes: $fromTypes, toId: $toId, toTypes: $toTypes, relationship_type: $relationship_type, startTimeStart: $startTimeStart, startTimeStop: $startTimeStop, stopTimeStart: $stopTimeStart, stopTimeStop: $stopTimeStop, filters: $filters, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode, search: $search) {
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
                "fromOrToId": from_or_to_id,
                "elementWithTargetTypes": element_with_target_types,
                "fromId": from_id,
                "fromTypes": from_types,
                "toId": to_id,
                "toTypes": to_types,
                "relationship_type": relationship_type,
                "startTimeStart": start_time_start,
                "startTimeStop": start_time_stop,
                "stopTimeStart": stop_time_start,
                "stopTimeStop": stop_time_stop,
                "filters": filters,
                "first": first,
                "after": after,
                "orderBy": order_by,
                "orderMode": order_mode,
                "search": search,
            },
        )
        if get_all:
            final_data = []
            data = self.opencti.process_multiple(
                result["data"]["stixCoreRelationships"]
            )
            final_data = final_data + data
            while result["data"]["stixCoreRelationships"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["stixCoreRelationships"]["pageInfo"]["endCursor"]
                self.opencti.app_logger.debug(
                    "Listing StixCoreRelationships", {"after": after}
                )
                result = self.opencti.query(
                    query,
                    {
                        "fromOrToId": from_or_to_id,
                        "elementWithTargetTypes": element_with_target_types,
                        "fromId": from_id,
                        "fromTypes": from_types,
                        "toId": to_id,
                        "toTypes": to_types,
                        "relationship_type": relationship_type,
                        "startTimeStart": start_time_start,
                        "startTimeStop": start_time_stop,
                        "stopTimeStart": stop_time_start,
                        "stopTimeStop": stop_time_stop,
                        "filters": filters,
                        "first": first,
                        "after": after,
                        "orderBy": order_by,
                        "orderMode": order_mode,
                        "search": search,
                    },
                )
                data = self.opencti.process_multiple(
                    result["data"]["stixCoreRelationships"]
                )
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["stixCoreRelationships"], with_pagination
            )

    def read(self, **kwargs):
        """Read a stix_core_relationship object.

        :param id: the id of the stix_core_relationship
        :type id: str
        :param fromOrToId: the id of an entity (source or target)
        :type fromOrToId: str
        :param fromId: the id of the source entity of the relation
        :type fromId: str
        :param toId: the id of the target entity of the relation
        :type toId: str
        :param relationship_type: the relation type
        :type relationship_type: str
        :param startTimeStart: the start_time date start filter
        :type startTimeStart: str
        :param startTimeStop: the start_time date stop filter
        :type startTimeStop: str
        :param stopTimeStart: the stop_time date start filter
        :type stopTimeStart: str
        :param stopTimeStop: the stop_time date stop filter
        :type stopTimeStop: str
        :param filters: filters to apply
        :type filters: dict
        :param customAttributes: custom attributes to return
        :type customAttributes: str
        :return: stix_core_relationship object
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        from_or_to_id = kwargs.get("fromOrToId", None)
        from_id = kwargs.get("fromId", None)
        to_id = kwargs.get("toId", None)
        relationship_type = kwargs.get("relationship_type", None)
        start_time_start = kwargs.get("startTimeStart", None)
        start_time_stop = kwargs.get("startTimeStop", None)
        stop_time_start = kwargs.get("stopTimeStart", None)
        stop_time_stop = kwargs.get("stopTimeStop", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.app_logger.info("Reading stix_core_relationship", {"id": id})
            query = (
                """
                    query StixCoreRelationship($id: String!) {
                        stixCoreRelationship(id: $id) {
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
                result["data"]["stixCoreRelationship"]
            )
        elif filters is not None:
            result = self.list(filters=filters, customAttributes=custom_attributes)
            if len(result) > 0:
                return result[0]
            else:
                return None
        elif from_id is not None and to_id is not None:
            result = self.list(
                fromOrToId=from_or_to_id,
                fromId=from_id,
                toId=to_id,
                relationship_type=relationship_type,
                startTimeStart=start_time_start,
                startTimeStop=start_time_stop,
                stopTimeStart=stop_time_start,
                stopTimeStop=stop_time_stop,
            )
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.app_logger.error("Missing parameters: id or from_id and to_id")
            return None

    def create(self, **kwargs):
        """Create a stix_core_relationship object.

        :param fromId: the id of the source entity
        :type fromId: str
        :param toId: the id of the target entity
        :type toId: str
        :param stix_id: (optional) the STIX ID
        :type stix_id: str
        :param relationship_type: the type of relationship
        :type relationship_type: str
        :param description: (optional) description
        :type description: str
        :param start_time: (optional) start time of the relationship
        :type start_time: str
        :param stop_time: (optional) stop time of the relationship
        :type stop_time: str
        :param revoked: (optional) whether the relationship is revoked
        :type revoked: bool
        :param confidence: (optional) confidence level (0-100)
        :type confidence: int
        :param lang: (optional) language
        :type lang: str
        :param created: (optional) creation date
        :type created: str
        :param modified: (optional) modification date
        :type modified: str
        :param createdBy: (optional) the author ID
        :type createdBy: str
        :param objectMarking: (optional) list of marking definition IDs
        :type objectMarking: list
        :param objectLabel: (optional) list of label IDs
        :type objectLabel: list
        :param externalReferences: (optional) list of external reference IDs
        :type externalReferences: list
        :param killChainPhases: (optional) list of kill chain phase IDs
        :type killChainPhases: list
        :param objectOrganization: (optional) list of organization IDs
        :type objectOrganization: list
        :param x_opencti_workflow_id: (optional) workflow ID
        :type x_opencti_workflow_id: str
        :param x_opencti_stix_ids: (optional) list of additional STIX IDs
        :type x_opencti_stix_ids: list
        :param x_opencti_modified_at: (optional) custom modification date
        :type x_opencti_modified_at: str
        :param coverage_information: (optional) coverage information
        :type coverage_information: list
        :param update: (optional) whether to update if exists (default: False)
        :type update: bool
        :return: stix_core_relationship object
        :rtype: dict or None
        """
        from_id = kwargs.get("fromId", None)
        to_id = kwargs.get("toId", None)
        stix_id = kwargs.get("stix_id", None)
        relationship_type = kwargs.get("relationship_type", None)
        description = kwargs.get("description", None)
        start_time = kwargs.get("start_time", None)
        stop_time = kwargs.get("stop_time", None)
        revoked = kwargs.get("revoked", None)
        confidence = kwargs.get("confidence", None)
        lang = kwargs.get("lang", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by = kwargs.get("createdBy", None)
        object_marking = kwargs.get("objectMarking", None)
        object_label = kwargs.get("objectLabel", None)
        external_references = kwargs.get("externalReferences", None)
        kill_chain_phases = kwargs.get("killChainPhases", None)
        granted_refs = kwargs.get("objectOrganization", None)
        x_opencti_workflow_id = kwargs.get("x_opencti_workflow_id", None)
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        x_opencti_modified_at = kwargs.get("x_opencti_modified_at", None)
        coverage_information = kwargs.get("coverage_information", None)
        update = kwargs.get("update", False)
        upsert_operations = kwargs.get("upsert_operations", None)

        self.opencti.app_logger.info(
            "Creating stix_core_relationship",
            {
                "relationship_type": relationship_type,
                "from_id": from_id,
                "to_id": to_id,
            },
        )
        query = """
                mutation StixCoreRelationshipAdd($input: StixCoreRelationshipAddInput!) {
                    stixCoreRelationshipAdd(input: $input) {
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
                    "fromId": from_id,
                    "toId": to_id,
                    "stix_id": stix_id,
                    "relationship_type": relationship_type,
                    "description": description,
                    "start_time": start_time,
                    "stop_time": stop_time,
                    "revoked": revoked,
                    "confidence": confidence,
                    "lang": lang,
                    "created": created,
                    "modified": modified,
                    "createdBy": created_by,
                    "objectMarking": object_marking,
                    "objectLabel": object_label,
                    "objectOrganization": granted_refs,
                    "externalReferences": external_references,
                    "killChainPhases": kill_chain_phases,
                    "x_opencti_workflow_id": x_opencti_workflow_id,
                    "x_opencti_stix_ids": x_opencti_stix_ids,
                    "x_opencti_modified_at": x_opencti_modified_at,
                    "coverage_information": coverage_information,
                    "update": update,
                    "upsertOperations": upsert_operations,
                }
            },
        )
        return self.opencti.process_multiple_fields(
            result["data"]["stixCoreRelationshipAdd"]
        )

    def update_field(self, **kwargs):
        """Update a stix_core_relationship object field.

        :param id: the stix_core_relationship id
        :type id: str
        :param input: the input of the field
        :type input: list
        :return: The updated stix_core_relationship object
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        input = kwargs.get("input", None)
        if id is not None and input is not None:
            self.opencti.app_logger.info("Updating stix_core_relationship", {"id": id})
            query = """
                    mutation StixCoreRelationshipEdit($id: ID!, $input: [EditInput]!) {
                        stixCoreRelationshipEdit(id: $id) {
                            fieldPatch(input: $input) {
                                id
                                standard_id
                                entity_type
                            }
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
                result["data"]["stixCoreRelationshipEdit"]["fieldPatch"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_stix_core_relationship] Missing parameters: id and input",
            )
            return None

    def delete(self, **kwargs):
        """Delete a stix_core_relationship.

        :param id: the stix_core_relationship id
        :type id: str
        :return: None
        """
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.app_logger.info("Deleting stix_core_relationship", {"id": id})
            query = """
                mutation StixCoreRelationshipEdit($id: ID!) {
                    stixCoreRelationshipEdit(id: $id) {
                        delete
                    }
                }
            """
            self.opencti.query(query, {"id": id})
        else:
            self.opencti.app_logger.error(
                "[opencti_stix_core_relationship] Missing parameters: id"
            )
            return None

    def add_marking_definition(self, **kwargs):
        """Add a Marking-Definition object to stix_core_relationship object (object_marking_refs).

        :param id: the id of the stix_core_relationship
        :type id: str
        :param marking_definition_id: the id of the Marking-Definition
        :type marking_definition_id: str
        :return: True if successful, False otherwise
        :rtype: bool
        """
        id = kwargs.get("id", None)
        marking_definition_id = kwargs.get("marking_definition_id", None)
        if id is not None and marking_definition_id is not None:
            custom_attributes = """
                id
                objectMarking {
                    id
                    standard_id
                    entity_type
                    definition_type
                    definition
                    x_opencti_order
                    x_opencti_color
                    created
                    modified
                }
            """
            stix_core_relationship = self.read(
                id=id, customAttributes=custom_attributes
            )
            if stix_core_relationship is None:
                self.opencti.app_logger.error(
                    "Cannot add Marking-Definition, entity not found"
                )
                return False
            if marking_definition_id in stix_core_relationship["objectMarkingIds"]:
                return True
            else:
                self.opencti.app_logger.info(
                    "Adding Marking-Definition to Stix-Domain-Object",
                    {"id": id, "marking_definition_id": marking_definition_id},
                )
                query = """
                   mutation StixCoreRelationshipAddRelation($id: ID!, $input: StixRefRelationshipAddInput!) {
                       stixCoreRelationshipEdit(id: $id) {
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
                            "toId": marking_definition_id,
                            "relationship_type": "object-marking",
                        },
                    },
                )
                return True
        else:
            self.opencti.app_logger.error(
                "Missing parameters: id and marking_definition_id"
            )
            return False

    def remove_marking_definition(self, **kwargs):
        """Remove a Marking-Definition object from stix_core_relationship.

        :param id: the id of the stix_core_relationship
        :type id: str
        :param marking_definition_id: the id of the Marking-Definition
        :type marking_definition_id: str
        :return: True if successful, False otherwise
        :rtype: bool
        """
        id = kwargs.get("id", None)
        marking_definition_id = kwargs.get("marking_definition_id", None)
        if id is not None and marking_definition_id is not None:
            self.opencti.app_logger.info(
                "Removing Marking-Definition from stix_core_relationship",
                {"id": id, "marking_definition_id": marking_definition_id},
            )
            query = """
               mutation StixCoreRelationshipRemoveRelation($id: ID!, $toId: StixRef!, $relationship_type: String!) {
                   stixCoreRelationshipEdit(id: $id) {
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
                    "toId": marking_definition_id,
                    "relationship_type": "object-marking",
                },
            )
            return True
        else:
            self.opencti.app_logger.error(
                "Missing parameters: id and marking_definition_id"
            )
            return False

    def add_label(self, **kwargs):
        """Add a Label object to stix_core_relationship (labeling).

        :param id: the id of the stix_core_relationship
        :type id: str
        :param label_id: the id of the Label
        :type label_id: str
        :param label_name: (optional) the name of the Label (will create if not exists)
        :type label_name: str
        :return: True if successful, False otherwise
        :rtype: bool
        """
        id = kwargs.get("id", None)
        label_id = kwargs.get("label_id", None)
        label_name = kwargs.get("label_name", None)
        if label_name is not None:
            label = self.opencti.label.read(
                filters={
                    "mode": "and",
                    "filters": [{"key": "value", "values": [label_name]}],
                    "filterGroups": [],
                }
            )
            if label:
                label_id = label["id"]
            else:
                label = self.opencti.label.create(value=label_name)
                label_id = label["id"]
        if id is not None and label_id is not None:
            self.opencti.app_logger.info(
                "Adding label to stix-core-relationship",
                {"label_id": label_id, "id": id},
            )
            query = """
               mutation StixCoreRelationshipAddRelation($id: ID!, $input: StixRefRelationshipAddInput!) {
                   stixCoreRelationshipEdit(id: $id) {
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
                        "toId": label_id,
                        "relationship_type": "object-label",
                    },
                },
            )
            return True
        else:
            self.opencti.app_logger.error("Missing parameters: id and label_id")
            return False

    def remove_label(self, **kwargs):
        """Remove a Label object from stix_core_relationship.

        :param id: the id of the stix_core_relationship
        :type id: str
        :param label_id: the id of the Label
        :type label_id: str
        :param label_name: (optional) the name of the Label
        :type label_name: str
        :return: True if successful, False otherwise
        :rtype: bool
        """
        id = kwargs.get("id", None)
        label_id = kwargs.get("label_id", None)
        label_name = kwargs.get("label_name", None)
        if label_name is not None:
            label = self.opencti.label.read(
                filters={
                    "mode": "and",
                    "filters": [{"key": "value", "values": [label_name]}],
                    "filterGroups": [],
                }
            )
            if label:
                label_id = label["id"]
        if id is not None and label_id is not None:
            self.opencti.app_logger.info(
                "Removing label from stix_core_relationship",
                {"label_id": label_id, "id": id},
            )
            query = """
               mutation StixCoreRelationshipRemoveRelation($id: ID!, $toId: StixRef!, $relationship_type: String!) {
                   stixCoreRelationshipEdit(id: $id) {
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
                    "toId": label_id,
                    "relationship_type": "object-label",
                },
            )
            return True
        else:
            self.opencti.app_logger.error("Missing parameters: id and label_id")
            return False

    def add_external_reference(self, **kwargs):
        """Add an External-Reference object to stix_core_relationship.

        :param id: the id of the stix_core_relationship
        :type id: str
        :param external_reference_id: the id of the External-Reference
        :type external_reference_id: str
        :return: True if successful, False otherwise
        :rtype: bool
        """
        id = kwargs.get("id", None)
        external_reference_id = kwargs.get("external_reference_id", None)
        if id is not None and external_reference_id is not None:
            self.opencti.app_logger.info(
                "Adding External-Reference to stix-core-relationship",
                {"external_reference_id": external_reference_id, "id": id},
            )
            query = """
               mutation StixCoreRelationshipEditRelationAdd($id: ID!, $input: StixRefRelationshipAddInput!) {
                   stixCoreRelationshipEdit(id: $id) {
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
                        "toId": external_reference_id,
                        "relationship_type": "external-reference",
                    },
                },
            )
            return True
        else:
            self.opencti.app_logger.error(
                "Missing parameters: id and external_reference_id"
            )
            return False

    def remove_external_reference(self, **kwargs):
        """Remove an External-Reference object from stix_core_relationship.

        :param id: the id of the stix_core_relationship
        :type id: str
        :param external_reference_id: the id of the External-Reference
        :type external_reference_id: str
        :return: True if successful, False otherwise
        :rtype: bool
        """
        id = kwargs.get("id", None)
        external_reference_id = kwargs.get("external_reference_id", None)
        if id is not None and external_reference_id is not None:
            self.opencti.app_logger.info(
                "Removing External-Reference from stix_core_relationship",
                {"external_reference_id": external_reference_id, "id": id},
            )
            query = """
               mutation StixCoreRelationshipRemoveRelation($id: ID!, $toId: StixRef!, $relationship_type: String!) {
                   stixCoreRelationshipEdit(id: $id) {
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
                    "toId": external_reference_id,
                    "relationship_type": "external-reference",
                },
            )
            return True
        else:
            self.opencti.app_logger.error(
                "Missing parameters: id and external_reference_id"
            )
            return False

    def add_kill_chain_phase(self, **kwargs):
        """Add a Kill-Chain-Phase object to stix_core_relationship object (kill_chain_phases).

        :param id: the id of the stix_core_relationship
        :type id: str
        :param kill_chain_phase_id: the id of the Kill-Chain-Phase
        :type kill_chain_phase_id: str
        :return: True if successful, False otherwise
        :rtype: bool
        """
        id = kwargs.get("id", None)
        kill_chain_phase_id = kwargs.get("kill_chain_phase_id", None)
        if id is not None and kill_chain_phase_id is not None:
            self.opencti.app_logger.info(
                "Adding Kill-Chain-Phase to stix-core-relationship",
                {"kill_chain_phase_id": kill_chain_phase_id, "id": id},
            )
            query = """
               mutation StixCoreRelationshipAddRelation($id: ID!, $input: StixRefRelationshipAddInput!) {
                   stixCoreRelationshipEdit(id: $id) {
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
                        "toId": kill_chain_phase_id,
                        "relationship_type": "kill-chain-phase",
                    },
                },
            )
            return True
        else:
            self.opencti.app_logger.error(
                "[opencti_stix_core_relationship] Missing parameters: id and kill_chain_phase_id",
            )
            return False

    def remove_kill_chain_phase(self, **kwargs):
        """Remove a Kill-Chain-Phase object from stix_core_relationship.

        :param id: the id of the stix_core_relationship
        :type id: str
        :param kill_chain_phase_id: the id of the Kill-Chain-Phase
        :type kill_chain_phase_id: str
        :return: True if successful, False otherwise
        :rtype: bool
        """
        id = kwargs.get("id", None)
        kill_chain_phase_id = kwargs.get("kill_chain_phase_id", None)
        if id is not None and kill_chain_phase_id is not None:
            self.opencti.app_logger.info(
                "Removing Kill-Chain-Phase from stix_core_relationship",
                {"kill_chain_phase_id": kill_chain_phase_id, "id": id},
            )
            query = """
               mutation StixCoreRelationshipRemoveRelation($id: ID!, $toId: StixRef!, $relationship_type: String!) {
                   stixCoreRelationshipEdit(id: $id) {
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
                    "toId": kill_chain_phase_id,
                    "relationship_type": "kill-chain-phase",
                },
            )
            return True
        else:
            self.opencti.app_logger.error(
                "[stix_core_relationship] Missing parameters: id and kill_chain_phase_id"
            )
            return False

    def update_created_by(self, **kwargs):
        """Update the Identity author of a stix_core_relationship (created_by).

        :param id: the id of the stix_core_relationship
        :type id: str
        :param identity_id: the id of the Identity
        :type identity_id: str
        :return: True if successful, False otherwise
        :rtype: bool
        """
        id = kwargs.get("id", None)
        identity_id = kwargs.get("identity_id", None)
        if id is not None:
            self.opencti.app_logger.info(
                "Updating author of stix_core_relationship with Identity",
                {"id": id, "identity_id": identity_id},
            )
            custom_attributes = """
                id
                createdBy {
                    ... on Identity {
                        id
                        standard_id
                        entity_type
                        parent_types
                        name
                        x_opencti_aliases
                        description
                        created
                        modified
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
            """
            stix_domain_object = self.read(id=id, customAttributes=custom_attributes)
            if stix_domain_object["createdBy"] is not None:
                query = """
                    mutation StixCoreRelationshipEdit($id: ID!, $toId: StixRef! $relationship_type: String!) {
                        stixCoreRelationshipEdit(id: $id) {
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
                        "toId": stix_domain_object["createdBy"]["id"],
                        "relationship_type": "created-by",
                    },
                )
            if identity_id is not None:
                # Add the new relation
                query = """
                    mutation StixCoreRelationshipEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
                        stixCoreRelationshipEdit(id: $id) {
                            relationAdd(input: $input) {
                                id
                            }
                        }
                    }
               """
                variables = {
                    "id": id,
                    "input": {
                        "toId": identity_id,
                        "relationship_type": "created-by",
                    },
                }
                self.opencti.query(query, variables)
        else:
            self.opencti.app_logger.error("Missing parameters: id")
            return False

    def import_from_stix2(self, **kwargs):
        """Import a stix_core_relationship from a STIX2 object.

        :param stixRelation: the STIX2 relationship object
        :type stixRelation: dict
        :param extras: extra parameters including created_by_id, object_marking_ids, etc.
        :type extras: dict
        :param update: whether to update if the entity already exists
        :type update: bool
        :param defaultDate: default date to use for start/stop times
        :type defaultDate: str or bool
        :return: stix_core_relationship object
        :rtype: dict or None
        """
        stix_relation = kwargs.get("stixRelation", None)
        extras = kwargs.get("extras", {})
        update = kwargs.get("update", False)
        default_date = kwargs.get("defaultDate", False)
        if stix_relation is not None:
            # Search in extensions
            if "x_opencti_stix_ids" not in stix_relation:
                stix_relation["x_opencti_stix_ids"] = (
                    self.opencti.get_attribute_in_extension("stix_ids", stix_relation)
                )
            if "x_opencti_granted_refs" not in stix_relation:
                stix_relation["x_opencti_granted_refs"] = (
                    self.opencti.get_attribute_in_extension(
                        "granted_refs", stix_relation
                    )
                )
            if "x_opencti_workflow_id" not in stix_relation:
                stix_relation["x_opencti_workflow_id"] = (
                    self.opencti.get_attribute_in_extension(
                        "workflow_id", stix_relation
                    )
                )
            if "x_opencti_modified_at" not in stix_relation:
                stix_relation["x_opencti_modified_at"] = (
                    self.opencti.get_attribute_in_extension(
                        "modified_at", stix_relation
                    )
                )
            if "opencti_upsert_operations" not in stix_relation:
                stix_relation["opencti_upsert_operations"] = (
                    self.opencti.get_attribute_in_extension(
                        "opencti_upsert_operations", stix_relation
                    )
                )

            raw_coverages = (
                stix_relation["coverage"] if "coverage" in stix_relation else []
            )
            coverage_information = list(
                map(
                    lambda cov: {
                        "coverage_name": cov["name"],
                        "coverage_score": cov["score"],
                    },
                    raw_coverages,
                )
            )

            source_ref = stix_relation["source_ref"]
            target_ref = stix_relation["target_ref"]
            return self.create(
                fromId=source_ref,
                toId=target_ref,
                stix_id=stix_relation["id"],
                relationship_type=stix_relation["relationship_type"],
                description=(
                    self.opencti.stix2.convert_markdown(stix_relation["description"])
                    if "description" in stix_relation
                    else None
                ),
                start_time=(
                    stix_relation["start_time"]
                    if "start_time" in stix_relation
                    else default_date
                ),
                stop_time=(
                    stix_relation["stop_time"]
                    if "stop_time" in stix_relation
                    else default_date
                ),
                coverage_information=coverage_information,
                revoked=(
                    stix_relation["revoked"] if "revoked" in stix_relation else None
                ),
                confidence=(
                    stix_relation["confidence"]
                    if "confidence" in stix_relation
                    else None
                ),
                lang=stix_relation["lang"] if "lang" in stix_relation else None,
                created=(
                    stix_relation["created"] if "created" in stix_relation else None
                ),
                modified=(
                    stix_relation["modified"] if "modified" in stix_relation else None
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
                externalReferences=(
                    extras["external_references_ids"]
                    if "external_references_ids" in extras
                    else None
                ),
                killChainPhases=(
                    extras["kill_chain_phases_ids"]
                    if "kill_chain_phases_ids" in extras
                    else None
                ),
                objectOrganization=(
                    stix_relation["x_opencti_granted_refs"]
                    if "x_opencti_granted_refs" in stix_relation
                    else None
                ),
                x_opencti_workflow_id=(
                    stix_relation["x_opencti_workflow_id"]
                    if "x_opencti_workflow_id" in stix_relation
                    else None
                ),
                x_opencti_stix_ids=(
                    stix_relation["x_opencti_stix_ids"]
                    if "x_opencti_stix_ids" in stix_relation
                    else None
                ),
                x_opencti_modified_at=(
                    stix_relation["x_opencti_modified_at"]
                    if "x_opencti_modified_at" in stix_relation
                    else None
                ),
                update=update,
                upsert_operations=(
                    stix_relation["opencti_upsert_operations"]
                    if "opencti_upsert_operations" in stix_relation
                    else None
                ),
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_stix_core_relationship] Missing parameters: stixObject"
            )
            return None

    def organization_share(self, entity_id, organization_ids, sharing_direct_container):
        """Share element to multiple organizations.

        :param entity_id: the stix_core_relationship id
        :type entity_id: str
        :param organization_ids: the organization IDs to share with
        :type organization_ids: list
        :param sharing_direct_container: whether to share direct container
        :type sharing_direct_container: bool
        :return: None
        """
        query = """
                mutation StixCoreRelationshipEdit($id: ID!, $organizationId: [ID!]!, $directContainerSharing: Boolean) {
                    stixCoreRelationshipEdit(id: $id) {
                        restrictionOrganizationAdd(organizationId: $organizationId, directContainerSharing: $directContainerSharing) {
                          id
                        }
                    }
                }
            """
        self.opencti.query(
            query,
            {
                "id": entity_id,
                "organizationId": organization_ids,
                "directContainerSharing": sharing_direct_container,
            },
        )

    def organization_unshare(
        self, entity_id, organization_ids, sharing_direct_container
    ):
        """Unshare element from multiple organizations.

        :param entity_id: the stix_core_relationship id
        :type entity_id: str
        :param organization_ids: the organization IDs to unshare from
        :type organization_ids: list
        :param sharing_direct_container: whether to unshare direct container
        :type sharing_direct_container: bool
        :return: None
        """
        query = """
                mutation StixCoreRelationshipEdit($id: ID!, $organizationId: [ID!]!, $directContainerSharing: Boolean) {
                    stixCoreRelationshipEdit(id: $id) {
                        restrictionOrganizationDelete(organizationId: $organizationId, directContainerSharing: $directContainerSharing) {
                          id
                        }
                    }
                }
            """
        self.opencti.query(
            query,
            {
                "id": entity_id,
                "organizationId": organization_ids,
                "directContainerSharing": sharing_direct_container,
            },
        )

    def remove_from_draft(self, **kwargs):
        """Remove a stix_core_relationship object from draft (revert).

        :param id: the stix_core_relationship id
        :type id: str
        :return: None
        """
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.app_logger.info(
                "Draft remove stix_core_relationship", {"id": id}
            )
            query = """
                    mutation StixCoreRelationshipEditDraftRemove($id: ID!) {
                        stixCoreRelationshipEdit(id: $id) {
                            removeFromDraft
                        }
                    }
                """
            self.opencti.query(query, {"id": id})
        else:
            self.opencti.app_logger.error(
                "[stix_core_relationship] Cannot remove from draft, missing parameters: id"
            )
            return None
