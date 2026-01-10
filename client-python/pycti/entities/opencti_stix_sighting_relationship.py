# coding: utf-8

import datetime
import uuid

from stix2.canonicalization.Canonicalize import canonicalize


class StixSightingRelationship:
    """Main StixSightingRelationship class for OpenCTI

    Manages STIX sighting relationships in the OpenCTI platform.

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type opencti: OpenCTIApiClient
    """

    def __init__(self, opencti):
        """Initialize the StixSightingRelationship instance.

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
            description
            first_seen
            last_seen
            attribute_count
            x_opencti_negative
            created
            modified
            confidence
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
        sighting_of_ref,
        where_sighted_refs,
        first_seen=None,
        last_seen=None,
    ):
        """Generate a STIX ID for a Sighting relationship.

        :param sighting_of_ref: The STIX ID of the entity being sighted
        :type sighting_of_ref: str
        :param where_sighted_refs: The STIX IDs of where the sighting occurred
        :type where_sighted_refs: list
        :param first_seen: (optional) The first seen date
        :type first_seen: str or datetime.datetime or None
        :param last_seen: (optional) The last seen date
        :type last_seen: str or datetime.datetime or None
        :return: STIX ID for the sighting
        :rtype: str
        """
        if isinstance(first_seen, datetime.datetime):
            first_seen = first_seen.isoformat()
        if isinstance(last_seen, datetime.datetime):
            last_seen = last_seen.isoformat()

        if first_seen is not None and last_seen is not None:
            data = {
                "type": "sighting",
                "sighting_of_ref": sighting_of_ref,
                "where_sighted_refs": where_sighted_refs,
                "first_seen": first_seen,
                "last_seen": last_seen,
            }
        elif first_seen is not None:
            data = {
                "type": "sighting",
                "sighting_of_ref": sighting_of_ref,
                "where_sighted_refs": where_sighted_refs,
                "first_seen": first_seen,
            }
        else:
            data = {
                "type": "sighting",
                "sighting_of_ref": sighting_of_ref,
                "where_sighted_refs": where_sighted_refs,
            }
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "sighting--" + id

    @staticmethod
    def generate_id_from_data(data):
        """Generate a STIX ID from sighting data.

        :param data: Dictionary containing sighting_of_ref, where_sighted_refs, and optionally first_seen/last_seen
        :type data: dict
        :return: STIX ID for the sighting
        :rtype: str
        """
        return StixSightingRelationship.generate_id(
            data["sighting_of_ref"],
            data["where_sighted_refs"],
            data.get("first_seen"),
            data.get("last_seen"),
        )

    def list(self, **kwargs):
        """List stix_sighting_relationship objects.

        :param fromOrToId: the id of an entity (source or target)
        :type fromOrToId: str
        :param fromId: the id of the source entity of the relation
        :type fromId: str
        :param fromTypes: filter by source entity types
        :type fromTypes: list
        :param toId: the id of the target entity of the relation
        :type toId: str
        :param toTypes: filter by target entity types
        :type toTypes: list
        :param firstSeenStart: the first_seen date start filter
        :type firstSeenStart: str
        :param firstSeenStop: the first_seen date stop filter
        :type firstSeenStop: str
        :param lastSeenStart: the last_seen date start filter
        :type lastSeenStart: str
        :param lastSeenStop: the last_seen date stop filter
        :type lastSeenStop: str
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
        :return: List of stix_sighting_relationship objects
        :rtype: list
        """
        from_or_to_id = kwargs.get("fromOrToId", None)
        from_id = kwargs.get("fromId", None)
        from_types = kwargs.get("fromTypes", None)
        to_id = kwargs.get("toId", None)
        to_types = kwargs.get("toTypes", None)
        first_seen_start = kwargs.get("firstSeenStart", None)
        first_seen_stop = kwargs.get("firstSeenStop", None)
        last_seen_start = kwargs.get("lastSeenStart", None)
        last_seen_stop = kwargs.get("lastSeenStop", None)
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
            "Listing stix_sighting with {type: stix_sighting}",
            {"from_id": from_id, "to_id": to_id},
        )
        query = (
            """
                query StixSightingRelationships($fromOrToId: String, $fromId: StixRef, $fromTypes: [String], $toId: StixRef, $toTypes: [String], $firstSeenStart: DateTime, $firstSeenStop: DateTime, $lastSeenStart: DateTime, $lastSeenStop: DateTime, $filters: FilterGroup, $first: Int, $after: ID, $orderBy: StixSightingRelationshipsOrdering, $orderMode: OrderingMode, $search: String) {
                    stixSightingRelationships(fromOrToId: $fromOrToId, fromId: $fromId, fromTypes: $fromTypes, toId: $toId, toTypes: $toTypes, firstSeenStart: $firstSeenStart, firstSeenStop: $firstSeenStop, lastSeenStart: $lastSeenStart, lastSeenStop: $lastSeenStop, filters: $filters, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode, search: $search) {
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
                "fromId": from_id,
                "fromTypes": from_types,
                "toId": to_id,
                "toTypes": to_types,
                "firstSeenStart": first_seen_start,
                "firstSeenStop": first_seen_stop,
                "lastSeenStart": last_seen_start,
                "lastSeenStop": last_seen_stop,
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
                result["data"]["stixSightingRelationships"]
            )
            final_data = final_data + data
            while result["data"]["stixSightingRelationships"]["pageInfo"][
                "hasNextPage"
            ]:
                after = result["data"]["stixSightingRelationships"]["pageInfo"][
                    "endCursor"
                ]
                self.opencti.app_logger.debug(
                    "Listing StixSightingRelationships", {"after": after}
                )
                result = self.opencti.query(
                    query,
                    {
                        "fromOrToId": from_or_to_id,
                        "fromId": from_id,
                        "fromTypes": from_types,
                        "toId": to_id,
                        "toTypes": to_types,
                        "firstSeenStart": first_seen_start,
                        "firstSeenStop": first_seen_stop,
                        "lastSeenStart": last_seen_start,
                        "lastSeenStop": last_seen_stop,
                        "filters": filters,
                        "first": first,
                        "after": after,
                        "orderBy": order_by,
                        "orderMode": order_mode,
                        "search": search,
                    },
                )
                data = self.opencti.process_multiple(
                    result["data"]["stixSightingRelationships"]
                )
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["stixSightingRelationships"], with_pagination
            )

    def read(self, **kwargs):
        """Read a stix_sighting_relationship object.

        :param id: the id of the stix_sighting_relationship
        :type id: str
        :param fromOrToId: the id of an entity (source or target)
        :type fromOrToId: str
        :param fromId: the id of the source entity of the relation
        :type fromId: str
        :param toId: the id of the target entity of the relation
        :type toId: str
        :param firstSeenStart: the first_seen date start filter
        :type firstSeenStart: str
        :param firstSeenStop: the first_seen date stop filter
        :type firstSeenStop: str
        :param lastSeenStart: the last_seen date start filter
        :type lastSeenStart: str
        :param lastSeenStop: the last_seen date stop filter
        :type lastSeenStop: str
        :param customAttributes: custom attributes to return
        :type customAttributes: str
        :param filters: filters to apply
        :type filters: dict
        :return: stix_sighting_relationship object
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        from_or_to_id = kwargs.get("fromOrToId", None)
        from_id = kwargs.get("fromId", None)
        to_id = kwargs.get("toId", None)
        first_seen_start = kwargs.get("firstSeenStart", None)
        first_seen_stop = kwargs.get("firstSeenStop", None)
        last_seen_start = kwargs.get("lastSeenStart", None)
        last_seen_stop = kwargs.get("lastSeenStop", None)
        custom_attributes = kwargs.get("customAttributes", None)
        filters = kwargs.get("filters", None)
        if id is not None:
            self.opencti.app_logger.info("Reading stix_sighting", {"id": id})
            query = (
                """
                    query StixSightingRelationship($id: String!) {
                        stixSightingRelationship(id: $id) {
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
                result["data"]["stixSightingRelationship"]
            )
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        elif from_id is not None and to_id is not None:
            result = self.list(
                fromOrToId=from_or_to_id,
                fromId=from_id,
                toId=to_id,
                firstSeenStart=first_seen_start,
                firstSeenStop=first_seen_stop,
                lastSeenStart=last_seen_start,
                lastSeenStop=last_seen_stop,
            )
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.app_logger.error("Missing parameters: id or from_id and to_id")
            return None

    def create(self, **kwargs):
        """Create a stix_sighting_relationship object.

        :param fromId: the id of the source entity
        :type fromId: str
        :param toId: the id of the target entity
        :type toId: str
        :param stix_id: (optional) the STIX ID
        :type stix_id: str
        :param description: (optional) description
        :type description: str
        :param first_seen: (optional) first seen date
        :type first_seen: str
        :param last_seen: (optional) last seen date
        :type last_seen: str
        :param count: (optional) sighting count
        :type count: int
        :param x_opencti_negative: (optional) whether this is a negative sighting
        :type x_opencti_negative: bool
        :param created: (optional) creation date
        :type created: str
        :param modified: (optional) modification date
        :type modified: str
        :param confidence: (optional) confidence level (0-100)
        :type confidence: int
        :param createdBy: (optional) the author ID
        :type createdBy: str
        :param objectMarking: (optional) list of marking definition IDs
        :type objectMarking: list
        :param objectLabel: (optional) list of label IDs
        :type objectLabel: list
        :param externalReferences: (optional) list of external reference IDs
        :type externalReferences: list
        :param x_opencti_stix_ids: (optional) list of additional STIX IDs
        :type x_opencti_stix_ids: list
        :param x_opencti_workflow_id: (optional) workflow ID
        :type x_opencti_workflow_id: str
        :param x_opencti_modified_at: (optional) custom modification date
        :type x_opencti_modified_at: str
        :param objectOrganization: (optional) list of organization IDs
        :type objectOrganization: list
        :param update: (optional) whether to update if exists (default: False)
        :type update: bool
        :return: stix_sighting_relationship object
        :rtype: dict or None
        """
        from_id = kwargs.get("fromId", None)
        to_id = kwargs.get("toId", None)
        stix_id = kwargs.get("stix_id", None)
        description = kwargs.get("description", None)
        first_seen = kwargs.get("first_seen", None)
        last_seen = kwargs.get("last_seen", None)
        count = kwargs.get("count", None)
        x_opencti_negative = kwargs.get("x_opencti_negative", False)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        confidence = kwargs.get("confidence", None)
        created_by = kwargs.get("createdBy", None)
        object_marking = kwargs.get("objectMarking", None)
        object_label = kwargs.get("objectLabel", None)
        external_references = kwargs.get("externalReferences", None)
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        x_opencti_workflow_id = kwargs.get("x_opencti_workflow_id", None)
        x_opencti_modified_at = kwargs.get("x_opencti_modified_at", None)
        granted_refs = kwargs.get("objectOrganization", None)
        update = kwargs.get("update", False)

        self.opencti.app_logger.info(
            "Creating stix_sighting", {"from_id": from_id, "to_id": to_id}
        )
        query = """
                mutation StixSightingRelationshipAdd($input: StixSightingRelationshipAddInput!) {
                    stixSightingRelationshipAdd(input: $input) {
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
                    "description": description,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "attribute_count": count,
                    "x_opencti_negative": x_opencti_negative,
                    "created": created,
                    "modified": modified,
                    "confidence": confidence,
                    "createdBy": created_by,
                    "objectMarking": object_marking,
                    "objectLabel": object_label,
                    "externalReferences": external_references,
                    "x_opencti_stix_ids": x_opencti_stix_ids,
                    "x_opencti_workflow_id": x_opencti_workflow_id,
                    "x_opencti_modified_at": x_opencti_modified_at,
                    "objectOrganization": granted_refs,
                    "update": update,
                }
            },
        )
        return self.opencti.process_multiple_fields(
            result["data"]["stixSightingRelationshipAdd"]
        )

    def update_field(self, **kwargs):
        """Update a stix_sighting_relationship object field.

        :param id: the stix_sighting_relationship id
        :type id: str
        :param input: the input of the field
        :type input: list
        :return: The updated stix_sighting_relationship object
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        input = kwargs.get("input", None)
        if id is not None and input is not None:
            self.opencti.app_logger.info("Updating stix_sighting", {"id": id})
            query = """
                    mutation StixSightingRelationshipEdit($id: ID!, $input: [EditInput]!) {
                        stixSightingRelationshipEdit(id: $id) {
                            fieldPatch(input: $input) {
                                id
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
                result["data"]["stixSightingRelationshipEdit"]["fieldPatch"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_stix_sighting] Missing parameters: id and input"
            )
            return None

    def add_marking_definition(self, **kwargs):
        """Add a Marking-Definition object to stix_sighting_relationship object (object_marking_refs).

        :param id: the id of the stix_sighting_relationship
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
                    "Adding Marking-Definition to stix_sighting_relationship",
                    {"marking_definition_id": marking_definition_id, "id": id},
                )
                query = """
                   mutation StixSightingRelationshipEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
                       stixSightingRelationshipEdit(id: $id) {
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
        """Remove a Marking-Definition object from stix_sighting_relationship.

        :param id: the id of the stix_sighting_relationship
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
                "Removing Marking-Definition from stix_sighting_relationship",
                {"marking_definition_id": marking_definition_id, "id": id},
            )
            query = """
               mutation StixSightingRelationshipEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
                   stixSightingRelationshipEdit(id: $id) {
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

    def update_created_by(self, **kwargs):
        """Update the Identity author of a stix_sighting_relationship object (created_by).

        :param id: the id of the stix_sighting_relationship
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
                "Updating author of stix_sighting_relationship with Identity",
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
                    mutation StixSightingRelationshipEdit($id: ID!, $toId: StixRef! $relationship_type: String!) {
                        stixSightingRelationshipEdit(id: $id) {
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
                    mutation StixSightingRelationshipEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
                        stixSightingRelationshipEdit(id: $id) {
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

    def organization_share(self, entity_id, organization_ids, sharing_direct_container):
        """Share element to multiple organizations.

        :param entity_id: the stix_sighting_relationship id
        :type entity_id: str
        :param organization_ids: the organization IDs to share with
        :type organization_ids: list
        :param sharing_direct_container: whether to share direct container
        :type sharing_direct_container: bool
        :return: None
        """
        query = """
                mutation StixSightingRelationshipEdit($id: ID!, $organizationId: [ID!]!, $directContainerSharing: Boolean) {
                    stixSightingRelationshipEdit(id: $id) {
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

        :param entity_id: the stix_sighting_relationship id
        :type entity_id: str
        :param organization_ids: the organization IDs to unshare from
        :type organization_ids: list
        :param sharing_direct_container: whether to unshare direct container
        :type sharing_direct_container: bool
        :return: None
        """
        query = """
                mutation StixSightingRelationshipEdit($id: ID!, $organizationId: [ID!]!, $directContainerSharing: Boolean) {
                    stixSightingRelationshipEdit(id: $id) {
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
        """Remove a stix_sighting_relationship object from draft (revert).

        :param id: the stix_sighting_relationship id
        :type id: str
        :return: None
        """
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.app_logger.info("Draft remove stix_sighting", {"id": id})
            query = """
                    mutation StixSightingRelationshipEditDraftRemove($id: ID!) {
                        stixSightingRelationshipEdit(id: $id) {
                            removeFromDraft
                        }
                    }
                """
            self.opencti.query(query, {"id": id})
        else:
            self.opencti.app_logger.error(
                "[stix_sighting] Cannot remove from draft, missing parameters: id"
            )
            return None

    def delete(self, **kwargs):
        """Delete a stix_sighting_relationship.

        :param id: the stix_sighting_relationship id
        :type id: str
        :return: None
        """
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.app_logger.info("Deleting stix_sighting", {"id": id})
            query = """
                mutation StixSightingRelationshipEdit($id: ID!) {
                    stixSightingRelationshipEdit(id: $id) {
                        delete
                    }
                }
            """
            self.opencti.query(query, {"id": id})
        else:
            self.opencti.app_logger.error(
                "[opencti_stix_sighting] Missing parameters: id"
            )
            return None
