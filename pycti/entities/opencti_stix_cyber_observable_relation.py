# coding: utf-8


class StixCyberObservableRelation:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            stix_id
            entity_type
            relationship_type
            description
            weight
            role_played
            first_seen
            last_seen
            created
            modified
            created_at
            updated_at
            from {
                id
                stix_id
                entity_type
                observable_value
            }
            to {
                id
                stix_id
                entity_type
                observable_value
            }
            createdBy {
                node {
                    id
                    entity_type
                    stix_id
                    stix_label
                    name
                    description
                    roles
                    contact_information
                    x_opencti_aliases
                    created
                    modified
                }
                relation {
                    id
                }
            }
            markingDefinitions {
                edges {
                    node {
                        id
                        entity_type
                        stix_id
                        definition_type
                        definition
                        level
                        color
                        created
                        modified
                    }
                    relation {
                       id
                    }
                }
            }
            externalReferences {
                edges {
                    node {
                        id
                        entity_type
                        stix_id
                        source_name
                        description
                        url
                        hash
                        external_id
                        created
                        modified
                    }
                    relation {
                        id
                    }
                }
            }
        """

    """
        List stix_observable_relation objects

        :param fromId: the id of the source entity of the relation
        :param toId: the id of the target entity of the relation
        :param relationship_type: the relation type
        :param firstSeenStart: the first_seen date start filter
        :param firstSeenStop: the first_seen date stop filter
        :param lastSeenStart: the last_seen date start filter
        :param lastSeenStop: the last_seen date stop filter
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of stix_observable_relation objects
    """

    def list(self, **kwargs):
        from_id = kwargs.get("fromId", None)
        from_types = kwargs.get("fromTypes", None)
        to_id = kwargs.get("toId", None)
        to_types = kwargs.get("toTypes", None)
        relationship_type = kwargs.get("relationship_type", None)
        first_seen_start = kwargs.get("firstSeenStart", None)
        first_seen_stop = kwargs.get("firstSeenStop", None)
        last_seen_start = kwargs.get("lastSeenStart", None)
        last_seen_stop = kwargs.get("lastSeenStop", None)
        first = kwargs.get("first", 500)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)
        if get_all:
            first = 500

        self.opencti.log(
            "info",
            "Listing stix_observable_relations with {type: "
            + str(relationship_type)
            + ", from_id: "
            + str(from_id)
            + ", to_id: "
            + str(to_id)
            + "}",
        )
        query = (
            """
            query StixCyberObservableRelations($fromId: String, $fromTypes: [String], $toId: String, $toTypes: [String], $relationship_type: String, $firstSeenStart: DateTime, $firstSeenStop: DateTime, $lastSeenStart: DateTime, $lastSeenStop: DateTime, $first: Int, $after: ID, $orderBy: StixCyberObservableRelationsOrdering, $orderMode: OrderingMode) {
                StixCyberObservableRelations(fromId: $fromId, fromTypes: $fromTypes, toId: $toId, toTypes: $toTypes, relationship_type: $relationship_type, firstSeenStart: $firstSeenStart, firstSeenStop: $firstSeenStop, lastSeenStart: $lastSeenStart, lastSeenStop: $lastSeenStop, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
                    edges {
                        node {
                            """
            + self.properties
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
                "fromId": from_id,
                "fromTypes": from_types,
                "toId": to_id,
                "toTypes": to_types,
                "relationship_type": relationship_type,
                "firstSeenStart": first_seen_start,
                "firstSeenStop": first_seen_stop,
                "lastSeenStart": last_seen_start,
                "lastSeenStop": last_seen_stop,
                "first": first,
                "after": after,
                "orderBy": order_by,
                "orderMode": order_mode,
            },
        )
        return self.opencti.process_multiple(
            result["data"]["StixCyberObservableRelations"], with_pagination
        )

    """
        Read a stix_observable_relation object

        :param id: the id of the stix_observable_relation
        :param stix_id: the STIX id of the stix_observable_relation
        :param fromId: the id of the source entity of the relation
        :param toId: the id of the target entity of the relation
        :param relationship_type: the relation type
        :param firstSeenStart: the first_seen date start filter
        :param firstSeenStop: the first_seen date stop filter
        :param lastSeenStart: the last_seen date start filter
        :param lastSeenStop: the last_seen date stop filter
        :return stix_observable_relation object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        from_id = kwargs.get("fromId", None)
        to_id = kwargs.get("toId", None)
        relationship_type = kwargs.get("relationship_type", None)
        first_seen_start = kwargs.get("firstSeenStart", None)
        first_seen_stop = kwargs.get("firstSeenStop", None)
        last_seen_start = kwargs.get("lastSeenStart", None)
        last_seen_stop = kwargs.get("lastSeenStop", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.log("info", "Reading stix_observable_relation {" + id + "}.")
            query = (
                """
                query StixCyberObservableRelation($id: String!) {
                    StixCyberObservableRelation(id: $id) {
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
                result["data"]["StixCyberObservableRelation"]
            )
        else:
            result = self.list(
                fromId=from_id,
                toId=to_id,
                relationship_type=relationship_type,
                firstSeenStart=first_seen_start,
                firstSeenStop=first_seen_stop,
                lastSeenStart=last_seen_start,
                lastSeenStop=last_seen_stop,
            )
            if len(result) > 0:
                return result[0]
            else:
                return None

    """
        Create a stix_observable_relation object

        :param from_id: id of the source entity
        :return stix_observable_relation object
    """

    def create(self, **kwargs):
        from_id = kwargs.get("fromId", None)
        from_role = kwargs.get("fromRole", None)
        to_id = kwargs.get("toId", None)
        to_role = kwargs.get("toRole", None)
        relationship_type = kwargs.get("relationship_type", None)
        description = kwargs.get("description", None)
        role_played = kwargs.get("role_played", None)
        first_seen = kwargs.get("first_seen", None)
        last_seen = kwargs.get("last_seen", None)
        weight = kwargs.get("weight", None)
        id = kwargs.get("id", None)
        stix_id = kwargs.get("stix_id", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by = kwargs.get("createdBy", None)
        object_marking = kwargs.get("objectMarking", None)
        update = kwargs.get("update", False)

        self.opencti.log(
            "info",
            "Creating stix_observable_relation {"
            + from_role
            + ": "
            + from_id
            + ", "
            + to_role
            + ": "
            + to_id
            + "}.",
        )
        query = """
                mutation StixCyberObservableRelationAdd($input: StixCyberObservableStixMetaRelationshipAddInput!) {
                    StixCyberObservableRelationAdd(input: $input) {
                        id
                        stix_id
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
                    "fromRole": from_role,
                    "toId": to_id,
                    "toRole": to_role,
                    "relationship_type": relationship_type,
                    "description": description,
                    "role_played": role_played,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "weight": weight,
                    "internal_id_key": id,
                    "stix_id": stix_id,
                    "created": created,
                    "modified": modified,
                    "createdBy": created_by,
                    "objectMarking": object_marking,
                    "update": update,
                }
            },
        )
        return self.opencti.process_multiple_fields(
            result["data"]["StixCyberObservableRelationAdd"]
        )

    """
        Update a stix_observable_relation object field

        :param id: the stix_observable_relation id
        :param key: the key of the field
        :param value: the value of the field
        :return The updated stix_observable_relation object
    """

    def update_field(self, **kwargs):
        id = kwargs.get("id", None)
        key = kwargs.get("key", None)
        value = kwargs.get("value", None)
        if id is not None and key is not None and value is not None:
            self.opencti.log(
                "info",
                "Updating stix_observable_relation {" + id + "} field {" + key + "}.",
            )
            query = (
                """
                mutation StixCyberObservableRelationEdit($id: ID!, $input: EditInput!) {
                    StixCyberObservableRelationEdit(id: $id) {
                        fieldPatch(input: $input) {
                            """
                + self.properties
                + """
                        }
                    }
                }
            """
            )
            result = self.opencti.query(
                query, {"id": id, "input": {"key": key, "value": value}}
            )
            return self.opencti.process_multiple_fields(
                result["data"]["StixCyberObservableRelationEdit"]["fieldPatch"]
            )
        else:
            self.opencti.log("error", "Missing parameters: id and key and value")
            return None
