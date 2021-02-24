# coding: utf-8


class StixCyberObservableRelationship:
    def __init__(self, opencti):
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
            start_time
            stop_time
            revoked
            confidence
            lang
            created
            modified
            from {
                id
                standard_id
                entity_type
                parent_types
                observable_value
            }
            to {
                id
                standard_id
                entity_type
                parent_types
                observable_value
            }
                        createdBy {
                ... on Identity {
                    id
                    standard_id
                    entity_type
                    parent_types
                    spec_version
                    name
                    description
                    roles
                    contact_information
                    x_opencti_aliases
                    created
                    modified
                    objectLabel {
                        edges {
                            node {
                                id
                                value
                                color
                            }
                        }
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
        """

    """
        List stix_observable_relationship objects

        :param fromId: the id of the source entity of the relation
        :param toId: the id of the target entity of the relation
        :param relationship_type: the relation type
        :param startTimeStart: the first_seen date start filter
        :param startTimeStop: the first_seen date stop filter
        :param stopTimeStart: the last_seen date start filter
        :param stopTimeStop: the last_seen date stop filter
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of stix_observable_relationship objects
    """

    def list(self, **kwargs):
        from_id = kwargs.get("fromId", None)
        from_types = kwargs.get("fromTypes", None)
        to_id = kwargs.get("toId", None)
        to_types = kwargs.get("toTypes", None)
        relationship_type = kwargs.get("relationship_type", None)
        first_seen_start = kwargs.get("startTimeStart", None)
        first_seen_stop = kwargs.get("startTimeStop", None)
        last_seen_start = kwargs.get("stopTimeStart", None)
        last_seen_stop = kwargs.get("stopTimeStop", None)
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
            "Listing stix_observable_relationships with {type: "
            + str(relationship_type)
            + ", from_id: "
            + str(from_id)
            + ", to_id: "
            + str(to_id)
            + "}",
        )
        query = (
            """
            query StixCyberObservableRelationships($fromId: String, $fromTypes: [String], $toId: String, $toTypes: [String], $relationship_type: String, $startTimeStart: DateTime, $startTimeStop: DateTime, $stopTimeStart: DateTime, $stopTimeStop: DateTime, $first: Int, $after: ID, $orderBy: StixCyberObservableRelationshipsOrdering, $orderMode: OrderingMode) {
                StixCyberObservableRelationships(fromId: $fromId, fromTypes: $fromTypes, toId: $toId, toTypes: $toTypes, relationship_type: $relationship_type, startTimeStart: $startTimeStart, startTimeStop: $startTimeStop, stopTimeStart: $stopTimeStart, stopTimeStop: $stopTimeStop, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
                "Start": first_seen_start,
                "startTimeStop": first_seen_stop,
                "stopTimeStart": last_seen_start,
                "stopTimeStop": last_seen_stop,
                "first": first,
                "after": after,
                "orderBy": order_by,
                "orderMode": order_mode,
            },
        )
        return self.opencti.process_multiple(
            result["data"]["StixCyberObservableRelationships"], with_pagination
        )

    """
        Read a stix_observable_relationship object

        :param id: the id of the stix_observable_relationship
        :param stix_id: the STIX id of the stix_observable_relationship
        :param fromId: the id of the source entity of the relation
        :param toId: the id of the target entity of the relation
        :param relationship_type: the relation type
        :param startTimeStart: the first_seen date start filter
        :param startTimeStop: the first_seen date stop filter
        :param stopTimeStart: the last_seen date start filter
        :param stopTimeStop: the last_seen date stop filter
        :return stix_observable_relationship object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        from_id = kwargs.get("fromId", None)
        to_id = kwargs.get("toId", None)
        relationship_type = kwargs.get("relationship_type", None)
        first_seen_start = kwargs.get("startTimeStart", None)
        first_seen_stop = kwargs.get("startTimeStop", None)
        last_seen_start = kwargs.get("stopTimeStart", None)
        last_seen_stop = kwargs.get("stopTimeStop", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.log(
                "info", "Reading stix_observable_relationship {" + id + "}."
            )
            query = (
                """
                query StixCyberObservableRelationship($id: String!) {
                    StixCyberObservableRelationship(id: $id) {
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
                result["data"]["StixCyberObservableRelationship"]
            )
        else:
            result = self.list(
                fromId=from_id,
                toId=to_id,
                relationship_type=relationship_type,
                startTimeStart=first_seen_start,
                startTimeStop=first_seen_stop,
                stopTimeStart=last_seen_start,
                stopTimeStop=last_seen_stop,
            )
            if len(result) > 0:
                return result[0]
            else:
                return None

    """
        Create a stix_observable_relationship object

        :param from_id: id of the source entity
        :return stix_observable_relationship object
    """

    def create(self, **kwargs):
        from_id = kwargs.get("fromId", None)
        from_role = kwargs.get("fromRole", None)
        to_id = kwargs.get("toId", None)
        to_role = kwargs.get("toRole", None)
        relationship_type = kwargs.get("relationship_type", None)
        description = kwargs.get("description", None)
        start_time = kwargs.get("start_time", None)
        stop_time = kwargs.get("stop_time", None)
        stix_id = kwargs.get("stix_id", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by = kwargs.get("createdBy", None)
        object_marking = kwargs.get("objectMarking", None)
        update = kwargs.get("update", False)

        self.opencti.log(
            "info",
            "Creating stix_observable_relationship {"
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
                mutation StixCyberObservableRelationshipAdd($input: StixCyberObservableStixMetaRelationshipAddInput!) {
                    StixCyberObservableRelationshipAdd(input: $input) {
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
                    "relationship_type": relationship_type,
                    "description": description,
                    "start_time": start_time,
                    "stop_time": stop_time,
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
            result["data"]["StixCyberObservableRelationshipAdd"]
        )

    """
        Update a stix_observable_relationship object field

        :param id: the stix_observable_relationship id
        :param key: the key of the field
        :param value: the value of the field
        :return The updated stix_observable_relationship object
    """

    def update_field(self, **kwargs):
        id = kwargs.get("id", None)
        key = kwargs.get("key", None)
        value = kwargs.get("value", None)
        if id is not None and key is not None and value is not None:
            self.opencti.log(
                "info",
                "Updating stix_observable_relationship {"
                + id
                + "} field {"
                + key
                + "}.",
            )
            query = (
                """
                mutation StixCyberObservableRelationshipEdit($id: ID!, $input: EditInput!) {
                    StixCyberObservableRelationshipEdit(id: $id) {
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
                result["data"]["StixCyberObservableRelationshipEdit"]["fieldPatch"]
            )
        else:
            self.opencti.log("error", "Missing parameters: id and key and value")
            return None
