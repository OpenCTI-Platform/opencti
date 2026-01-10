class StixNestedRefRelationship:
    """Main StixNestedRefRelationship class for OpenCTI

    Manages nested reference relationships in the OpenCTI platform.

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type opencti: OpenCTIApiClient
    """

    def __init__(self, opencti):
        """Initialize the StixNestedRefRelationship instance.

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
            start_time
            stop_time
            from {
                ... on StixObject {
                    id
                    standard_id
                    entity_type
                    parent_types
                }
                ... on StixCoreRelationship {
                    id
                    standard_id
                    entity_type
                    parent_types
                }
                ... on StixSightingRelationship {
                    id
                    standard_id
                    entity_type
                    parent_types
                }
                ... on StixCyberObservable {
                    observable_value
                }
            }
            to {
                ... on StixObject {
                    id
                    standard_id
                    entity_type
                    parent_types
                }
                ... on StixCoreRelationship {
                    id
                    standard_id
                    entity_type
                    parent_types
                }
                ... on StixSightingRelationship {
                    id
                    standard_id
                    entity_type
                    parent_types
                }
                ... on StixCyberObservable {
                    observable_value
                }
            }
        """

    def list(self, **kwargs):
        """List stix nested ref relationship objects.

        :param fromOrToId: the id of either the source or target entity
        :type fromOrToId: str
        :param fromId: the id of the source entity of the relation
        :type fromId: str
        :param fromTypes: the types of the source entities
        :type fromTypes: list
        :param toId: the id of the target entity of the relation
        :type toId: str
        :param toTypes: the types of the target entities
        :type toTypes: list
        :param relationship_type: the relation type
        :type relationship_type: str
        :param startTimeStart: the first_seen date start filter
        :type startTimeStart: str
        :param startTimeStop: the first_seen date stop filter
        :type startTimeStop: str
        :param stopTimeStart: the last_seen date start filter
        :type stopTimeStart: str
        :param stopTimeStop: the last_seen date stop filter
        :type stopTimeStop: str
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :type first: int
        :param after: ID of the first row for pagination
        :type after: str
        :return: List of stix nested ref relationship objects
        :rtype: list
        """
        from_or_to_id = kwargs.get("fromOrToId", None)
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
        first = kwargs.get("first", 500)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        custom_attributes = kwargs.get("customAttributes", None)
        with_pagination = kwargs.get("withPagination", False)

        self.opencti.app_logger.info(
            "Listing stix_nested_ref_relationships",
            {
                "relationship_type": relationship_type,
                "from_id": from_id,
                "to_id": to_id,
            },
        )
        query = (
            """
            query StixNestedRefRelationships($fromOrToId: String, $fromId: StixRef, $fromTypes: [String], $toId: StixRef, $toTypes: [String], $relationship_type: [String], $startTimeStart: DateTime, $startTimeStop: DateTime, $stopTimeStart: DateTime, $stopTimeStop: DateTime, $filters: FilterGroup, $first: Int, $after: ID, $orderBy: StixRefRelationshipsOrdering, $orderMode: OrderingMode) {
                stixNestedRefRelationships(fromOrToId: $fromOrToId, fromId: $fromId, fromTypes: $fromTypes, toId: $toId, toTypes: $toTypes, relationship_type: $relationship_type, startTimeStart: $startTimeStart, startTimeStop: $startTimeStop, stopTimeStart: $stopTimeStart, stopTimeStop: $stopTimeStop, filters: $filters, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
            },
        )
        return self.opencti.process_multiple(
            result["data"]["stixNestedRefRelationships"], with_pagination
        )

    def read(self, **kwargs):
        """Read a stix nested ref relationship object.

        :param id: the id of the stix nested ref relationship
        :type id: str
        :param fromOrToId: the id of either the source or target entity
        :type fromOrToId: str
        :param fromId: the id of the source entity of the relation
        :type fromId: str
        :param toId: the id of the target entity of the relation
        :type toId: str
        :param relationship_type: the relation type
        :type relationship_type: str
        :param startTimeStart: the first_seen date start filter
        :type startTimeStart: str
        :param startTimeStop: the first_seen date stop filter
        :type startTimeStop: str
        :param stopTimeStart: the last_seen date start filter
        :type stopTimeStart: str
        :param stopTimeStop: the last_seen date stop filter
        :type stopTimeStop: str
        :param customAttributes: custom attributes to return
        :type customAttributes: str
        :param filters: the filters to apply
        :type filters: dict
        :return: stix nested ref relationship object
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
        custom_attributes = kwargs.get("customAttributes", None)
        filters = kwargs.get("filters", None)
        if id is not None:
            self.opencti.app_logger.info(
                "Reading stix_observable_relationship", {"id": id}
            )
            query = (
                """
                query StixRefRelationship($id: String!) {
                    stixRefRelationship(id: $id) {
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
                result["data"]["stixRefRelationship"]
            )
        elif filters is not None:
            result = self.list(filters=filters, customAttributes=custom_attributes)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
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

    def create(self, **kwargs):
        """Create a stix nested ref relationship object.

        :param fromId: the id of the source entity
        :type fromId: str
        :param toId: the id of the target entity
        :type toId: str
        :param relationship_type: the type of the relationship
        :type relationship_type: str
        :param start_time: (optional) the start time of the relationship
        :type start_time: str
        :param stop_time: (optional) the stop time of the relationship
        :type stop_time: str
        :param stix_id: (optional) the STIX ID
        :type stix_id: str
        :param created: (optional) creation date
        :type created: str
        :param modified: (optional) modification date
        :type modified: str
        :param createdBy: (optional) the creator ID
        :type createdBy: str
        :param objectMarking: (optional) list of marking definition IDs
        :type objectMarking: list
        :param x_opencti_stix_ids: (optional) list of additional STIX IDs
        :type x_opencti_stix_ids: list
        :param update: (optional) whether to update if exists
        :type update: bool
        :return: stix nested ref relationship object
        :rtype: dict
        """
        from_id = kwargs.get("fromId", None)
        to_id = kwargs.get("toId", None)
        relationship_type = kwargs.get("relationship_type", None)
        start_time = kwargs.get("start_time", None)
        stop_time = kwargs.get("stop_time", None)
        stix_id = kwargs.get("stix_id", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by = kwargs.get("createdBy", None)
        object_marking = kwargs.get("objectMarking", None)
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        update = kwargs.get("update", False)

        if relationship_type == "resolves-to":
            relationship_type = "obs_resolves-to"
        elif relationship_type == "belongs-to":
            relationship_type = "obs_belongs-to"
        elif relationship_type == "content":
            relationship_type = "obs_content"

        self.opencti.app_logger.info(
            "Creating stix_observable_relationship",
            {
                "relationship_type": relationship_type,
                "from_id": from_id,
                "to_id": to_id,
            },
        )
        query = """
                mutation StixRefRelationshipAdd($input: StixRefRelationshipAddInput!) {
                    stixRefRelationshipAdd(input: $input) {
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
                    "start_time": start_time,
                    "stop_time": stop_time,
                    "stix_id": stix_id,
                    "created": created,
                    "modified": modified,
                    "createdBy": created_by,
                    "objectMarking": object_marking,
                    "x_opencti_stix_ids": x_opencti_stix_ids,
                    "update": update,
                }
            },
        )
        return self.opencti.process_multiple_fields(
            result["data"]["stixRefRelationshipAdd"]
        )

    def update_field(self, **kwargs):
        """Update a stix nested ref relationship object field.

        :param id: the stix nested ref relationship id
        :type id: str
        :param input: the input of the field to update
        :type input: list
        :return: The updated stix nested ref relationship object
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        input = kwargs.get("input", None)
        if id is not None and input is not None:
            self.opencti.app_logger.info(
                "Updating stix_observable_relationship", {"id": id}
            )
            query = (
                """
                mutation StixRefRelationshipEdit($id: ID!, $input: [EditInput]!) {
                    stixRefRelationshipEdit(id: $id) {
                        fieldPatch(input: $input) {
                            """
                + self.properties
                + """
                        }
                    }
                }
            """
            )
            result = self.opencti.query(query, {"id": id, "input": input})
            return self.opencti.process_multiple_fields(
                result["data"]["stixRefRelationshipEdit"]["fieldPatch"]
            )
        else:
            self.opencti.app_logger.error("Missing parameters: id and key and value")
            return None
