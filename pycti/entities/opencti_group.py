from typing import Dict, List, Optional


class Group:
    """Representation of a Group in OpenCTI

    Groups have members and also have assigned roles. Roles attached to a group
    determine what members of the group have permissions to do according to
    the capabilities the role has.

    Additionally, groups have a confidence level which informs the effective
    confidence of members of the group.

    Groups also have permissions on Marking Definitions. Assigned marking
    definitions allow users to apply their capabilities on objects with those
    definitions. Additionally, there are default markings added to all objects
    created by members of a group, and max shareable definitions which
    determine which objects users can export from the platform to share.

    See the properties attribute to understand what properties are fetched by
    default from GraphQL queries.
    """

    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            standard_id
            name
            description
            entity_type
            parent_types
            created_at
            updated_at
            default_assignation
            no_creators
            restrict_delete
            default_hidden_types
            auto_new_marking
            allowed_marking {
                id, standard_id, definition_type, definition
            }
            default_marking {
                entity_type
                values {
                    id, standard_id, definition_type, definition
                }
            }
            not_shareable_marking_types
            max_shareable_marking {
                id, standard_id, definition_type, definition
            }
            group_confidence_level {
                max_confidence
                overrides {
                    entity_type
                    max_confidence
                }
            }
            roles {
                edges {
                    node {
                        id, name
                        capabilities {
                            id, name
                        }
                    }
                }
            }
            members {
                edges {
                    node {
                        id, individual_id, user_email, name
                    }
                }
            }
        """

    def list(self, **kwargs) -> List[Dict]:
        """Lists groups based on a number of filters.

        :param first:  Retrieve this number of results. If 0
            then fetches all results, defaults to 0.
        :type first: int, optional
        :param after:  ID of the group to fetch results
            after in the list of all results, defaults to None.
        :type after: str, optional
        :param orderBy:  Field by which to order results.
            Must be one of name, default_assignation, no_creators,
            restrict_delete, auto_new_marking, created_at, updated_at,
            group_confidence_level, and _score, defaults to "name".
        :type orderBy: str, optional
        :param orderMode:  Direction of ordering. Must be
            one of "asc" or "desc", defaults to "asc".
        :type orderMode: str, optional
        :param search:  String to search groups for, defaults to None.
        :type search: str, optional
        :param filters:  OpenCTI API FilterGroup object.
            This is an advanced parameter. To learn more please search for
            the FilterGroup object in the OpenCTI GraphQL Playground, defaults
            to {}.
        :type filters: dict, optional
        :param customAttributes: Custom attributes to fetch from the GraphQL
            query
        :type customAttributes: str, optional
        :param getAll: Defaults to False. Whether or not to get all results
            from the search. If True then param first is ignored.
        :type getAll: bool, optional
        :param withPagination: Defaults to False. Whether to return pagination
            info with results.
        :type withPagination: bool, optional
        :return: List of groups in dictionary representation.
        :rtype: list[dict]
        """
        first = kwargs.get("first", 500)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        search = kwargs.get("search", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)

        if get_all:
            first = 100

        self.opencti.admin_logger.info(
            "Fetching groups with filters", {"filters": filters}
        )
        query = (
            """
            query Groups($first: Int, $after: ID, $orderBy: GroupsOrdering, $orderMode: OrderingMode, $search: String, $filters: FilterGroup) {
                groups(first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode, search: $search, filters: $filters) {
                    edges {
                        node {
                                """
            + (self.properties if custom_attributes is None else custom_attributes)
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
                "first": first,
                "after": after,
                "orderBy": order_by,
                "orderMode": order_mode,
                "search": search,
                "filters": filters,
            },
        )

        if get_all:
            final_data = []
            data = self.opencti.process_multiple(result["data"]["groups"])
            final_data = final_data + data
            while result["data"]["groups"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["groups"]["pageInfo"]["endCursor"]
                result = self.opencti.query(
                    query,
                    {
                        "first": first,
                        "after": after,
                        "orderBy": order_by,
                        "orderMode": order_mode,
                        "search": search,
                        "filters": filters,
                    },
                )
                data = self.opencti.process_multiple(result["data"]["groups"])
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["groups"], with_pagination
            )

    def read(self, **kwargs) -> Optional[Dict]:
        """Fetch a given group from OpenCTI

        One of id or filters is required.

        :param id: ID of the group to fetch
        :type id: str, optional
        :param filters: Filters to apply to find single group
        :type filters: dict, optional
        :param customAttributes: Custom attributes to fetch for the group
        :type customAttributes: str
        :return: Representation of a group.
        :rtype: Optional[Dict]
        """
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        search = kwargs.get("search", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.admin_logger.info("Fetching group with ID", {"id": id})
            query = (
                """
                query Group($id: String!) {
                    group(id: $id) {
                        """
                + (self.properties if custom_attributes is None else custom_attributes)
                + """
                    }
                }
                """
            )
            result = self.opencti.query(query, {"id": id})
            return self.opencti.process_multiple_fields(result["data"]["group"])
        elif filters is not None or search is not None:
            results = self.list(
                filters=filters, search=search, customAttributes=custom_attributes
            )
            return results[0] if results else None
        else:
            self.opencti.admin_logger.error(
                "[opencti_group] Missing parameters: id or filters"
            )
            return None

    def create(self, **kwargs) -> Optional[Dict]:
        """Create a group with required details

        Groups can be configured after creation using other functions.

        :param name: Name of the group to create.
        :type name: str
        :param id_confidence_level: Confidence-level dictionary, with a
            max_confidence member between 0 and 100 (incl) and an overrides
            list with max_confidence and the entity_type it applies to.
        :type id_confidence_level: dict
        :param description: Description of the group
        :type description: str, optional
        :param default_assignation: Defaults to False. Whether or not to assign
            this group by default to all new users.
        :type default_assignation: bool, optional
        :param no_creators: Defaults to False. Whether or not to create
            authors for members of this group.
        :type no_creators: bool, optional
        :param restrict_delete: Defaults to False. Whether or not to restrict
            members deleting entities that are not their own.
        :type restrict_delete: bool, optional
        :param auto_new_marking: Defaults to False. Whether or not to allow
            members access to new markings automatically.
        :type auto_new_marking: bool, optional
        :param customAttributes: Attributes to retrieve from the new group
        :type customAttributes: str, optional
        :return: Representation of the group.
        :rtype: Optional[Dict]
        """
        name = kwargs.get("name", None)
        group_confidence_level = kwargs.get("group_confidence_level", None)
        description = kwargs.get("description", None)
        default_assignation = kwargs.get("default_assignation", False)
        no_creators = kwargs.get("no_creators", False)
        restrict_delete = kwargs.get("restrict_delete", False)
        auto_new_marking = kwargs.get("auto_new_marking", False)
        custom_attributes = kwargs.get("customAttributes", None)

        if name is None or group_confidence_level is None:
            self.opencti.admin_logger.error(
                "[opencti_group] Missing parameters: name and group_confidence_level"
            )
            return None

        self.opencti.admin_logger.info(
            "Creating new group with parameters",
            {
                "name": name,
                "group_confidence_level": group_confidence_level,
                "description": description,
                "default_assignation": default_assignation,
                "no_creators": no_creators,
                "restrict_delete": restrict_delete,
                "auto_new_marking": auto_new_marking,
            },
        )
        query = (
            """
            mutation GroupAdd($input: GroupAddInput!) {
                groupAdd(input: $input) {
                    """
            + (self.properties if custom_attributes is None else custom_attributes)
            + """
                }
            }
            """
        )
        result = self.opencti.query(
            query,
            {
                "input": {
                    "name": name,
                    "description": description,
                    "default_assignation": default_assignation,
                    "no_creators": no_creators,
                    "restrict_delete": restrict_delete,
                    "auto_new_marking": auto_new_marking,
                    "group_confidence_level": group_confidence_level,
                }
            },
        )
        return self.opencti.process_multiple_fields(result["data"]["groupAdd"])

    def delete(self, id: str):
        """Delete a given group from OpenCTI

        :param id: ID of the group to delete.
        :type id: str
        """
        self.opencti.admin_logger.info("Deleting group", {"id": id})
        query = """
            mutation GroupDelete($id: ID!) {
                groupEdit(id: $id) {
                    delete
                }
            }
        """
        self.opencti.query(query, {"id": id})

    def update_field(self, **kwargs) -> Optional[Dict]:
        """Update a group using fieldPatch

        :param id: ID of the group to update
        :type id: str
        :param input: FieldPatchInput object to edit group
        :type input: List[Dict]
        :param customAttributes: Custom attributes to retrieve from group
        :type customAttribues: str, optional
        :return: Representation of a group
        :rtype: Optional[Dict]
        """
        id = kwargs.get("id", None)
        input = kwargs.get("input", None)
        custom_attributes = kwargs.get("customAttributes", None)

        if id is None or input is None:
            self.opencti.admin_logger.error(
                "[opencti_group] Missing parameters: id and input"
            )
            return None

        self.opencti.admin_logger.info("Editing group with input", {"input": input})
        query = (
            """
            mutation GroupEdit($id: ID!, $input:[EditInput]!) {
                groupEdit(id: $id) {
                    fieldPatch(input: $input) {
                        """
            + (self.properties if custom_attributes is None else custom_attributes)
            + """
                    }
                }
            }
            """
        )
        result = self.opencti.query(query, {"id": id, "input": input})
        return self.opencti.process_multiple_fields(
            result["data"]["groupEdit"]["fieldPatch"]
        )

    def add_member(self, **kwargs) -> Optional[Dict]:
        """Add a member to a given group.

        :param id: ID of the group to add a member to
        :type id: str
        :param user_id: ID to add to the group
        :type user_id: str
        :return: Representation of the relationship
        :rtype: Optional[Dict]
        """
        id = kwargs.get("id", None)
        user_id = kwargs.get("user_id", None)

        if id is None or user_id is None:
            self.opencti.admin_logger.error(
                "[opencti_group] Missing parameters: id and user_id"
            )
            return None

        self.opencti.admin_logger.info(
            "Adding member to group", {"groupId": id, "userId": user_id}
        )
        query = """
            mutation GroupEditMemberAdd($groupId: ID!, $userId: ID!) {
                groupEdit(id: $groupId) {
                    relationAdd(input: {
                        fromId: $userId,
                        relationship_type: "member-of"
                    }) {
                        id, standard_id, entity_type, created_at, updated_at
                        from {
                            id, entity_type
                        }
                        to {
                            id, entity_type
                        }
                    }
                }
            }
            """
        result = self.opencti.query(query, {"groupId": id, "userId": user_id})
        return self.opencti.process_multiple_fields(
            result["data"]["groupEdit"]["relationAdd"]
        )

    def delete_member(self, **kwargs) -> Optional[Dict]:
        """Remove a given user from a group

        :param id: ID to remove a user from
        :type id: str
        :param user: ID to remove from the group
        :type user: str
        :return: Representation of the group after the member has been removed
        :rtype: Optional[Dict]
        """
        id = kwargs.get("id", None)
        user_id = kwargs.get("user_id", None)

        if id is None or user_id is None:
            self.opencti.admin_logger.error(
                "[opencti_group] Missing parameters: id and user_id"
            )
            return None

        self.opencti.admin_logger.info(
            "Removing member from group", {"groupId": id, "userId": user_id}
        )
        query = (
            """
            mutation GroupEditMemberDelete ($groupId: ID!, $userId: StixRef!) {
                groupEdit(id: $groupId) {
                    relationDelete(fromId: $userId, relationship_type: "member-of") {
                        """
            + self.properties
            + """
                    }
                }
            }
            """
        )
        result = self.opencti.query(query, {"groupId": id, "userId": user_id})
        return self.opencti.process_multiple_fields(
            result["data"]["groupEdit"]["relationDelete"]
        )

    def add_role(self, **kwargs) -> Optional[Dict]:
        """Add a role to a given group

        :param id: ID to add a role to
        :type id: str
        :param role_id: Role ID to add to the group
        :type role: str
        :return: Representation of the group after a role has been added
        :rtype: Optional[Dict]
        """
        id = kwargs.get("id", None)
        role_id = kwargs.get("role_id", None)

        if id is None or role_id is None:
            self.opencti.admin_logger.error(
                "[opencti_group] Missing parameters: id and role_id"
            )
            return None

        self.opencti.admin_logger.info(
            "Adding role to group", {"groupId": id, "roleId": role_id}
        )
        query = """
            mutation GroupEditRoleAdd($groupId: ID!, $roleId: ID!) {
                groupEdit(id: $groupId) {
                    relationAdd(input: {
                        toId: $roleId, relationship_type: "has-role"
                    }) {
                        id, standard_id, entity_type, created_at, updated_at
                        from {
                            id, entity_type
                        }
                        to {
                            id, entity_type
                        }
                    }
                }
            }
            """
        result = self.opencti.query(query, {"groupId": id, "roleId": role_id})
        return self.opencti.process_multiple_fields(
            result["data"]["groupEdit"]["relationAdd"]
        )

    def delete_role(self, **kwargs) -> Optional[Dict]:
        """Removes a role from a given group

        :param id: ID to remove role from
        :type id: str
        :param role_id: Role ID to remove from the group
        :type role_id: str
        :return: Representation of the group after role is removed
        :rtype: Optional[Dict]
        """
        id = kwargs.get("id", None)
        role_id = kwargs.get("role_id", None)

        if id is None or role_id is None:
            self.opencti.admin_logger.error(
                "[opencti_group] Missing parameters: id and role_id"
            )
            return None

        self.opencti.admin_logger.info(
            "Removing role from group", {"groupId": id, "roleId": role_id}
        )
        query = (
            """
            mutation GroupEditRoleDelete($groupId: ID!, $roleId: StixRef!) {
                groupEdit(id: $groupId) {
                    relationDelete(toId: $roleId, relationship_type: "has-role") {
                        """
            + self.properties
            + """
                    }
                }
            }
            """
        )
        result = self.opencti.query(query, {"groupId": id, "roleId": role_id})
        return self.opencti.process_multiple_fields(
            result["data"]["groupEdit"]["relationDelete"]
        )

    def edit_default_marking(self, **kwargs) -> Optional[Dict]:
        """Adds a default marking to the group.

        :param id: ID of the group.
        :type id: str
        :param marking_ids: IDs of the markings to add, or an empty list to
            remove all default markings
        :type marking_ids: List[str]
        :param entity:  STIX entity type to add default
            marking for. If set to "GLOBAL" applies to all entity types,
            defaults to "GLOBAL".
        :type entity: str, optional
        :return: Group after adding the default marking.
        :rtype: Optional[Dict]
        """
        id = kwargs.get("id", None)
        marking_ids = kwargs.get("marking_ids", None)
        entity_type = kwargs.get("entity_type", "GLOBAL")

        if id is None or marking_ids is None:
            self.opencti.admin_logger.error(
                "[opencti_group] Missing parameters: id and marking_ids"
            )
            return None

        self.opencti.admin_logger.info(
            "Setting default markings for entity on group",
            {"markings": marking_ids, "entity_type": entity_type, "groupId": id},
        )
        query = (
            """
            mutation GroupEditEditDefaultMarking($id: ID!, $entity_type: String!, $values: [String!]) {
                groupEdit(id: $id) {
                    editDefaultMarking(input: {
                        entity_type: $entity_type,
                        values: $values
                    }) {
                        """
            + self.properties
            + """
                    }
                }
            }
            """
        )
        result = self.opencti.query(
            query, {"id": id, "entity_type": entity_type, "values": marking_ids}
        )
        return self.opencti.process_multiple_fields(
            result["data"]["groupEdit"]["editDefaultMarking"]
        )

    def add_allowed_marking(self, **kwargs) -> Optional[Dict]:
        """Allow a group to access a marking

        :param id: ID of group to authorise
        :type id: str
        :param marking_id: ID of marking to authorise
        :type marking_id: str
        :return: Relationship from the group to the marking definition
        :rtype: Optional[Dict]
        """
        id = kwargs.get("id", None)
        marking_id = kwargs.get("marking_id", None)

        if id is None or marking_id is None:
            self.opencti.admin_logger.error(
                "[opencti_group] Missing parameters: id and marking_id"
            )
            return None

        self.opencti.admin_logger.info(
            "Granting group access to marking definition",
            {"groupId": id, "markingId": marking_id},
        )
        query = """
            mutation GroupEditionMarkingsMarkingDefinitionsRelationAddMutation(
                $id: ID!
                $input: InternalRelationshipAddInput!
            ) {
                groupEdit(id: $id) {
                    relationAdd(input: $input) {
                        from {
                            __typename
                            ...GroupEditionMarkings_group
                            id
                        }
                        id
                        }
                    }
                }

                fragment GroupEditionMarkings_group on Group {
                id
                default_assignation
                allowed_marking {
                    id
                }
                not_shareable_marking_types
                max_shareable_marking {
                    id
                    definition
                    definition_type
                    x_opencti_order
                }
                default_marking {
                    entity_type
                    values {
                    id
                    }
                }
            }
        """
        result = self.opencti.query(
            query,
            {
                "id": id,
                "input": {"relationship_type": "accesses-to", "toId": marking_id},
            },
        )
        return self.opencti.process_multiple_fields(
            result["data"]["groupEdit"]["relationAdd"]
        )

    def delete_allowed_marking(self, **kwargs) -> Optional[Dict]:
        """Removes access to a marking for a group

        :param id: ID of group to forbid
        :type id: str
        :param marking_id: ID of marking to deny
        :type marking_id: str
        :return: Group after denying access to marking definition
        :rtype: Optional[Dict]
        """
        id = kwargs.get("id", None)
        marking_id = kwargs.get("marking_id", None)

        if id is None or marking_id is None:
            self.opencti.admin_logger.error(
                "[opencti_group] Missing parameters: id and marking_id"
            )
            return None

        self.opencti.admin_logger.info(
            "Forbidding group access to marking definition",
            {"groupId": id, "markingId": marking_id},
        )
        query = (
            """
            mutation GroupEditMarkingRemove($groupId: ID!, $markingId: StixRef!) {
                groupEdit(id: $groupId) {
                    relationDelete(toId: $markingId, relationship_type: "accesses-to") {
                        """
            + self.properties
            + """
                    }
                }
            }
            """
        )
        result = self.opencti.query(query, {"groupId": id, "markingId": marking_id})
        return self.opencti.process_multiple_fields(
            result["data"]["groupEdit"]["relationDelete"]
        )

    def process_multiple_fields(self, data):
        if "roles" in data:
            data["roles"] = self.opencti.process_multiple(data["roles"])
            data["rolesIds"] = self.opencti.process_multiple_ids(data["roles"])
        if "members" in data:
            data["members"] = self.opencti.process_multiple(data["members"])
            data["membersIds"] = self.opencti.process_multiple_ids(data["members"])
        return data
