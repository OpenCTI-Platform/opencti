from typing import Dict, List, Optional


class Role:
    """Representation of a role in OpenCTI

    Roles can have capabilities. Groups have roles, and the combined
    capabilities of those roles determine what a group of users can do on the
    platform.

    Check the properties attribute of the class to understand what default
    properties are fetched.
    """

    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            standard_id
            entity_type
            parent_types
            name
            description
            created_at
            updated_at
            capabilities {
                id
                name
                description
            }
            can_manage_sensitive_config
        """

    def list(self, **kwargs) -> List[Dict]:
        """Search or list the roles on the server.

        :param search:
            Defaults to None.
        :type search: str, optional
        :param first: Defaults to 500 Return the first x results from ID or
            beginning if $after is not specified.
        :type first: int, optional
        :param after: Return all results after the given ID, useful for
            pagination. Ignored if returning all results, defaults to None.
        :type after: str, optional
        :param orderBy: Field to order by. Must be one of "name",
            "created_at", "updated_at", or "_score". Defaults
            to "name", defaults to "name".
        :type orderBy: str, optional
        :param orderMode: Direction to order in, either "asc" or "desc",
            defaults to "asc".
        :type orderMode: str, optional
        :param customAttributes: Defaults to None. Custom attributes to return
            from query. If None, defaults are used.
        :type customAttributes: str, optional
        :param getAll: Defaults to False. Retrieve all results. If true then
            the "first" param is ignored.
        :type getAll: bool, optional
        :param withPagination: Defaults to False Whether to include pagination
            pageInfo properties in result.
        :type withPagination: bool, optional

        :return: List of Python dictionaries with the properties of the role.
        :rtype: List[Dict]
        """
        search = kwargs.get("search", None)
        first = kwargs.get("first", 500)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        custom_attributes = kwargs.get("customAttributes", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)

        self.opencti.admin_logger.info(
            "Searching roles matching search term", {"search": search}
        )

        if get_all:
            first = 100

        query = (
            """
            query RoleList($first: Int, $after: ID, $orderBy: RolesOrdering, $orderMode: OrderingMode, $search: String) {
                roles(first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode, search: $search) {
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
            },
        )
        if get_all:
            final_data = []
            data = self.opencti.process_multiple(result["data"]["roles"])
            final_data = final_data + data
            while result["data"]["roles"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["roles"]["pageInfo"]["endCursor"]
                result = self.opencti.query(
                    query,
                    {
                        "first": first,
                        "after": after,
                        "orderBy": order_by,
                        "orderMode": order_mode,
                        "search": search,
                    },
                )
                data = self.opencti.process_multiple(result["data"]["roles"])
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["roles"], with_pagination
            )

    def read(self, **kwargs) -> Optional[Dict]:
        """Get a role given its ID or a search term

        One of id or search must be provided.

        :param id: ID of the role on the platform
        :type id: str, optional
        :param search: Search term for a role, e.g. its name
        :type search: str, optional
        :param customAttributes: Custom attributes on the role to return
        :type customAttributes: str, optional

        :return: Representation of the role
        :rtype: Optional[Dict]
        """
        id = kwargs.get("id", None)
        search = kwargs.get("search", None)
        custom_attributes = kwargs.get("customAttributes", None)

        if id is not None:
            self.opencti.admin_logger.info("Reading role", {"id": id})
            query = (
                """
                query RoleRead($id: String!) {
                    role(id: $id) {
                        """
                + (self.properties if custom_attributes is None else custom_attributes)
                + """
                    }
                }
                """
            )
            result = self.opencti.query(query, {"id": id})
            return self.opencti.process_multiple_fields(result["data"]["role"])
        elif search is not None:
            result = self.list(search=search)
            return result[0] if len(result) > 0 else None
        else:
            self.opencti.admin_logger.error(
                "[opencti_role] Missing parameters: id or search"
            )
            return None

    def delete(self, **kwargs):
        """Delete a role given its ID

        :param id: ID for the role on the platform.
        :type id: str
        """
        id = kwargs.get("id", None)

        if id is None:
            self.opencti.admin_logger.error("[opencti_role] Missing parameter: id")
            return None

        self.opencti.admin_logger.info("Deleting role", {"id": id})
        query = """
            mutation RoleDelete($id: ID!) {
                roleEdit(id: $id) {
                    delete
                }
            }
        """
        self.opencti.query(query, {"id": id})

    def create(self, **kwargs) -> Optional[Dict]:
        """Add a new role to OpenCTI.

        :param name: Name to assign to the role.
        :type name: str
        :param description: Optional. Description of the role, defaults to
            None.
        :type description: str, optional
        :param customAttributes: Custom attributes to return on role
        :type customAttributes: str, optional
        :return: Representation of the role.
        :rtype: Optional[Dict]
        """
        name = kwargs.get("name", None)
        description = kwargs.get("description", None)
        custom_attributes = kwargs.get("customAttributes", None)

        if name is None:
            self.opencti.admin_logger.error("[opencti_role] Missing parameter: name")
            return None

        self.opencti.admin_logger.info(
            "Creating new role", {"name": name, "description": description}
        )
        query = (
            """
            mutation RoleCreate($input: RoleAddInput!) {
                roleAdd(input: $input) {
                    """
            + (self.properties if custom_attributes is None else custom_attributes)
            + """
                }
            }
            """
        )
        result = self.opencti.query(
            query, {"input": {"name": name, "description": description}}
        )
        return self.opencti.process_multiple_fields(result["data"]["roleAdd"])

    def update_field(self, **kwargs) -> Optional[Dict]:
        """Updates a given role with the given inputs

        Example of input::

            [
                {
                    "key": "name",
                    "value": "NewCustomRole"
                },
                {
                    "key": "can_manage_sensitive_config",
                    "value": False
                }
            ]

        :param id: ID for the role on the platform
        :type id: str
        :param input: List of EditInput objects
        :type input: List[Dict]
        :param customAttributes: Custom attributes to return on the role
        :type customAttributes: str, optional

        :return: Representation of the role
        :rtype: Optional[Dict]
        """
        id = kwargs.get("id", None)
        input = kwargs.get("input", None)
        custom_attributes = kwargs.get("customAttributes", None)

        if id is None or input is None:
            self.opencti.admin_logger.error(
                "[opencti_role] Missing parameters: id and input"
            )
            return None

        self.opencti.admin_logger.info(
            "Editing role with input", {"id": id, "input": input}
        )
        query = (
            """
            mutation RoleUpdate($id: ID!, $input: [EditInput]!) {
                roleEdit(id: $id) {
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
            result["data"]["roleEdit"]["fieldPatch"]
        )

    def add_capability(self, **kwargs) -> Optional[Dict]:
        """Adds a capability to a role

        :param id: ID of the role.
        :type id: str
        :param capability_id: ID of the capability to add.
        :type capability_id: str
        :return: Representation of the relationship, including the role and
            capability
        :rtype: Optional[Dict]
        """
        id = kwargs.get("id", None)
        capability_id = kwargs.get("capability_id", None)

        if id is None or capability_id is None:
            self.opencti.admin_logger(
                "[opencti_role] Missing parameters: id and capability_id"
            )
            return None

        self.opencti.admin_logger.info(
            "Adding capability to role", {"roleId": id, "capabilityId": capability_id}
        )
        query = (
            """
            mutation RoleEditAddCapability($id: ID!, $input: InternalRelationshipAddInput!) {
                roleEdit(id: $id) {
                    relationAdd(input: $input) {
                        id
                        entity_type
                        parent_types
                        created_at
                        updated_at
                        from {
                            ... on Role {
                                """
            + self.properties
            + """
                            }
                        }
                        to {
                            ... on Capability {
                                id, name, description
                            }
                        }
                    }
                }
            }
            """
        )
        result = self.opencti.query(
            query,
            {
                "id": id,
                "input": {"relationship_type": "has-capability", "toId": capability_id},
            },
        )
        return self.opencti.process_multiple_fields(
            result["data"]["roleEdit"]["relationAdd"]
        )

    def delete_capability(self, **kwargs) -> Optional[Dict]:
        """Removes a capability from a role

        :param id: ID of the role
        :type id: str
        :param capability_id: ID of the capability to remove
        :type capability_id: str
        :return: Representation of the role after removing the capability
        :rtype: Optional[Dict]
        """
        id = kwargs.get("id", None)
        capability_id = kwargs.get("capability_id", None)

        if id is None or capability_id is None:
            self.opencti.admin_logger.error(
                "[opencti_role] Missing parameters: id and capability_id"
            )
            return None

        self.opencti.admin_logger.info(
            "Removing capability from role",
            {"roleId": id, "capabilityId": capability_id},
        )
        query = (
            """
            mutation RoleEditDeleteCapability($id: ID!, $toId: StixRef!) {
                roleEdit(id: $id) {
                    relationDelete(toId: $toId, relationship_type: "has-capability") {
                        """
            + self.properties
            + """
                    }
                }
            }
            """
        )
        result = self.opencti.query(query, {"id": id, "toId": capability_id})
        return self.opencti.process_multiple_fields(
            result["data"]["roleEdit"]["relationDelete"]
        )

    def process_multiple_fields(self, data):
        if "capabilities" in data:
            data["capabilities"] = self.opencti.process_multiple(data["capabilities"])
            data["capabilitiesIds"] = self.opencti.process_multiple_ids(
                data["capabilities"]
            )
        return data
