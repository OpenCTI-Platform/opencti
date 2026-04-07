from typing import List, Optional, Union

from dateutil.parser import parse

from pycti.types import Entities, FilterGroup, OrderMode, PaginatedResponse

__all__ = [
    "ListFilesMixin",
    "ListObjectsMixin",
    "GetByStixIdOrNameMixin",
    "StixObjectOrRelationshipMixin",
]


class ListObjectsMixin:
    @staticmethod
    def get_list_objects_query(label: str, name: str, attributes: str) -> str:
        return f"""
            query List{label}Objects(
                $id: String!,
                $first: Int = 100,
                $after: ID,
                $orderBy: StixObjectOrStixRelationshipsOrdering,
                $orderMode: OrderingMode,
                $filters: FilterGroup,
                $search: String,
                $types: [String],
                $all: Boolean = false,
            ) {{
                {name}(id: $id) {{
                    objects(
                            first: $first,
                            after: $after,
                            orderBy: $orderBy,
                            orderMode: $orderMode,
                            filters: $filters,
                            search: $search,
                            types: $types,
                            all: $all
                    ) {{
                        edges {{
                            node {{
                                {attributes}
                            }}
                        }}
                        pageInfo {{
                            startCursor
                            endCursor
                            hasNextPage
                            hasPreviousPage
                            globalCount
                        }}
                    }}
                }}
            }}
            """

    def list_objects(
        self,
        id: str,
        first: int = 100,
        after: str = None,
        order_by: str = None,
        order_mode: OrderMode = None,
        filters: FilterGroup = None,
        search: str = None,
        types: List[str] = None,
        all: bool = True,
        custom_attributes: str = None,
        **kwargs,
    ) -> Union[Entities, PaginatedResponse]:
        """List objects of an entity via connection.

        The `objects` property of the entity (found via `id_or_name`) is listed, exactly
        like the `list` method. Each of these objects is a StixObjectOrStixRelationship,
        so the properties should be set based on the possible type, i.e.
        "... on IPv4Addr".

        :param id: The entity's `id` or `standard_id`.
        :param first: The number of objects to return per page
        :param after: The ID of the cursor to retrieve objects "after". This is likely
            the `pageInfo.endCursor` of the last page returned.
        :param order_by: The field to order the returned objects by.
        :param order_mode: The ordering mode for the returned objects.
        :param filters: A list of filters to use for filtering objects.
        :param search: A search keyword to use for filtering objects.
        :param types: A list of object types to filter objects by.
        :param all: Whether to retrieve all objects or no
        :param custom_attributes: The GraphQL properties/schema to use for the `objects`
            connection edges -> nodes.
        :param kwargs: Additional keyword arguments to pass to `query_connection`.
        :return: A list of objects or a dict containing a page of objects and pagination
            info.
        """
        if first == 1:
            self.opencti.app_logger.warning(
                "`first=1` is known to return incorrect results; overriding to 2"
            )
            first = 2

        query = self.get_list_objects_query(
            label=self.name(),
            name=self.query_name(),
            attributes=custom_attributes or self.objects_properties,
        )
        variables = {
            "id": id,
            "first": first,
            "after": after,
            "orderBy": order_by,
            "orderMode": order_mode,
            "filters": filters,
            "search": search,
            "types": types,
            "all": all,
        }
        try:
            return self.opencti.query_connection(
                query,
                variables=variables,
                key=lambda r: r["data"][self.query_name()]["objects"],
                **kwargs,
            )
        except Exception:
            self.opencti.app_logger.error(
                f"Error listing {self.query_name()} objects for {id}"
            )
            raise


class ListFilesMixin:
    @staticmethod
    def get_list_files_query(label: str, name: str, attributes: str) -> str:
        return f"""
            query {label}($id: String!) {{
                {name}(id: $id) {{
                    importFiles {{
                        edges {{
                            node {{
                                {attributes}
                            }}
                        }}
                    }}
                }}
            }}
        """

    def list_files(self, id: str) -> List[dict]:
        """List files attached to an Entity

        :param id: the id of the entity
        :type id: str
        :return: List of files
        :rtype: list
        """
        self.opencti.app_logger.debug(f"Listing files of {self.name()}", {"id": id})
        query = self.get_list_files_query(
            self.name(), self.entity_type(), self.files_properties
        )
        result = self.opencti.query(query, {"id": id})
        entity = self.opencti.process_multiple_fields(
            result["data"][self.entity_type()]
        )
        return entity["importFiles"]


class GetByStixIdOrNameMixin:
    def get_by_stix_id_or_name(
        self,
        stix_id: str = None,
        name: str = None,
        created: str = None,
        custom_attributes: str = None,
        **kwargs,
    ) -> Optional[dict]:
        """Read a Task object by stix_id or name.

        :param stix_id: the STIX ID of the Task
        :type stix_id: str
        :param name: the name of the Task
        :type name: str
        :param created: the creation date of the Task
        :type created: str
        :param custom_attributes: custom attributes to return for the subject entity
        :type custom_attributes: str
        :return: Task object
        :rtype: dict or None
        """
        custom_attributes = custom_attributes or kwargs.get("customAttributes", None)

        object_result = None
        if stix_id is not None:
            object_result = self.read(id=stix_id, customAttributes=custom_attributes)
        if object_result is None and name is not None and created is not None:
            created_final = parse(created).strftime("%Y-%m-%d")
            object_result = self.read(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "name", "values": [name]},
                        {"key": "created_day", "values": [created_final]},
                    ],
                    "filterGroups": [],
                },
                customAttributes=custom_attributes,
            )
        return object_result


class StixObjectOrRelationshipMixin:
    def contains_stix_object_or_stix_relationship(
        self, id: str = None, stix_object_or_stix_relationship_id: str = None, **kwargs
    ):
        """Check if a case incident already contains a thing (Stix Object or Stix Relationship).

        :param id: the id of the Case Incident
        :type id: str
        :param stix_object_or_stix_relationship_id: the id of the Stix-Entity
        :type stix_object_or_stix_relationship_id: str
        :return: True if contained, False otherwise
        :rtype: bool or None
        """
        stix_object_or_stix_relationship_id = (
            stix_object_or_stix_relationship_id
            or kwargs.get("stixObjectOrStixRelationshipId", None)
        )
        if id is None or stix_object_or_stix_relationship_id is None:
            self.opencti.app_logger.error(
                f"[opencti_{self.entity_type()}] Missing parameters: id or stixObjectOrStixRelationshipId"
            )
            return None

        self.opencti.app_logger.info(
            f"Checking StixObjectOrStixRelationship in {self.name()}",
            {
                "id": id,
                "stix_object_or_stix_relationship_id": stix_object_or_stix_relationship_id,
            },
        )
        query = f"""
            query {self.name()}ContainsStixObjectOrStixRelationship(
                $id: String!, $stixObjectOrStixRelationshipId: String!
            ) {{
                {self.entity_type()}ContainsStixObjectOrStixRelationship(
                    id: $id, stixObjectOrStixRelationshipId: $stixObjectOrStixRelationshipId
                )
            }}
        """
        result = self.opencti.query(
            query,
            {
                "id": id,
                "stixObjectOrStixRelationshipId": stix_object_or_stix_relationship_id,
            },
        )
        return result["data"][f"{self.name()}ContainsStixObjectOrStixRelationship"]

    def add_stix_object_or_stix_relationship(
        self, id: str = None, stix_object_or_stix_relationship_id: str = None, **kwargs
    ):
        """Add a Stix-Entity object to Entity object (object_refs).

        :param id: the id of the Entity
        :type id: str
        :param stix_object_or_stix_relationship_id: the id of the Stix-Entity
        :type stix_object_or_stix_relationship_id: str
        :return: True if successful, False otherwise
        :rtype: bool
        """
        stix_object_or_stix_relationship_id = (
            stix_object_or_stix_relationship_id
            or kwargs.get("stixObjectOrStixRelationshipId", None)
        )
        if id is None or stix_object_or_stix_relationship_id is None:
            self.opencti.app_logger.error(
                f"[opencti_{self.entity_type()}] Missing parameters: id or stixObjectOrStixRelationshipId"
            )
            return None

        self.opencti.app_logger.info(
            f"Adding StixObjectOrStixRelationship to {self.name()}",
            {
                "stix_object_or_stix_relationship_id": stix_object_or_stix_relationship_id,
                "id": id,
            },
        )

        query = f"""
           mutation {self.name()}EditRelationAdd($id: ID!, $input: StixRefRelationshipAddInput!) {{
                {self.OVERRIDES["queries"]["relation_add"]}
           }}
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

    def remove_stix_object_or_stix_relationship(
        self, id: str = None, stix_object_or_stix_relationship_id: str = None, **kwargs
    ):
        """Remove a Stix-Entity object from Entity object (object_refs).

        :param id: the id of the Entity
        :type id: str
        :param stix_object_or_stix_relationship_id: the id of the Stix-Entity
        :type stix_object_or_stix_relationship_id: str
        :return: True if successful, False otherwise
        :rtype: bool
        """
        stix_object_or_stix_relationship_id = (
            stix_object_or_stix_relationship_id
            or kwargs.get("stixObjectOrStixRelationshipId", None)
        )
        if id is None or stix_object_or_stix_relationship_id is None:
            self.opencti.app_logger.error(
                f"[opencti_{self.entity_type()}] Missing parameters: id or stixObjectOrStixRelationshipId"
            )
            return None

        self.opencti.app_logger.info(
            f"Removing StixObjectOrStixRelationship from {self.name()}",
            {
                "id": id,
                "stix_object_or_stix_relationship_id": stix_object_or_stix_relationship_id,
            },
        )

        query = f"""
           mutation {self.name()}EditRelationDelete($id: ID!, $toId: StixRef!, $relationship_type: String!) {{
                {self.OVERRIDES["queries"]["relation_delete"]}
           }}
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
