import abc
import json
from functools import lru_cache
from typing import TYPE_CHECKING, ClassVar, Optional

from pycti.types import Entities, FilterGroup, OrderMode

if TYPE_CHECKING:
    from pycti.api.opencti_api_client import OpenCTIApiClient

__all__ = ["Entity"]


class Entity(abc.ABC):

    PROPERTIES: ClassVar[str]
    OBJECTS_PROPERTIES: ClassVar[Optional[str]] = None
    FILES_PROPERTIES: ClassVar[Optional[str]] = None

    OVERRIDES: ClassVar[dict] = {
        "queries": {
            "relation_add": "stixDomainObjectEdit(id: $id) { relationAdd(input: $input) { id } }",
            "relation_delete": """stixDomainObjectEdit(id: $id) {
                relationDelete(toId: $toId, relationship_type: $relationship_type) {
                    id
                }
            }""",
        }
    }

    def __init__(
        self,
        opencti_api_client: "OpenCTIApiClient",
        properties: str = None,
        objects_properties: str = None,
        files_properties: str = None,
    ) -> None:
        self.opencti = opencti_api_client
        self.properties = properties or self.PROPERTIES
        self.objects_properties = objects_properties or self.OBJECTS_PROPERTIES
        self.files_properties = files_properties or self.FILES_PROPERTIES

    @lru_cache(maxsize=2)
    def name(self, plural: bool = False) -> str:
        name = self.__class__.__name__
        if plural:
            if name.endswith("y"):
                return name[:-1] + "ies"
            if name.endswith("is"):
                return name[:-2] + "es"
            return name + "s"
        return name

    @lru_cache(maxsize=2)
    def query_name(self, plural: bool = False) -> str:
        name = self.name(plural=plural)
        return name[0].lower() + name[1:]

    def _get_attributes(
        self,
        custom_attributes: Optional[str] = None,
        with_objects: bool = False,
        custom_objects_attributes: Optional[str] = None,
        with_files: bool = False,
        custom_files_attributes: Optional[str] = None,
    ) -> str:
        """Build the attributes for an entity query

        :param custom_attributes: custom attributes to return for the subject entity
        :type custom_attributes: str
        :param with_objects: whether to include objects in the query results
        :type with_objects: bool
        :param custom_objects_attributes: custom attributes to return for the subject entity's objects
        :type custom_objects_attributes: str
        :param with_files: whether to include files in the query results
        :type with_files: bool
        :param custom_files_attributes: custom attributes to return for the subject entity's files
        :type custom_files_attributes: str
        :return: attributes for an entity query
        :rtype: str"""
        attributes = custom_attributes or self.properties
        if with_objects and self.objects_properties is not None:
            attributes += f"""
                objects(all: true) {{
                    edges {{
                        node {{
                            {custom_objects_attributes or self.objects_properties}
                        }}
                    }}
                }}
                """
        if with_files and self.files_properties is not None:
            attributes += f"""
                importFiles {{
                    edges {{
                        node {{
                            {custom_files_attributes or self.files_properties}
                        }}
                    }}
                }}
                """
        return attributes

    @staticmethod
    def get_read_query(label: str, name: str, attributes: str) -> str:
        """Create query for reading an entity

        :param label: the label for the query
        :type label: str
        :param name: the name of the query in graphql api
        :type name: str
        :param attributes: the attributes to return for the subject query
        :type attributes: str
        :return: the query
        :rtype: str
        """
        return f"""
            query {label}($id: String!) {{
                {name}(id: $id) {{
                    {attributes}
                }}
            }}
        """

    def read(
        self,
        id: str = None,
        filters: FilterGroup = None,
        custom_attributes: str = None,
        with_objects: bool = True,
        custom_objects_attributes: str = None,
        with_files: bool = False,
        custom_files_attributes: str = None,
        **kwargs,
    ) -> Optional[dict]:
        """Read an entity.

        :param id: the id of the entity to read; if not given, `filters` is required.
        :type id: str
        :param filters: the filters to apply if no id provided; used in conjunction with a call to `list()`.
        :type filters: dict
        :param custom_attributes: custom attributes to return
        :type custom_attributes: list
        :param with_objects: whether to include files
        :type with_objects: bool
        :param custom_objects_attributes: custom attributes to return
        :type custom_objects_attributes: list
        :param with_files: whether to include files
        :type with_files: bool
        :param custom_files_attributes: custom attributes to return
        :type custom_files_attributes: list
        :param kwargs: snakecase variables passed in as camelcase will be translated to their snakecase counterparts.
            the rest of the kwargs are passed, as is, into the potential call to `list()`.
        :type kwargs: dict
        :return: an entity object
        :rtype: dict or None
        """
        assert id or filters, "Either id or filters must be provided"

        custom_attributes = custom_attributes or kwargs.pop("customAttributes", None)
        with_objects = with_objects or kwargs.pop("withObjects", False)
        custom_objects_attributes = custom_objects_attributes or kwargs.pop(
            "customObjectsAttributes", None
        )
        with_files = with_files or kwargs.pop("withFiles", False)
        custom_files_attributes = custom_files_attributes or kwargs.pop(
            "customFilesAttributes", None
        )

        if id is not None:
            self.opencti.app_logger.info(f"Reading {self.name}", {"id": id})
            attributes = self._get_attributes(
                custom_attributes,
                with_objects,
                custom_objects_attributes,
                with_files,
                custom_files_attributes,
            )
            query = self.get_read_query(
                label=self.name(),
                name=self.query_name(),
                attributes=attributes,
            )
            result = self.opencti.query(query, {"id": id})
            return self.opencti.process_multiple_fields(
                result["data"][self.query_name()]
            )

        results = self.list(
            filters=filters,
            custom_attributes=custom_attributes,
            with_objects=with_objects,
            custom_objects_attributes=custom_objects_attributes,
            with_files=with_files,
            custom_files_attributes=custom_files_attributes,
            **kwargs,
        )
        if len(results) == 0:
            return None
        elif len(results) == 1:
            return results[0]
        else:
            self.opencti.app_logger.warning(
                f"{len(results)} entities found; returning the first one"
            )
            return results[0]

    @classmethod
    def get_list_query(cls, label: str, name: str, attributes: str) -> str:
        """Create query for listing entities

        :param label: the label for the query
        :type label: str
        :param name: the name of the query in graphql api
        :type name: str
        :param attributes: the attributes to return for the subject query
        :type attributes: str
        :return: the query
        :rtype: str
        """
        ordering = cls.OVERRIDES.get("ordering", f"{label}Ordering")
        return f"""
            query {label}(
                $filters: FilterGroup,
                $search: String,
                $first: Int,
                $after: ID,
                $orderBy: {ordering},
                $orderMode: OrderingMode,
            ) {{
                {name}(
                    filters: $filters,
                    search: $search,
                    first: $first,
                    after: $after,
                    orderBy: $orderBy,
                    orderMode: $orderMode
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
            """

    def list(
        self,
        filters: FilterGroup = None,
        search: str = None,
        first: int = None,
        after: str = None,
        order_by: str = None,
        order_mode: OrderMode = None,
        get_all: bool = False,
        with_pagination: bool = False,
        custom_attributes: str = None,
        with_objects: bool = False,
        custom_objects_attributes: str = None,
        with_files: bool = False,
        custom_files_attributes: str = None,
        **kwargs,
    ) -> Entities:
        """List entities

        :param filters: the filters to apply
        :type filters: dict
        :param search: the search keyword
        :type search: str
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :type first: int
        :param after: ID of the first row for pagination
        :type after: str
        :param order_by: field to order results by
        :type order_by: str
        :param order_mode: ordering mode (asc/desc)
        :type order_mode: str
        :param get_all: whether to retrieve all results
        :type get_all: bool
        :param with_pagination: whether to include pagination info
        :type with_pagination: bool
        :param custom_attributes: custom attributes to return
        :type custom_attributes: str
        :param with_objects: whether to include entity objects
        :type with_objects: bool
        :param custom_objects_attributes: custom objects attributes to return
        :type custom_objects_attributes: str
        :param with_files: whether to include files
        :type with_files: bool
        :param custom_files_attributes: custom file attributes to return
        :type custom_files_attributes: str
        :param kwargs: snakecase variables passed in as camelcase will be translated to
            snakecase. the rest of the kwargs are passed, as is, as variables to the
            call to `query()`.
        :type kwargs: dict
        :return: List of entity objects
        :rtype: Entities
        """
        if first == 1:
            self.opencti.app_logger.warning(
                "`first=1` is known to return incorrect results; overriding to 2"
            )
            first = 2

        order_by = order_by or kwargs.pop("orderBy", None)
        order_mode = order_mode or kwargs.pop("orderMode", None)
        get_all = get_all or kwargs.pop("getAll", False)
        with_pagination = with_pagination or kwargs.pop("withPagination", False)
        custom_attributes = custom_attributes or kwargs.pop("customAttributes", None)
        with_objects = with_objects or kwargs.pop("withObjects", False)
        custom_objects_attributes = custom_objects_attributes or kwargs.pop(
            "customObjectsAttributes", None
        )
        with_files = with_files or kwargs.pop("withFiles", False)
        custom_files_attributes = custom_files_attributes or kwargs.pop(
            "customFilesAttributes", None
        )

        query_label = self.name(plural=True)
        query_name = self.query_name(plural=True)

        self.opencti.app_logger.info(
            f"Listing {query_label} with filters", {"filters": json.dumps(filters)}
        )
        attributes = self._get_attributes(
            custom_attributes=custom_attributes,
            with_objects=with_objects,
            custom_objects_attributes=custom_objects_attributes,
            with_files=with_files,
            custom_files_attributes=custom_files_attributes,
        )
        query = self.get_list_query(
            label=query_label, name=query_name, attributes=attributes
        )
        variables = {
            "first": first,
            "after": after,
            "orderBy": order_by,
            "orderMode": order_mode,
            "filters": filters,
            "search": search,
            "all": get_all,
            **kwargs,
        }
        return self.opencti.query_connection(
            query,
            variables=variables,
            key=lambda r: r["data"][query_name],
            with_pagination=with_pagination,
        )
