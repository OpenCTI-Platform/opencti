# coding: utf-8

import json


class Tag:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            tag_type
            value
            color
            created_at
            updated_at
        """

    """
        List Tag objects

        :param filters: the filters to apply
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Tag objects
    """

    def list(self, **kwargs):
        filters = kwargs.get("filters", None)
        first = kwargs.get("first", 500)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)
        if get_all:
            first = 500

        self.opencti.log(
            "info", "Listing Tags with filters " + json.dumps(filters) + "."
        )
        query = (
            """
            query Tags($filters: [TagsFiltering], $first: Int, $after: ID, $orderBy: TagsOrdering, $orderMode: OrderingMode) {
                tags(filters: $filters, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
                "filters": filters,
                "first": first,
                "after": after,
                "orderBy": order_by,
                "orderMode": order_mode,
            },
        )
        return self.opencti.process_multiple(result["data"]["tags"], with_pagination)

    """
        Read a Tag object

        :param id: the id of the Tag
        :param filters: the filters to apply if no id provided
        :return Marking-Definition object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        if id is not None:
            self.opencti.log("info", "Reading Tag {" + id + "}.")
            query = (
                """
                query Tag($id: String!) {
                    tag(id: $id) {
                        """
                + self.properties
                + """
                    }
                }
            """
            )
            result = self.opencti.query(query, {"id": id})
            return self.opencti.process_multiple_fields(result["data"]["tag"])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.log("error", "[opencti_tag] Missing parameters: id or filters")
            return None

    """
        Create a Tag object

        :param tag_type: the tag type
        :param value: the value
        :param color: the color
        :return Tag object
    """

    def create_raw(self, **kwargs):
        tag_type = kwargs.get("tag_type", None)
        value = kwargs.get("value", None)
        color = kwargs.get("color", None)
        id = kwargs.get("id", None)

        if tag_type is not None and value is not None and color is not None:
            query = (
                """
                mutation TagAdd($input: TagAddInput) {
                    tagAdd(input: $input) {
                        """
                + self.properties
                + """
                    }
                }
            """
            )
            result = self.opencti.query(
                query,
                {
                    "input": {
                        "tag_type": tag_type,
                        "value": value,
                        "color": color,
                        "internal_id_key": id,
                    }
                },
            )
            return self.opencti.process_multiple_fields(result["data"]["tagAdd"])
        else:
            self.opencti.log(
                "error",
                "[opencti_tag] Missing parameters: tag_type and value and color",
            )

    """
        Create a Tag object only if it not exists, update it on request

        :param tag_type: the tag type
        :param value: the value
        :param color: the color
        :return Tag object
    """

    def create(self, **kwargs):
        tag_type = kwargs.get("tag_type", None)
        value = kwargs.get("value", None)
        color = kwargs.get("color", None)
        id = kwargs.get("id", None)

        object_result = self.read(filters=[{"key": "value", "values": [value]}])
        if object_result is not None:
            return object_result
        else:
            return self.create_raw(tag_type=tag_type, value=value, color=color, id=id)
