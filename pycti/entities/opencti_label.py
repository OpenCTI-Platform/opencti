# coding: utf-8

import json


class Label:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            value
            color
            created_at
            updated_at
        """

    """
        List Label objects

        :param filters: the filters to apply
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Label objects
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
            "info", "Listing Labels with filters " + json.dumps(filters) + "."
        )
        query = (
            """
            query Labels($filters: [LabelsFiltering], $first: Int, $after: ID, $orderBy: LabelsOrdering, $orderMode: OrderingMode) {
                labels(filters: $filters, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
        return self.opencti.process_multiple(result["data"]["labels"], with_pagination)

    """
        Read a Label object

        :param id: the id of the Label
        :param filters: the filters to apply if no id provided
        :return Label object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        if id is not None:
            self.opencti.log("info", "Reading label {" + id + "}.")
            query = (
                """
                query Label($id: String!) {
                    label(id: $id) {
                        """
                + self.properties
                + """
                    }
                }
            """
            )
            result = self.opencti.query(query, {"id": id})
            return self.opencti.process_multiple_fields(result["data"]["label"])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.log(
                "error", "[opencti_label] Missing parameters: id or filters"
            )
            return None

    """
        Create a Label object

        :param value: the value
        :param color: the color
        :return label object
    """

    def create(self, **kwargs):
        stix_id = kwargs.get("stix_id", None)
        value = kwargs.get("value", None)
        color = kwargs.get("color", None)

        if value is not None:
            query = (
                """
                mutation LabelAdd($input: LabelAddInput) {
                    labelAdd(input: $input) {
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
                        "stix_id": stix_id,
                        "value": value,
                        "color": color,
                    }
                },
            )
            return self.opencti.process_multiple_fields(result["data"]["labelAdd"])
        else:
            self.opencti.log(
                "error",
                "[opencti_label] Missing parameters: value",
            )

    """
        Update a Label object field

        :param id: the Label id
        :param key: the key of the field
        :param value: the value of the field
        :return The updated Label object
    """

    def update_field(self, **kwargs):
        id = kwargs.get("id", None)
        key = kwargs.get("key", None)
        value = kwargs.get("value", None)
        operation = kwargs.get("operation", "replace")
        if isinstance(value, list):
            value = [str(v) for v in value]
        else:
            value = str(value)
        if id is not None and key is not None and value is not None:
            self.opencti.log(
                "info", "Updating Label {" + id + "} field {" + key + "}."
            )
            query = """
                    mutation LabelEdit($id: ID!, $input: EditInput!, $operation: EditOperation) {
                        labelEdit(id: $id) {
                            fieldPatch(input: $input, operation: $operation) {
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
                    "input": {"key": key, "value": value},
                    "operation": operation,
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["labelEdit"]["fieldPatch"]
            )
        else:
            self.opencti.log(
                "error",
                "[opencti_label] Missing parameters: id and key and value",
            )
            return None