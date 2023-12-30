# coding: utf-8

import json
import uuid

from stix2.canonicalization.Canonicalize import canonicalize


class Label:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            value
            color
            created_at
            updated_at
            standard_id
        """

    @staticmethod
    def generate_id(value):
        data = {"value": value}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "label--" + id

    """
        List Label objects

        :param filters: the filters to apply
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Label objects
    """

    def list(self, **kwargs):
        filters = kwargs.get("filters", None)
        search = kwargs.get("search", None)
        first = kwargs.get("first", 500)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        custom_attributes = kwargs.get("customAttributes", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)
        if get_all:
            first = 100

        self.opencti.app_logger.info(
            "Listing Labels with filters", {"filters": json.dumps(filters)}
        )
        query = (
            """
            query Labels($filters: FilterGroup, $search: String, $first: Int, $after: ID, $orderBy: LabelsOrdering, $orderMode: OrderingMode) {
                labels(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
                "filters": filters,
                "search": search,
                "first": first,
                "after": after,
                "orderBy": order_by,
                "orderMode": order_mode,
            },
        )
        if get_all:
            final_data = []
            data = self.opencti.process_multiple(result["data"]["labels"])
            final_data = final_data + data
            while result["data"]["labels"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["labels"]["pageInfo"]["endCursor"]
                self.opencti.app_logger.info("Listing Labels", {"after": after})
                result = self.opencti.query(
                    query,
                    {
                        "filters": filters,
                        "search": search,
                        "first": first,
                        "after": after,
                        "orderBy": order_by,
                        "orderMode": order_mode,
                    },
                )
                data = self.opencti.process_multiple(result["data"]["labels"])
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["labels"], with_pagination
            )

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
            self.opencti.app_logger.info("Reading label", {"id": id})
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
            self.opencti.app_logger.error(
                "[opencti_label] Missing parameters: id or filters"
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
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        update = kwargs.get("update", False)

        if value is not None:
            self.opencti.app_logger.info("Creating Label", {"value": value})
            query = (
                """
                mutation LabelAdd($input: LabelAddInput!) {
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
                        "x_opencti_stix_ids": x_opencti_stix_ids,
                        "update": update,
                    }
                },
            )
            return self.opencti.process_multiple_fields(result["data"]["labelAdd"])
        else:
            self.opencti.app_logger.error("[opencti_label] Missing parameters: value")

    """
        Read or create a Label
        If the user has no rights to create the label, return None
        :return The available or created Label object
    """

    def read_or_create_unchecked(self, **kwargs):
        value = kwargs.get("value", None)
        label = self.read(
            filters={
                "mode": "and",
                "filters": [{"key": "value", "values": [value]}],
                "filterGroups": [],
            }
        )
        if label is None:
            try:
                return self.create(**kwargs)
            except ValueError:
                return None
        return label

    """
        Update a Label object field

        :param id: the Label id
        :param input: the input of the field
        :return The updated Label object
    """

    def update_field(self, **kwargs):
        id = kwargs.get("id", None)
        input = kwargs.get("input", None)
        if id is not None and input is not None:
            self.opencti.app_logger.info("Updating Label", {"id": id})
            query = """
                    mutation LabelEdit($id: ID!, $input: [EditInput]!) {
                        labelEdit(id: $id) {
                            fieldPatch(input: $input) {
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
                    "input": input,
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["labelEdit"]["fieldPatch"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_label] Missing parameters: id and key and value"
            )
            return None

    def delete(self, **kwargs):
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.app_logger.info("Deleting Label", {"id": id})
            query = """
                 mutation LabelEdit($id: ID!) {
                     labelEdit(id: $id) {
                         delete
                     }
                 }
             """
            self.opencti.query(query, {"id": id})
        else:
            self.opencti.app_logger.error("[opencti_label] Missing parameters: id")
            return None
