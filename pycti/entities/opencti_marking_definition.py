# coding: utf-8

import json


class MarkingDefinition:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            stix_id_key
            entity_type
            definition_type
            definition
            level
            color
            created
            modified
            created_at
            updated_at
        """

    """
        List Marking-Definition objects

        :param filters: the filters to apply
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Marking-Definition objects
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
            "info",
            "Listing Marking-Definitions with filters " + json.dumps(filters) + ".",
        )
        query = (
            """
            query MarkingDefinitions($filters: [MarkingDefinitionsFiltering], $first: Int, $after: ID, $orderBy: MarkingDefinitionsOrdering, $orderMode: OrderingMode) {
                markingDefinitions(filters: $filters, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
        return self.opencti.process_multiple(
            result["data"]["markingDefinitions"], with_pagination
        )

    """
        Read a Marking-Definition object

        :param id: the id of the Marking-Definition
        :param filters: the filters to apply if no id provided
        :return Marking-Definition object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        if id is not None:
            self.opencti.log("info", "Reading Marking-Definition {" + id + "}.")
            query = (
                """
                query MarkingDefinition($id: String!) {
                    markingDefinition(id: $id) {
                        """
                + self.properties
                + """
                    }
                }
            """
            )
            result = self.opencti.query(query, {"id": id})
            return self.opencti.process_multiple_fields(
                result["data"]["markingDefinition"]
            )
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.log(
                "error",
                "[opencti_marking_definition] Missing parameters: id or filters",
            )
            return None

    """
        Create a Marking-Definition object

        :param definition_type: the definition_type
        :param definition: the definition
        :return Marking-Definition object
    """

    def create_raw(self, **kwargs):
        definition_type = kwargs.get("definition_type", None)
        definition = kwargs.get("definition", None)
        level = kwargs.get("level", 0)
        color = kwargs.get("color", None)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)

        if definition is not None and definition_type is not None:
            query = (
                """
                mutation MarkingDefinitionAdd($input: MarkingDefinitionAddInput) {
                    markingDefinitionAdd(input: $input) {
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
                        "definition_type": definition_type,
                        "definition": definition,
                        "internal_id_key": id,
                        "level": level,
                        "color": color,
                        "stix_id_key": stix_id_key,
                        "created": created,
                        "modified": modified,
                    }
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["markingDefinitionAdd"]
            )
        else:
            self.opencti.log(
                "error",
                "[opencti_marking_definition] Missing parameters: definition and definition_type",
            )

    """
        Create a Marking-Definition object only if it not exists, update it on request

        :param definition_type: the definition_type
        :param definition: the definition
        :return Marking-Definition object
    """

    def create(self, **kwargs):
        definition_type = kwargs.get("definition_type", None)
        definition = kwargs.get("definition", None)
        level = kwargs.get("level", 0)
        color = kwargs.get("color", None)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)

        object_result = None
        if stix_id_key is not None:
            object_result = self.read(id=stix_id_key)
        if object_result is None:
            object_result = self.read(
                filters=[
                    {"key": "definition_type", "values": [definition_type]},
                    {"key": "definition", "values": [definition]},
                ]
            )
        if object_result is not None:
            return object_result
        else:
            return self.create_raw(
                definition_type=definition_type,
                definition=definition,
                level=level,
                color=color,
                id=id,
                stix_id_key=stix_id_key,
                created=created,
                modified=modified,
            )
