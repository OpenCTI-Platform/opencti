# coding: utf-8

import json


class MarkingDefinition:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            standard_id
            entity_type
            parent_types
            definition_type
            definition
            x_opencti_order
            x_opencti_color
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

    def create(self, **kwargs):
        stix_id = kwargs.get("stix_id", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        definition_type = kwargs.get("definition_type", None)
        definition = kwargs.get("definition", None)
        x_opencti_order = kwargs.get("x_opencti_order", 0)
        x_opencti_color = kwargs.get("x_opencti_color", None)
        update = kwargs.get("update", False)

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
                        "x_opencti_order": x_opencti_order,
                        "x_opencti_color": x_opencti_color,
                        "stix_id": stix_id,
                        "created": created,
                        "modified": modified,
                        "update": update,
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
        Import an Marking Definition object from a STIX2 object

        :param stixObject: the MarkingDefinition
        :return MarkingDefinition object
    """

    def import_from_stix2(self, **kwargs):
        stix_object = kwargs.get("stixObject", None)
        if stix_object is not None:
            definition_type = stix_object["definition_type"]
            definition = stix_object["definition"][stix_object["definition_type"]]
            if stix_object["definition_type"] == "tlp":
                definition_type = definition_type.upper()
                definition = (
                    definition_type + ":" + stix_object["definition"]["tlp"].upper()
                )

            # TODO: Compatibility with OpenCTI 3.X to be REMOVED
            if "x_opencti_order" not in stix_object:
                stix_object["x_opencti_order"] = (
                    stix_object["x_opencti_level"]
                    if "x_opencti_level" in stix_object
                    else 0
                )

            return self.opencti.marking_definition.create(
                stix_id=stix_object["id"],
                created=stix_object["created"] if "created" in stix_object else None,
                modified=stix_object["modified"] if "modified" in stix_object else None,
                definition_type=definition_type,
                definition=definition,
                x_opencti_order=stix_object["x_opencti_order"]
                if "x_opencti_order" in stix_object
                else 0,
                x_opencti_color=stix_object["x_opencti_color"]
                if "x_opencti_color" in stix_object
                else None,
            )
        else:
            self.opencti.log(
                "error", "[opencti_marking_definition] Missing parameters: stixObject"
            )
