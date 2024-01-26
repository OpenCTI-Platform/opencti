# coding: utf-8

import json
import uuid

from stix2.canonicalization.Canonicalize import canonicalize


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

    @staticmethod
    def generate_id(definition, definition_type):
        data = {"definition": definition, "definition_type": definition_type}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "marking-definition--" + id

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
        custom_attributes = kwargs.get("customAttributes", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)
        if get_all:
            first = 500

        self.opencti.app_logger.info(
            "Listing Marking-Definitions with filters", {"filters": json.dumps(filters)}
        )
        query = (
            """
            query MarkingDefinitions($filters: FilterGroup, $first: Int, $after: ID, $orderBy: MarkingDefinitionsOrdering, $orderMode: OrderingMode) {
                markingDefinitions(filters: $filters, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
            self.opencti.app_logger.info("Reading Marking-Definition", {"id": id})
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
            self.opencti.app_logger.error(
                "[opencti_marking_definition] Missing parameters: id or filters"
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
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        update = kwargs.get("update", False)

        if definition is not None and definition_type is not None:
            query = (
                """
                mutation MarkingDefinitionAdd($input: MarkingDefinitionAddInput!) {
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
                        "x_opencti_stix_ids": x_opencti_stix_ids,
                        "update": update,
                    }
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["markingDefinitionAdd"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_marking_definition] Missing parameters: definition and definition_type",
            )

    """
        Update a Marking definition object field

        :param id: the Marking definition id
        :param input: the input of the field
        :return The updated Marking definition object
    """

    def update_field(self, **kwargs):
        id = kwargs.get("id", None)
        input = kwargs.get("input", None)
        if id is not None and input is not None:
            self.opencti.app_logger.info("Updating Marking Definition", {"id": id})
            query = """
                    mutation MarkingDefinitionEdit($id: ID!, $input: [EditInput]!) {
                        markingDefinitionEdit(id: $id) {
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
                result["data"]["markingDefinitionEdit"]["fieldPatch"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_marking_definition] Missing parameters: id and key and value"
            )
            return None

    """
        Import an Marking Definition object from a STIX2 object

        :param stixObject: the MarkingDefinition
        :return MarkingDefinition object
    """

    def import_from_stix2(self, **kwargs):
        stix_object = kwargs.get("stixObject", None)
        update = kwargs.get("update", False)
        if stix_object is not None:
            if (
                "x_opencti_definition_type" in stix_object
                and "x_opencti_definition" in stix_object
            ):
                definition_type = stix_object["x_opencti_definition_type"]
                definition = stix_object["x_opencti_definition"]
            elif "definition_type" in stix_object:
                definition_type = stix_object["definition_type"]
                definition = None
                if stix_object["definition_type"] == "tlp":
                    definition_type = definition_type.upper()
                    if "definition" in stix_object:
                        definition = (
                            definition_type
                            + ":"
                            + stix_object["definition"]["tlp"].upper()
                        )
                    elif "name" in stix_object:
                        definition = stix_object["name"]
                else:
                    if "definition" in stix_object:
                        if isinstance(stix_object["definition"], str):
                            definition = stix_object["definition"]
                        elif (
                            isinstance(stix_object["definition"], dict)
                            and stix_object["definition_type"]
                            in stix_object["definition"]
                        ):
                            definition = stix_object["definition"][
                                stix_object["definition_type"]
                            ]
                        else:
                            definition = stix_object["name"]
                    elif "name" in stix_object:
                        definition = stix_object["name"]
            elif "name" in stix_object:
                if ":" in stix_object["name"]:
                    definition_type = stix_object["name"].split(":")[0]
                else:
                    definition_type = "statement"
                definition = stix_object["name"]
            else:
                return None

            # Replace TLP:WHITE
            if definition == "TLP:WHITE":
                definition = "TLP:CLEAR"

            # Search in extensions
            if (
                "x_opencti_order" not in stix_object
                and self.opencti.get_attribute_in_extension("order", stix_object)
                is not None
            ):
                stix_object["x_opencti_order"] = (
                    self.opencti.get_attribute_in_extension("order", stix_object)
                )
            if "x_opencti_color" not in stix_object:
                stix_object["x_opencti_color"] = (
                    self.opencti.get_attribute_in_extension("color", stix_object)
                )
            if "x_opencti_stix_ids" not in stix_object:
                stix_object["x_opencti_stix_ids"] = (
                    self.opencti.get_attribute_in_extension("stix_ids", stix_object)
                )

            return self.opencti.marking_definition.create(
                stix_id=stix_object["id"],
                created=stix_object["created"] if "created" in stix_object else None,
                modified=stix_object["modified"] if "modified" in stix_object else None,
                definition_type=definition_type,
                definition=definition,
                x_opencti_order=(
                    stix_object["x_opencti_order"]
                    if "x_opencti_order" in stix_object
                    else 0
                ),
                x_opencti_color=(
                    stix_object["x_opencti_color"]
                    if "x_opencti_color" in stix_object
                    else None
                ),
                x_opencti_stix_ids=(
                    stix_object["x_opencti_stix_ids"]
                    if "x_opencti_stix_ids" in stix_object
                    else None
                ),
                update=update,
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_marking_definition] Missing parameters: stixObject"
            )

    def delete(self, **kwargs):
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.app_logger.info("Deleting Marking-Definition", {"id": id})
            query = """
                 mutation MarkingDefinitionEdit($id: ID!) {
                     markingDefinitionEdit(id: $id) {
                         delete
                     }
                 }
             """
            self.opencti.query(query, {"id": id})
        else:
            self.opencti.app_logger.error(
                "[opencti_marking_definition] Missing parameters: id"
            )
            return None
