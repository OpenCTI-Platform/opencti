# coding: utf-8

import json


class ExternalReference:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            standard_id
            entity_type
            parent_types
            created_at
            updated_at
            created
            modified
            source_name
            description
            url
            hash
            external_id
        """

    """
        List External-Reference objects

        :param filters: the filters to apply
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of External-Reference objects
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
            "Listing External-Reference with filters " + json.dumps(filters) + ".",
        )
        query = (
            """
            query ExternalReferences($filters: [ExternalReferencesFiltering], $first: Int, $after: ID, $orderBy: ExternalReferencesOrdering, $orderMode: OrderingMode) {
                externalReferences(filters: $filters, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
            result["data"]["externalReferences"], with_pagination
        )

    """
        Read a External-Reference object

        :param id: the id of the External-Reference
        :param filters: the filters to apply if no id provided
        :return External-Reference object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        if id is not None:
            self.opencti.log("info", "Reading External-Reference {" + id + "}.")
            query = (
                """
                query ExternalReference($id: String!) {
                    externalReference(id: $id) {
                        """
                + self.properties
                + """
                    }
                }
            """
            )
            result = self.opencti.query(query, {"id": id})
            return self.opencti.process_multiple_fields(
                result["data"]["externalReference"]
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
                "[opencti_external_reference] Missing parameters: id or filters",
            )
            return None

    """
        Create a External Reference object

        :param source_name: the source_name of the External Reference
        :return External Reference object
    """

    def create(self, **kwargs):
        stix_id = kwargs.get("stix_id", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        source_name = kwargs.get("source_name", None)
        url = kwargs.get("url", None)
        external_id = kwargs.get("external_id", None)
        description = kwargs.get("description", None)
        update = kwargs.get("update", False)

        if source_name is not None and url is not None:
            self.opencti.log(
                "info", "Creating External Reference {" + source_name + "}."
            )
            query = (
                """
                mutation ExternalReferenceAdd($input: ExternalReferenceAddInput) {
                    externalReferenceAdd(input: $input) {
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
                        "created": created,
                        "modified": modified,
                        "source_name": source_name,
                        "external_id": external_id,
                        "description": description,
                        "url": url,
                        "update": update,
                    }
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["externalReferenceAdd"]
            )
        else:
            self.opencti.log(
                "error",
                "[opencti_external_reference] Missing parameters: source_name and url",
            )

    """
        Update a External Reference object field

        :param id: the External Reference id
        :param key: the key of the field
        :param value: the value of the field
        :return The updated External Reference object
    """

    def update_field(self, **kwargs):
        id = kwargs.get("id", None)
        key = kwargs.get("key", None)
        value = kwargs.get("value", None)
        if id is not None and key is not None and value is not None:
            self.opencti.log(
                "info", "Updating External-Reference {" + id + "} field {" + key + "}."
            )
            query = """
                    mutation ExternalReferenceEdit($id: ID!, $input: EditInput!) {
                        externalReferenceEdit(id: $id) {
                            fieldPatch(input: $input) {
                                id
                            }
                        }
                    }
                """
            result = self.opencti.query(
                query, {"id": id, "input": {"key": key, "value": value}}
            )
            return self.opencti.process_multiple_fields(
                result["data"]["externalReferenceEdit"]["fieldPatch"]
            )
        else:
            self.opencti.log(
                "error",
                "[opencti_external_reference] Missing parameters: id and key and value",
            )
            return None

    def delete(self, id):
        self.opencti.log("info", "Deleting External-Reference " + id + "...")
        query = """
             mutation ExternalReferenceEdit($id: ID!) {
                 externalReferenceEdit(id: $id) {
                     delete
                 }
             }
         """
        self.opencti.query(query, {"id": id})
