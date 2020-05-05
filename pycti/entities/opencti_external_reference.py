# coding: utf-8

import json


class ExternalReference:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            entity_type
            stix_id_key
            source_name
            description
            url
            hash
            external_id
            created
            modified
            created_at
            updated_at
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

    def create_raw(self, **kwargs):
        source_name = kwargs.get("source_name", None)
        url = kwargs.get("url", None)
        external_id = kwargs.get("external_id", None)
        description = kwargs.get("description", None)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)

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
                        "source_name": source_name,
                        "external_id": external_id,
                        "description": description,
                        "url": url,
                        "internal_id_key": id,
                        "stix_id_key": stix_id_key,
                        "created": created,
                        "modified": modified,
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
        Create a External Reference object only if it not exists, update it on request

        :param name: the name of the External Reference
        :return External Reference object
    """

    def create(self, **kwargs):
        source_name = kwargs.get("source_name", None)
        url = kwargs.get("url", None)
        external_id = kwargs.get("external_id", None)
        description = kwargs.get("description", None)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)

        external_reference_result = self.read(filters=[{"key": "url", "values": [url]}])
        if external_reference_result is not None:
            return external_reference_result
        else:
            return self.create_raw(
                source_name=source_name,
                url=url,
                external_id=external_id,
                description=description,
                id=id,
                stix_id_key=stix_id_key,
                created=created,
                modified=modified,
            )
