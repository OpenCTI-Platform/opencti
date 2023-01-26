# coding: utf-8

import json
import os
import uuid

import magic
from stix2.canonicalization.Canonicalize import canonicalize

from pycti.entities import LOGGER


class ExternalReference:
    def __init__(self, opencti, file):
        self.opencti = opencti
        self.file = file
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
            importFiles {
                edges {
                    node {
                        id
                        name
                        size
                        metaData {
                            mimetype
                            version
                        }
                    }
                }
            }
        """

    @staticmethod
    def generate_id(url=None, source_name=None, external_id=None):
        if url is not None:
            data = {"url": url}
        elif source_name is not None and external_id is not None:
            data = {"source_name": source_name, "external_id": external_id}
        else:
            return None
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "external-reference--" + id

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
        custom_attributes = kwargs.get("customAttributes", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)
        if get_all:
            first = 500

        LOGGER.info("Listing External-Reference with filters %s.", json.dumps(filters))
        query = (
            """
            query ExternalReferences($filters: [ExternalReferencesFiltering], $first: Int, $after: ID, $orderBy: ExternalReferencesOrdering, $orderMode: OrderingMode) {
                externalReferences(filters: $filters, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
            LOGGER.info("Reading External-Reference {%s}.", id)
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
            LOGGER.error(
                "[opencti_external_reference] Missing parameters: id or filters"
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
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        update = kwargs.get("update", False)

        if source_name is not None or url is not None:
            LOGGER.info("Creating External Reference {%s}.", source_name)
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
                        "x_opencti_stix_ids": x_opencti_stix_ids,
                        "update": update,
                    }
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["externalReferenceAdd"]
            )
        else:
            LOGGER.error(
                "[opencti_external_reference] Missing parameters: source_name and url"
            )

    """
        Upload a file in this External-Reference

        :param id: the Stix-Domain-Object id
        :param file_name
        :param data
        :return void
    """

    def add_file(self, **kwargs):
        id = kwargs.get("id", None)
        file_name = kwargs.get("file_name", None)
        data = kwargs.get("data", None)
        mime_type = kwargs.get("mime_type", "text/plain")
        if id is not None and file_name is not None:
            final_file_name = os.path.basename(file_name)
            query = """
                mutation ExternalReferenceEdit($id: ID!, $file: Upload!) {
                    externalReferenceEdit(id: $id) {
                        importPush(file: $file) {
                            id
                            name
                        }
                    }
                }
             """
            if data is None:
                data = open(file_name, "rb")
                if file_name.endswith(".json"):
                    mime_type = "application/json"
                else:
                    mime_type = magic.from_file(file_name, mime=True)
            LOGGER.info(
                "Uploading a file {%s} in Stix-Domain-Object {%s}.", final_file_name, id
            )
            return self.opencti.query(
                query,
                {"id": id, "file": (self.file(final_file_name, data, mime_type))},
            )
        else:
            LOGGER.error(
                "[opencti_stix_domain_object] Missing parameters: id or file_name"
            )
            return None

    """
        Update a External Reference object field

        :param id: the External Reference id
        :param input: the input of the field
        :return The updated External Reference object
    """

    def update_field(self, **kwargs):
        id = kwargs.get("id", None)
        input = kwargs.get("input", None)
        if id is not None and input is not None:
            LOGGER.info("Updating External-Reference {%s}.", id)
            query = """
                    mutation ExternalReferenceEdit($id: ID!, $input: [EditInput]!) {
                        externalReferenceEdit(id: $id) {
                            fieldPatch(input: $input) {
                                id
                            }
                        }
                    }
                """
            result = self.opencti.query(query, {"id": id, "input": input})
            return self.opencti.process_multiple_fields(
                result["data"]["externalReferenceEdit"]["fieldPatch"]
            )
        else:
            LOGGER.error(
                "[opencti_external_reference] Missing parameters: id and key and value"
            )
            return None

    def delete(self, id):
        LOGGER.info("Deleting External-Reference " + id + "...")
        query = """
             mutation ExternalReferenceEdit($id: ID!) {
                 externalReferenceEdit(id: $id) {
                     delete
                 }
             }
         """
        self.opencti.query(query, {"id": id})

    def list_files(self, **kwargs):
        id = kwargs.get("id", None)
        LOGGER.info("Listing files of External-Reference { " + id + " }")
        query = """
            query externalReference($id: String!) {
                externalReference(id: $id) {
                    importFiles {
                        edges {
                            node {
                                id
                                name
                                size
                                metaData {
                                    mimetype
                                    version
                                }
                            }
                        }
                    }
                }
            }
        """
        result = self.opencti.query(query, {"id": id})
        entity = self.opencti.process_multiple_fields(
            result["data"]["externalReference"]
        )
        return entity["importFiles"]
