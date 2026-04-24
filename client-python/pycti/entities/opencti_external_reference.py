# coding: utf-8

import os
import uuid

import magic
from stix2.canonicalization.Canonicalize import canonicalize

from pycti.entities import mixins
from pycti.entities.base import Entity


class ExternalReference(mixins.ListFilesMixin, Entity):
    """Main ExternalReference class for OpenCTI

    Manages external references and citations in the OpenCTI platform.
    """

    PROPERTIES = """
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

    FILES_PROPERTIES = """
        id
        name
        size
        metaData {
            mimetype
            version
        }
        objectMarking {
            id
            standard_id
            entity_type
            definition_type
            definition
            created
            modified
            x_opencti_order
            x_opencti_color
        }
    """

    @staticmethod
    def generate_id(url=None, source_name=None, external_id=None):
        """Generate a STIX ID for an External Reference.

        :param url: The URL of the external reference
        :type url: str or None
        :param source_name: The source name
        :type source_name: str or None
        :param external_id: The external ID
        :type external_id: str or None
        :return: STIX ID for the external reference, or None if insufficient parameters
        :rtype: str or None
        """
        if url is not None:
            data = {"url": url}
        elif source_name is not None and external_id is not None:
            data = {"source_name": source_name, "external_id": external_id}
        else:
            return None
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "external-reference--" + id

    @staticmethod
    def generate_id_from_data(data):
        """Generate a STIX ID from external reference data.

        :param data: Dictionary containing 'url', 'source_name', or 'external_id' keys
        :type data: dict
        :return: STIX ID for the external reference
        :rtype: str or None
        """
        return ExternalReference.generate_id(
            data.get("url"), data.get("source_name"), data.get("external_id")
        )

    def create(self, **kwargs):
        """Create an External Reference object.

        :param stix_id: (optional) the STIX ID
        :type stix_id: str
        :param created: (optional) creation date
        :type created: datetime
        :param modified: (optional) modification date
        :type modified: datetime
        :param source_name: the source name of the External Reference (required if no url)
        :type source_name: str
        :param url: (optional) the URL of the external reference (required if no source_name)
        :type url: str
        :param external_id: (optional) the external ID
        :type external_id: str
        :param description: (optional) description
        :type description: str
        :param x_opencti_stix_ids: (optional) list of additional STIX IDs
        :type x_opencti_stix_ids: list
        :param update: (optional) whether to update if exists (default: False)
        :type update: bool
        :param files: (optional) list of File objects to attach
        :type files: list
        :param filesMarkings: (optional) list of lists of marking definition IDs for each file
        :type filesMarkings: list
        :return: External Reference object
        :rtype: dict or None
        """
        stix_id = kwargs.get("stix_id", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        source_name = kwargs.get("source_name", None)
        url = kwargs.get("url", None)
        external_id = kwargs.get("external_id", None)
        description = kwargs.get("description", None)
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        update = kwargs.get("update", False)
        files = kwargs.get("files", None)
        files_markings = kwargs.get("filesMarkings", None)
        no_trigger_import = kwargs.get("noTriggerImport", None)
        embedded = kwargs.get("embedded", None)

        if source_name is not None or url is not None:
            self.opencti.app_logger.info(
                "Creating External Reference", {"source_name": source_name}
            )
            query = (
                """
                mutation ExternalReferenceAdd($input: ExternalReferenceAddInput!) {
                    externalReferenceAdd(input: $input) {
                        """
                + self.properties
                + """
                    }
                }
            """
            )
            input_variables = {
                "stix_id": stix_id,
                "created": created,
                "modified": modified,
                "source_name": source_name,
                "external_id": external_id,
                "description": description,
                "url": url,
                "x_opencti_stix_ids": x_opencti_stix_ids,
                "update": update,
                "files": files,
                "filesMarkings": files_markings,
                "noTriggerImport": no_trigger_import,
                "embedded": embedded,
            }
            result = self.opencti.query(query, {"input": input_variables})
            return self.opencti.process_multiple_fields(
                result["data"]["externalReferenceAdd"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_external_reference] Missing parameters: source_name and url"
            )
            return None

    def add_file(self, **kwargs):
        """Upload a file in this External-Reference.

        :param id: the External-Reference id
        :type id: str
        :param file_name: the name of the file to upload
        :type file_name: str
        :param data: the file data (if None, reads from file_name path)
        :type data: bytes or None
        :param version: (optional) the file version date
        :type version: datetime
        :param fileMarkings: (optional) list of marking definition IDs for the file
        :type fileMarkings: list
        :param mime_type: (optional) MIME type (default: text/plain)
        :type mime_type: str
        :param no_trigger_import: (optional) don't trigger import (default: False)
        :type no_trigger_import: bool
        :param embedded: (optional) embed the file (default: False)
        :type embedded: bool
        :return: File upload result
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        file_name = kwargs.get("file_name", None)
        data = kwargs.get("data", None)
        version = kwargs.get("version", None)
        file_markings = kwargs.get("fileMarkings", None)
        mime_type = kwargs.get("mime_type", "text/plain")
        no_trigger_import = kwargs.get("no_trigger_import", False)
        embedded = kwargs.get("embedded", False)
        if id is not None and file_name is not None:
            final_file_name = os.path.basename(file_name)
            query = """
                mutation ExternalReferenceEdit($id: ID!, $file: Upload!, $fileMarkings: [String], $version: DateTime, $noTriggerImport: Boolean, $embedded: Boolean) {
                    externalReferenceEdit(id: $id) {
                        importPush(file: $file, fileMarkings: $fileMarkings, version: $version, noTriggerImport: $noTriggerImport, embedded: $embedded) {
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
            self.opencti.app_logger.info(
                "Uploading a file in External-Reference",
                {"file": final_file_name, "id": id},
            )
            return self.opencti.query(
                query,
                {
                    "id": id,
                    "file": (self.opencti.file(final_file_name, data, mime_type)),
                    "fileMarkings": file_markings,
                    "version": version,
                    "noTriggerImport": (
                        no_trigger_import
                        if isinstance(no_trigger_import, bool)
                        else no_trigger_import == "True"
                    ),
                    "embedded": embedded,
                },
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_external_reference] Missing parameters: id or file_name"
            )
            return None

    def update_field(self, **kwargs):
        """Update an External Reference object field.

        :param id: the External Reference id
        :type id: str
        :param input: the input of the field
        :type input: list
        :return: The updated External Reference object
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        input = kwargs.get("input", None)
        if id is not None and input is not None:
            self.opencti.app_logger.info("Updating External-Reference", {"id": id})
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
            self.opencti.app_logger.error(
                "[opencti_external_reference] Missing parameters: id and key and value"
            )
            return None

    def delete(self, id):
        """Delete an External-Reference object.

        :param id: the id of the External-Reference to delete
        :type id: str
        :return: None
        """
        self.opencti.app_logger.info("Deleting External-Reference", {"id": id})
        query = """
             mutation ExternalReferenceEdit($id: ID!) {
                 externalReferenceEdit(id: $id) {
                     delete
                 }
             }
         """
        self.opencti.query(query, {"id": id})
