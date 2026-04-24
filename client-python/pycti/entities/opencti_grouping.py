# coding: utf-8

import datetime
import uuid

from stix2.canonicalization.Canonicalize import canonicalize

from .base import Entity
from .mixins import ListFilesMixin, ListObjectsMixin, StixObjectOrRelationshipMixin


class Grouping(ListObjectsMixin, ListFilesMixin, StixObjectOrRelationshipMixin, Entity):
    """Main Grouping class for OpenCTI

    Manages STIX grouping objects in the OpenCTI platform.
    """

    PROPERTIES = """
        id
        standard_id
        entity_type
        parent_types
        spec_version
        created_at
        updated_at
        status {
            id
            template {
              id
              name
              color
            }
        }
        createdBy {
            ... on Identity {
                id
                standard_id
                entity_type
                parent_types
                spec_version
                identity_class
                name
                description
                roles
                contact_information
                x_opencti_aliases
                created
                modified
                objectLabel {
                    id
                    value
                    color
                }
            }
            ... on Organization {
                x_opencti_organization_type
                x_opencti_reliability
            }
            ... on Individual {
                x_opencti_firstname
                x_opencti_lastname
            }
        }
        objectOrganization {
            id
            standard_id
            name
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
        objectLabel {
            id
            value
            color
        }
        externalReferences {
            edges {
                node {
                    id
                    standard_id
                    entity_type
                    source_name
                    description
                    url
                    hash
                    external_id
                    created
                    modified
                }
            }
        }
        revoked
        confidence
        created
        modified
        name
        description
        context
        x_opencti_aliases
    """

    OBJECTS_PROPERTIES = """
        ... on BasicObject {
            id
            entity_type
            parent_types
        }
        ... on BasicRelationship {
            id
            entity_type
            parent_types
        }
        ... on StixObject {
            standard_id
            spec_version
            created_at
            updated_at
        }
        ... on AttackPattern {
            name
        }
        ... on Campaign {
            name
        }
        ... on CourseOfAction {
            name
        }
        ... on Individual {
            name
        }
        ... on Organization {
            name
        }
        ... on Sector {
            name
        }
        ... on System {
            name
        }
        ... on Indicator {
            name
        }
        ... on Infrastructure {
            name
        }
        ... on IntrusionSet {
            name
        }
        ... on Position {
            name
        }
        ... on City {
            name
        }
        ... on Country {
            name
        }
        ... on Region {
            name
        }
        ... on Malware {
            name
        }
        ... on ThreatActor {
            name
        }
        ... on Tool {
            name
        }
        ... on Vulnerability {
            name
        }
        ... on Incident {
            name
        }
        ... on StixCyberObservable {
            observable_value
        }
        ... on StixCoreRelationship {
            standard_id
            spec_version
            created_at
            updated_at
            relationship_type
        }
        ... on StixSightingRelationship {
            standard_id
            spec_version
            created_at
            updated_at
        }
        ... on ObservedData {
            id
            entity_type
            first_observed
            last_observed
            number_observed
            objects(all: true) {
                edges {
                    node {
                        ... on BasicObject {
                            id
                            entity_type
                            parent_types
                        }
                        ... on BasicRelationship {
                            id
                            entity_type
                            parent_types
                        }
                        ... on StixObject {
                            standard_id
                            spec_version
                            created_at
                            updated_at
                        }
                        ... on StixCyberObservable {
                            observable_value
                        }
                    }
                }
            }
        }
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

    OVERRIDES = {
        "queries": {
            "relation_add": "groupingRelationAdd(id: $id, input: $input) { id }",
            "relation_delete": (
                "groupingRelationDelete(id: $id, toId: $toId, relationship_type: $relationship_type) { id }"
            ),
        }
    }

    @staticmethod
    def generate_id(name, context, created=None):
        """Generate a STIX ID for a Grouping.

        :param name: The name of the grouping
        :type name: str
        :param context: The grouping context
        :type context: str
        :param created: Optional creation date
        :type created: datetime or str or None
        :return: STIX ID for the grouping
        :rtype: str
        """
        name = name.lower().strip()
        context = context.lower().strip()
        if isinstance(created, datetime.datetime):
            created = created.isoformat()
        if created is None:
            data = {"name": name, "context": context}
        else:
            data = {"name": name, "context": context, "created": created}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "grouping--" + id

    @staticmethod
    def generate_id_from_data(data):
        """Generate a STIX ID from grouping data.

        :param data: Dictionary containing 'name', 'context', and 'created' keys
        :type data: dict
        :return: STIX ID for the grouping
        :rtype: str
        """
        return Grouping.generate_id(data["name"], data["context"], data["created"])

    def get_by_stix_id_or_name(self, **kwargs):
        """Read a Grouping object by stix_id or name.

        :param stix_id: the STIX ID of the Grouping
        :type stix_id: str
        :param name: the name of the Grouping
        :type name: str
        :param context: the context of the Grouping
        :type context: str
        :param customAttributes: custom attributes to return
        :type customAttributes: list
        :return: Grouping object
        :rtype: dict or None
        """
        stix_id = kwargs.get("stix_id", None)
        name = kwargs.get("name", None)
        context = kwargs.get("context", None)
        custom_attributes = kwargs.get("customAttributes", None)
        object_result = None
        if stix_id is not None:
            object_result = self.read(id=stix_id, customAttributes=custom_attributes)
        if object_result is None and name is not None and context is not None:
            object_result = self.read(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "name", "values": [name]},
                        {"key": "context", "values": [context]},
                    ],
                    "filterGroups": [],
                },
                customAttributes=custom_attributes,
            )
        return object_result

    def create(self, **kwargs):
        """Create a Grouping object.

        :param stix_id: (optional) the STIX ID
        :type stix_id: str
        :param createdBy: (optional) the author ID
        :type createdBy: str
        :param objects: (optional) list of STIX object IDs
        :type objects: list
        :param objectMarking: (optional) list of marking definition IDs
        :type objectMarking: list
        :param objectLabel: (optional) list of label IDs
        :type objectLabel: list
        :param externalReferences: (optional) list of external reference IDs
        :type externalReferences: list
        :param revoked: (optional) whether the grouping is revoked
        :type revoked: bool
        :param confidence: (optional) confidence level (0-100)
        :type confidence: int
        :param lang: (optional) language
        :type lang: str
        :param created: (optional) creation date
        :type created: datetime
        :param modified: (optional) modification date
        :type modified: datetime
        :param name: the name of the Grouping (required)
        :type name: str
        :param context: the grouping context (required)
        :type context: str
        :param content: (optional) content
        :type content: str
        :param description: (optional) description
        :type description: str
        :param x_opencti_aliases: (optional) list of aliases
        :type x_opencti_aliases: list
        :param x_opencti_stix_ids: (optional) list of additional STIX IDs
        :type x_opencti_stix_ids: list
        :param objectOrganization: (optional) list of organization IDs
        :type objectOrganization: list
        :param x_opencti_workflow_id: (optional) workflow ID
        :type x_opencti_workflow_id: str
        :param x_opencti_modified_at: (optional) custom modification date
        :type x_opencti_modified_at: datetime
        :param update: (optional) whether to update if exists (default: False)
        :type update: bool
        :param files: (optional) list of File objects to attach
        :type files: list
        :param filesMarkings: (optional) list of lists of marking definition IDs for each file
        :type filesMarkings: list
        :return: Grouping object
        :rtype: dict or None
        """
        stix_id = kwargs.get("stix_id", None)
        created_by = kwargs.get("createdBy", None)
        objects = kwargs.get("objects", None)
        object_marking = kwargs.get("objectMarking", None)
        object_label = kwargs.get("objectLabel", None)
        external_references = kwargs.get("externalReferences", None)
        revoked = kwargs.get("revoked", None)
        confidence = kwargs.get("confidence", None)
        lang = kwargs.get("lang", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        name = kwargs.get("name", None)
        context = kwargs.get("context", None)
        content = kwargs.get("content", None)
        description = kwargs.get("description", None)
        x_opencti_aliases = kwargs.get("x_opencti_aliases", None)
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        granted_refs = kwargs.get("objectOrganization", None)
        x_opencti_workflow_id = kwargs.get("x_opencti_workflow_id", None)
        x_opencti_modified_at = kwargs.get("x_opencti_modified_at", None)
        update = kwargs.get("update", False)
        files = kwargs.get("files", None)
        files_markings = kwargs.get("filesMarkings", None)
        no_trigger_import = kwargs.get("noTriggerImport", None)
        embedded = kwargs.get("embedded", None)
        upsert_operations = kwargs.get("upsert_operations", None)

        if name is not None and context is not None:
            self.opencti.app_logger.info("Creating Grouping", {"name": name})
            query = """
                mutation GroupingAdd($input: GroupingAddInput!) {
                    groupingAdd(input: $input) {
                        id
                        standard_id
                        entity_type
                        parent_types
                    }
                }
            """
            input_variables = {
                "stix_id": stix_id,
                "createdBy": created_by,
                "objectMarking": object_marking,
                "objectLabel": object_label,
                "objectOrganization": granted_refs,
                "objects": objects,
                "externalReferences": external_references,
                "revoked": revoked,
                "confidence": confidence,
                "lang": lang,
                "created": created,
                "modified": modified,
                "name": name,
                "context": context,
                "content": content,
                "description": description,
                "x_opencti_aliases": x_opencti_aliases,
                "x_opencti_stix_ids": x_opencti_stix_ids,
                "x_opencti_workflow_id": x_opencti_workflow_id,
                "x_opencti_modified_at": x_opencti_modified_at,
                "update": update,
                "files": files,
                "filesMarkings": files_markings,
                "noTriggerImport": no_trigger_import,
                "embedded": embedded,
                "upsertOperations": upsert_operations,
            }
            result = self.opencti.query(query, {"input": input_variables})
            return self.opencti.process_multiple_fields(result["data"]["groupingAdd"])
        else:
            self.opencti.app_logger.error(
                "[opencti_grouping] Missing parameters: name and context"
            )
            return None

    def import_from_stix2(self, **kwargs):
        """Import a Grouping object from a STIX2 object.

        :param stixObject: the Stix-Object Grouping
        :type stixObject: dict
        :param extras: extra dict
        :type extras: dict
        :param update: set the update flag on import
        :type update: bool
        :return: Grouping object
        :rtype: dict or None
        """
        stix_object = kwargs.get("stixObject", None)
        extras = kwargs.get("extras", {})
        update = kwargs.get("update", False)
        if stix_object is not None:
            # Search in extensions
            if "x_opencti_aliases" not in stix_object:
                stix_object[
                    "x_opencti_aliases"
                ] = self.opencti.get_attribute_in_extension("aliases", stix_object)
            if "x_opencti_stix_ids" not in stix_object:
                stix_object[
                    "x_opencti_stix_ids"
                ] = self.opencti.get_attribute_in_extension("stix_ids", stix_object)
            if "x_opencti_granted_refs" not in stix_object:
                stix_object[
                    "x_opencti_granted_refs"
                ] = self.opencti.get_attribute_in_extension("granted_refs", stix_object)
            if "x_opencti_content" not in stix_object or "content" not in stix_object:
                stix_object["content"] = self.opencti.get_attribute_in_extension(
                    "content", stix_object
                )
            if "x_opencti_content" in stix_object:
                stix_object["content"] = stix_object["x_opencti_content"]

            if "x_opencti_workflow_id" not in stix_object:
                stix_object[
                    "x_opencti_workflow_id"
                ] = self.opencti.get_attribute_in_extension("workflow_id", stix_object)
            if "x_opencti_modified_at" not in stix_object:
                stix_object[
                    "x_opencti_modified_at"
                ] = self.opencti.get_attribute_in_extension("modified_at", stix_object)
            if "opencti_upsert_operations" not in stix_object:
                stix_object[
                    "opencti_upsert_operations"
                ] = self.opencti.get_attribute_in_extension(
                    "opencti_upsert_operations", stix_object
                )
            return self.create(
                stix_id=stix_object["id"],
                createdBy=(
                    extras["created_by_id"] if "created_by_id" in extras else None
                ),
                objectMarking=(
                    extras["object_marking_ids"]
                    if "object_marking_ids" in extras
                    else None
                ),
                objectLabel=(
                    extras["object_label_ids"] if "object_label_ids" in extras else None
                ),
                objects=extras["object_ids"] if "object_ids" in extras else [],
                externalReferences=(
                    extras["external_references_ids"]
                    if "external_references_ids" in extras
                    else None
                ),
                content=(
                    self.opencti.stix2.convert_markdown(stix_object["content"])
                    if "content" in stix_object
                    else None
                ),
                revoked=stix_object["revoked"] if "revoked" in stix_object else None,
                confidence=(
                    stix_object["confidence"] if "confidence" in stix_object else None
                ),
                lang=stix_object["lang"] if "lang" in stix_object else None,
                created=stix_object["created"] if "created" in stix_object else None,
                modified=stix_object["modified"] if "modified" in stix_object else None,
                name=stix_object["name"],
                context=stix_object["context"],
                description=(
                    self.opencti.stix2.convert_markdown(stix_object["description"])
                    if "description" in stix_object
                    else None
                ),
                x_opencti_stix_ids=(
                    stix_object["x_opencti_stix_ids"]
                    if "x_opencti_stix_ids" in stix_object
                    else None
                ),
                objectOrganization=(
                    stix_object["x_opencti_granted_refs"]
                    if "x_opencti_granted_refs" in stix_object
                    else None
                ),
                x_opencti_aliases=self.opencti.stix2.pick_aliases(stix_object),
                x_opencti_workflow_id=(
                    stix_object["x_opencti_workflow_id"]
                    if "x_opencti_workflow_id" in stix_object
                    else None
                ),
                x_opencti_modified_at=(
                    stix_object["x_opencti_modified_at"]
                    if "x_opencti_modified_at" in stix_object
                    else None
                ),
                update=update,
                files=extras.get("files"),
                filesMarkings=extras.get("filesMarkings"),
                noTriggerImport=extras.get("noTriggerImport", None),
                embedded=extras.get("embedded", None),
                upsert_operations=(
                    stix_object["opencti_upsert_operations"]
                    if "opencti_upsert_operations" in stix_object
                    else None
                ),
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_grouping] Missing parameters: stixObject"
            )
            return None
