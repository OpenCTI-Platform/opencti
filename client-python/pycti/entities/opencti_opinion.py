# coding: utf-8

import datetime
import uuid

from stix2.canonicalization.Canonicalize import canonicalize

from pycti.entities.base import Entity
from pycti.entities.mixins import (
    ListFilesMixin,
    ListObjectsMixin,
    StixObjectOrRelationshipMixin,
)


class Opinion(ListObjectsMixin, ListFilesMixin, StixObjectOrRelationshipMixin, Entity):
    """Main Opinion class for OpenCTI

    Manages analyst opinions and assessments in the OpenCTI platform.
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
        }
        revoked
        confidence
        created
        modified
        explanation
        authors
        opinion
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
        ... on Case {
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
            "relation_add": "opinionEdit(id: $id) { relationAdd(input: $input) { id } }",
            "relation_delete": (
                "opinionEdit(id: $id) { relationDelete(toId: $toId, relationship_type: $relationship_type) { id } }"
            ),
        },
    }

    @staticmethod
    def generate_id(created, opinion):
        """Generate a STIX ID for an Opinion.

        :param created: The creation date of the opinion
        :type created: datetime or str or None
        :param opinion: The opinion value (required)
        :type opinion: str
        :return: STIX ID for the opinion
        :rtype: str
        :raises ValueError: If opinion is None
        """
        if opinion is None:
            raise ValueError("opinion is required")
        if created is not None:
            if isinstance(created, datetime.datetime):
                created = created.isoformat()
            data = {"opinion": opinion.strip(), "created": created}
        else:
            data = {"opinion": opinion.strip()}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "opinion--" + id

    @staticmethod
    def generate_id_from_data(data):
        """Generate a STIX ID from opinion data.

        :param data: Dictionary containing 'opinion' and optionally 'created' keys
        :type data: dict
        :return: STIX ID for the opinion
        :rtype: str
        """
        return Opinion.generate_id(data.get("created"), data["opinion"])

    def create(self, **kwargs):
        """Create an Opinion object.

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
        :param revoked: (optional) whether the opinion is revoked
        :type revoked: bool
        :param confidence: (optional) confidence level (0-100)
        :type confidence: int
        :param lang: (optional) language
        :type lang: str
        :param created: (optional) creation date
        :type created: datetime
        :param modified: (optional) modification date
        :type modified: datetime
        :param explanation: (optional) explanation text
        :type explanation: str
        :param authors: (optional) list of authors
        :type authors: list
        :param opinion: the opinion value (required)
        :type opinion: str
        :param x_opencti_stix_ids: (optional) list of additional STIX IDs
        :type x_opencti_stix_ids: list
        :param objectOrganization: (optional) list of organization IDs
        :type objectOrganization: list
        :param x_opencti_modified_at: (optional) custom modification date
        :type x_opencti_modified_at: datetime
        :param update: (optional) whether to update if exists (default: False)
        :type update: bool
        :param files: (optional) list of File objects to attach
        :type files: list
        :param filesMarkings: (optional) list of lists of marking definition IDs for each file
        :type filesMarkings: list
        :return: Opinion object
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
        explanation = kwargs.get("explanation", None)
        authors = kwargs.get("authors", None)
        opinion = kwargs.get("opinion", None)
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        granted_refs = kwargs.get("objectOrganization", None)
        x_opencti_workflow_id = kwargs.get("x_opencti_workflow_id", None)
        x_opencti_modified_at = kwargs.get("x_opencti_modified_at", None)
        update = kwargs.get("update", False)
        files = kwargs.get("files", None)
        files_markings = kwargs.get("filesMarkings", None)
        no_trigger_import = kwargs.get("noTriggerImport", None)
        embedded = kwargs.get("embedded", None)

        if opinion is not None:
            self.opencti.app_logger.info("Creating Opinion", {"opinion": opinion})
            query = """
                mutation OpinionAdd($input: OpinionAddInput!) {
                    opinionAdd(input: $input) {
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
                "explanation": explanation,
                "authors": authors,
                "opinion": opinion,
                "x_opencti_stix_ids": x_opencti_stix_ids,
                "x_opencti_workflow_id": x_opencti_workflow_id,
                "x_opencti_modified_at": x_opencti_modified_at,
                "update": update,
                "files": files,
                "filesMarkings": files_markings,
                "noTriggerImport": no_trigger_import,
                "embedded": embedded,
            }
            result = self.opencti.query(query, {"input": input_variables})
            return self.opencti.process_multiple_fields(result["data"]["opinionAdd"])
        else:
            self.opencti.app_logger.error(
                "[opencti_opinion] Missing parameters: opinion"
            )
            return None

    def import_from_stix2(self, **kwargs):
        """Import an Opinion object from a STIX2 object.

        :param stixObject: the Stix-Object Opinion
        :type stixObject: dict
        :param extras: extra dict
        :type extras: dict
        :param update: set the update flag on import
        :type update: bool
        :return: Opinion object
        :rtype: dict or None
        """
        stix_object = kwargs.get("stixObject", None)
        extras = kwargs.get("extras", {})
        update = kwargs.get("update", False)
        if stix_object is not None:
            # Search in extensions
            if "x_opencti_stix_ids" not in stix_object:
                stix_object[
                    "x_opencti_stix_ids"
                ] = self.opencti.get_attribute_in_extension("stix_ids", stix_object)
            if "x_opencti_granted_refs" not in stix_object:
                stix_object[
                    "x_opencti_granted_refs"
                ] = self.opencti.get_attribute_in_extension("granted_refs", stix_object)
            if "x_opencti_modified_at" not in stix_object:
                stix_object[
                    "x_opencti_modified_at"
                ] = self.opencti.get_attribute_in_extension("modified_at", stix_object)
            if "x_opencti_workflow_id" not in stix_object:
                stix_object[
                    "x_opencti_workflow_id"
                ] = self.opencti.get_attribute_in_extension("workflow_id", stix_object)

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
                revoked=stix_object["revoked"] if "revoked" in stix_object else None,
                confidence=(
                    stix_object["confidence"] if "confidence" in stix_object else None
                ),
                lang=stix_object["lang"] if "lang" in stix_object else None,
                created=stix_object["created"] if "created" in stix_object else None,
                modified=stix_object["modified"] if "modified" in stix_object else None,
                explanation=(
                    self.opencti.stix2.convert_markdown(stix_object["explanation"])
                    if "explanation" in stix_object
                    else None
                ),
                authors=stix_object["authors"] if "authors" in stix_object else None,
                x_opencti_stix_ids=(
                    stix_object["x_opencti_stix_ids"]
                    if "x_opencti_stix_ids" in stix_object
                    else None
                ),
                x_opencti_modified_at=(
                    stix_object["x_opencti_modified_at"]
                    if "x_opencti_modified_at" in stix_object
                    else None
                ),
                x_opencti_workflow_id=(
                    stix_object["x_opencti_workflow_id"]
                    if "x_opencti_workflow_id" in stix_object
                    else None
                ),
                opinion=stix_object["opinion"] if "opinion" in stix_object else None,
                objectOrganization=(
                    stix_object["x_opencti_granted_refs"]
                    if "x_opencti_granted_refs" in stix_object
                    else None
                ),
                update=update,
                files=extras.get("files"),
                filesMarkings=extras.get("filesMarkings"),
                noTriggerImport=extras.get("noTriggerImport", None),
                embedded=extras.get("embedded", None),
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_opinion] Missing parameters: stixObject"
            )
            return None
