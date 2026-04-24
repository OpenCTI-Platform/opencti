import datetime
import uuid

from stix2.canonicalization.Canonicalize import canonicalize

from pycti.entities.base import Entity
from pycti.entities.mixins import (
    GetByStixIdOrNameMixin,
    ListFilesMixin,
    ListObjectsMixin,
    StixObjectOrRelationshipMixin,
)


class CaseRft(
    ListObjectsMixin,
    ListFilesMixin,
    StixObjectOrRelationshipMixin,
    GetByStixIdOrNameMixin,
    Entity,
):
    """Main CaseRft (Request for Takedown) class for OpenCTI

    Manages RFT cases in the OpenCTI platform.
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
        takedown_types
        severity
        priority
        tasks {
            edges {
                node {
                    name
                    description
                    due_date
                    status {
                      id
                      template {
                        id
                        name
                        color
                      }
                    }
                }
            }
        }
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
        ... on Event {
            name
        }
        ... on Channel {
            name
        }
        ... on Narrative {
            name
        }
        ... on Language {
            name
        }
        ... on DataComponent {
            name
        }
        ... on DataSource {
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

    @staticmethod
    def generate_id(name, created):
        """Generate a STIX ID for a Case RFT object.

        :param name: the name of the Case RFT
        :type name: str
        :param created: the creation date of the Case RFT
        :type created: str or datetime.datetime
        :return: STIX ID for the Case RFT
        :rtype: str
        """
        name = name.lower().strip()
        if isinstance(created, datetime.datetime):
            created = created.isoformat()
        data = {"name": name, "created": created}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "case-rft--" + id

    @staticmethod
    def generate_id_from_data(data):
        """Generate a STIX ID from Case RFT data.

        :param data: Dictionary containing 'name' and 'created' keys
        :type data: dict
        :return: STIX ID for the Case RFT
        :rtype: str
        """
        return CaseRft.generate_id(data["name"], data["created"])

    def create(self, **kwargs):
        """Create a Case RFT (Request for Takedown) object.

        :param stix_id: (optional) the STIX ID
        :type stix_id: str
        :param createdBy: (optional) the author ID
        :type createdBy: str
        :param objects: (optional) list of STIX object IDs contained in the case
        :type objects: list
        :param objectMarking: (optional) list of marking definition IDs
        :type objectMarking: list
        :param objectLabel: (optional) list of label IDs
        :type objectLabel: list
        :param objectAssignee: (optional) list of assignee IDs
        :type objectAssignee: list
        :param objectParticipant: (optional) list of participant IDs
        :type objectParticipant: list
        :param externalReferences: (optional) list of external reference IDs
        :type externalReferences: list
        :param revoked: (optional) whether the case is revoked
        :type revoked: bool
        :param severity: (optional) severity level
        :type severity: str
        :param priority: (optional) priority level
        :type priority: str
        :param confidence: (optional) confidence level (0-100)
        :type confidence: int
        :param lang: (optional) language
        :type lang: str
        :param content: (optional) content
        :type content: str
        :param created: (optional) creation date
        :type created: str
        :param modified: (optional) modification date
        :type modified: str
        :param name: the name of the Case RFT (required)
        :type name: str
        :param description: (optional) description
        :type description: str
        :param x_opencti_stix_ids: (optional) list of additional STIX IDs
        :type x_opencti_stix_ids: list
        :param objectOrganization: (optional) list of organization IDs
        :type objectOrganization: list
        :param x_opencti_workflow_id: (optional) workflow ID
        :type x_opencti_workflow_id: str
        :param x_opencti_modified_at: (optional) custom modification date
        :type x_opencti_modified_at: str
        :param update: (optional) whether to update if exists (default: False)
        :type update: bool
        :param takedown_types: (optional) list of takedown types
        :type takedown_types: list
        :param files: (optional) list of File objects to attach
        :type files: list
        :param filesMarkings: (optional) list of lists of marking definition IDs for each file
        :type filesMarkings: list
        :return: Case RFT object
        :rtype: dict or None
        """
        stix_id = kwargs.get("stix_id", None)
        created_by = kwargs.get("createdBy", None)
        objects = kwargs.get("objects", None)
        object_marking = kwargs.get("objectMarking", None)
        object_label = kwargs.get("objectLabel", None)
        object_assignee = kwargs.get("objectAssignee", None)
        object_participant = kwargs.get("objectParticipant", None)
        external_references = kwargs.get("externalReferences", None)
        revoked = kwargs.get("revoked", None)
        severity = kwargs.get("severity", None)
        priority = kwargs.get("priority", None)
        confidence = kwargs.get("confidence", None)
        lang = kwargs.get("lang", None)
        content = kwargs.get("content", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        name = kwargs.get("name", None)
        description = kwargs.get("description", None)
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        granted_refs = kwargs.get("objectOrganization", None)
        x_opencti_workflow_id = kwargs.get("x_opencti_workflow_id", None)
        x_opencti_modified_at = kwargs.get("x_opencti_modified_at", None)
        update = kwargs.get("update", False)
        takedown_types = kwargs.get("takedown_types", None)
        files = kwargs.get("files", None)
        files_markings = kwargs.get("filesMarkings", None)
        no_trigger_import = kwargs.get("noTriggerImport", None)
        embedded = kwargs.get("embedded", None)
        upsert_operations = kwargs.get("upsert_operations", None)

        if name is not None:
            self.opencti.app_logger.info("Creating Case Rft", {"name": name})
            query = """
                mutation CaseRftAdd($input: CaseRftAddInput!) {
                    caseRftAdd(input: $input) {
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
                "objectAssignee": object_assignee,
                "objectParticipant": object_participant,
                "objects": objects,
                "externalReferences": external_references,
                "revoked": revoked,
                "severity": severity,
                "priority": priority,
                "content": content,
                "confidence": confidence,
                "lang": lang,
                "created": created,
                "modified": modified,
                "name": name,
                "description": description,
                "x_opencti_stix_ids": x_opencti_stix_ids,
                "x_opencti_workflow_id": x_opencti_workflow_id,
                "x_opencti_modified_at": x_opencti_modified_at,
                "update": update,
                "takedown_types": takedown_types,
                "files": files,
                "filesMarkings": files_markings,
                "noTriggerImport": no_trigger_import,
                "embedded": embedded,
                "upsertOperations": upsert_operations,
            }
            result = self.opencti.query(query, {"input": input_variables})
            return self.opencti.process_multiple_fields(result["data"]["caseRftAdd"])
        else:
            self.opencti.app_logger.error("[opencti_case_rft] Missing parameters: name")
            return None

    def import_from_stix2(self, **kwargs):
        """Import a Case RFT object from a STIX2 object.

        :param stixObject: the STIX2 Case RFT object
        :type stixObject: dict
        :param extras: extra parameters including created_by_id, object_marking_ids, etc.
        :type extras: dict
        :param update: whether to update if the entity already exists
        :type update: bool
        :return: Case RFT object
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
            if "x_opencti_assignee_ids" not in stix_object:
                stix_object[
                    "x_opencti_assignee_ids"
                ] = self.opencti.get_attribute_in_extension("assignee_ids", stix_object)
            if "x_opencti_participant_ids" not in stix_object:
                stix_object[
                    "x_opencti_participant_ids"
                ] = self.opencti.get_attribute_in_extension(
                    "participant_ids", stix_object
                )
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
                revoked=stix_object["revoked"] if "revoked" in stix_object else None,
                severity=stix_object["severity"] if "severity" in stix_object else None,
                priority=stix_object["priority"] if "priority" in stix_object else None,
                confidence=(
                    stix_object["confidence"] if "confidence" in stix_object else None
                ),
                content=(
                    self.opencti.stix2.convert_markdown(stix_object["content"])
                    if "content" in stix_object
                    else None
                ),
                lang=stix_object["lang"] if "lang" in stix_object else None,
                created=stix_object["created"] if "created" in stix_object else None,
                modified=stix_object["modified"] if "modified" in stix_object else None,
                name=stix_object["name"],
                description=(
                    self.opencti.stix2.convert_markdown(stix_object["description"])
                    if "description" in stix_object
                    else None
                ),
                takedown_types=(
                    stix_object["takedown_types"]
                    if "takedown_types" in stix_object
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
                objectAssignee=(
                    stix_object["x_opencti_assignee_ids"]
                    if "x_opencti_assignee_ids" in stix_object
                    else None
                ),
                objectParticipant=(
                    stix_object["x_opencti_participant_ids"]
                    if "x_opencti_participant_ids" in stix_object
                    else None
                ),
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
                "[opencti_case_rft] Missing parameters: stixObject"
            )
            return None

    def delete(self, **kwargs):
        """Delete a Case RFT object.

        :param id: the id of the Case RFT to delete
        :type id: str
        :return: None
        """
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.app_logger.info("Deleting Case RFT", {"id": id})
            query = """
                 mutation CaseRFTDelete($id: ID!) {
                     stixDomainObjectEdit(id: $id) {
                         delete
                     }
                 }
             """
            self.opencti.query(query, {"id": id})
        else:
            self.opencti.app_logger.error("[opencti_case_rft] Missing parameters: id")
            return None
