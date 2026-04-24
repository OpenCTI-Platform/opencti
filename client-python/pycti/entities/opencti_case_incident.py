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


class CaseIncident(
    ListObjectsMixin,
    ListFilesMixin,
    StixObjectOrRelationshipMixin,
    GetByStixIdOrNameMixin,
    Entity,
):
    """Main CaseIncident class for OpenCTI

    Manages incident response cases in the OpenCTI platform.
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
        rating
        severity
        priority
        response_types
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
        """Generate a STIX ID for a Case Incident object.

        :param name: the name of the Case Incident
        :type name: str
        :param created: the creation date of the Case Incident
        :type created: str or datetime.datetime
        :return: STIX ID for the Case Incident
        :rtype: str
        """
        name = name.lower().strip()
        if isinstance(created, datetime.datetime):
            created = created.isoformat()
        data = {"name": name, "created": created}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "case-incident--" + id

    @staticmethod
    def generate_id_from_data(data):
        """Generate a STIX ID from Case Incident data.

        :param data: Dictionary containing 'name' and 'created' keys
        :type data: dict
        :return: STIX ID for the Case Incident
        :rtype: str
        """
        return CaseIncident.generate_id(data["name"], data["created"])

    def create(self, **kwargs):
        """
        Create a Case Incident object

        :param stix_id: (optional) the STIX ID
        :param createdBy: (optional) the author ID
        :param objects: (optional) list of STIX object IDs contained in the case
        :param objectMarking: (optional) list of marking definition IDs
        :param objectLabel: (optional) list of label IDs
        :param externalReferences: (optional) list of external reference IDs
        :param revoked: (optional) whether the case is revoked
        :param confidence: (optional) confidence level (0-100)
        :param lang: (optional) language
        :param created: (optional) creation date
        :param modified: (optional) modification date
        :param name: the name of the Case Incident (required)
        :param description: (optional) description
        :param content: (optional) content
        :param severity: (optional) severity level
        :param priority: (optional) priority level
        :param x_opencti_stix_ids: (optional) list of additional STIX IDs
        :param objectAssignee: (optional) list of assignee IDs
        :param objectParticipant: (optional) list of participant IDs
        :param objectOrganization: (optional) list of organization IDs
        :param response_types: (optional) list of response types
        :param x_opencti_workflow_id: (optional) workflow ID
        :param x_opencti_modified_at: (optional) custom modification date
        :param update: (optional) whether to update if exists (default: False)
        :type update: bool
        :param files: (optional) list of File objects to attach
        :type files: list
        :param filesMarkings: (optional) list of lists of marking definition IDs for each file
        :type filesMarkings: list
        :return: Case Incident object
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
        description = kwargs.get("description", None)
        content = kwargs.get("content", None)
        severity = kwargs.get("severity", None)
        priority = kwargs.get("priority", None)
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        object_assignee = kwargs.get("objectAssignee", None)
        object_participant = kwargs.get("objectParticipant", None)
        granted_refs = kwargs.get("objectOrganization", None)
        response_types = kwargs.get("response_types", None)
        x_opencti_workflow_id = kwargs.get("x_opencti_workflow_id", None)
        x_opencti_modified_at = kwargs.get("x_opencti_modified_at", None)
        update = kwargs.get("update", False)
        files = kwargs.get("files", None)
        files_markings = kwargs.get("filesMarkings", None)
        no_trigger_import = kwargs.get("noTriggerImport", None)
        embedded = kwargs.get("embedded", None)
        upsert_operations = kwargs.get("upsert_operations", None)

        if name is not None:
            self.opencti.app_logger.info("Creating Case Incident", {"name": name})
            query = """
                mutation CaseIncidentAdd($input: CaseIncidentAddInput!) {
                    caseIncidentAdd(input: $input) {
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
                "confidence": confidence,
                "lang": lang,
                "created": created,
                "modified": modified,
                "name": name,
                "description": description,
                "content": content,
                "severity": severity,
                "priority": priority,
                "x_opencti_stix_ids": x_opencti_stix_ids,
                "response_types": response_types,
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
            return self.opencti.process_multiple_fields(
                result["data"]["caseIncidentAdd"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_case_incident] Missing parameters: name"
            )
            return None

    def import_from_stix2(self, **kwargs):
        """Import a Case Incident object from a STIX2 object.

        :param stixObject: the Stix-Object Case Incident
        :type stixObject: dict
        :param extras: additional parameters like created_by_id, object_marking_ids
        :type extras: dict
        :param update: whether to update existing object
        :type update: bool
        :return: Case Incident object
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
            if "x_opencti_workflow_id" not in stix_object:
                stix_object[
                    "x_opencti_workflow_id"
                ] = self.opencti.get_attribute_in_extension("workflow_id", stix_object)
            if "x_opencti_content" not in stix_object or "content" not in stix_object:
                stix_object["content"] = self.opencti.get_attribute_in_extension(
                    "content", stix_object
                )
            if "x_opencti_content" in stix_object:
                stix_object["content"] = stix_object["x_opencti_content"]
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
                confidence=(
                    stix_object["confidence"] if "confidence" in stix_object else None
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
                content=(
                    self.opencti.stix2.convert_markdown(stix_object["content"])
                    if "content" in stix_object
                    else None
                ),
                severity=stix_object["severity"] if "severity" in stix_object else None,
                priority=stix_object["priority"] if "priority" in stix_object else None,
                response_types=(
                    stix_object["response_types"]
                    if "response_types" in stix_object
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
                "[opencti_case_incident] Missing parameters: stixObject"
            )
            return None

    def delete(self, **kwargs):
        """Delete a Case Incident object.

        :param id: the id of the Case Incident to delete
        :type id: str
        :return: None
        """
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.app_logger.info("Deleting Case Incident", {"id": id})
            query = """
                 mutation CaseIncidentDelete($id: ID!) {
                     stixDomainObjectEdit(id: $id) {
                         delete
                     }
                 }
             """
            self.opencti.query(query, {"id": id})
        else:
            self.opencti.app_logger.error(
                "[opencti_case_incident] Missing parameters: id"
            )
            return None
