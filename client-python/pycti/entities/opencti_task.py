import datetime
import json
import uuid

from stix2.canonicalization.Canonicalize import canonicalize

from pycti.entities.base import Entity
from pycti.entities.mixins import (
    GetByStixIdOrNameMixin,
    ListFilesMixin,
    ListObjectsMixin,
    StixObjectOrRelationshipMixin,
)


class Task(
    ListObjectsMixin,
    ListFilesMixin,
    StixObjectOrRelationshipMixin,
    GetByStixIdOrNameMixin,
    Entity,
):
    """Main Task class for OpenCTI

    Manages tasks and to-do items in the OpenCTI platform.
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
        name
        description
        due_date
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
            "relation_add": "taskRelationAdd(id: $id, input: $input) { id }",
            "relation_delete": (
                "taskRelationDelete(id: $id, toId: $toId, relationship_type: $relationship_type) { id }"
            ),
        }
    }

    @staticmethod
    def generate_id(name, created):
        """Generate a STIX ID for a Task object.

        :param name: the name of the Task
        :type name: str
        :param created: the creation date of the Task
        :type created: str or datetime.datetime
        :return: STIX ID for the Task
        :rtype: str
        """
        if isinstance(created, datetime.datetime):
            created = created.isoformat()
        data = {"name": name.lower().strip(), "created": created}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "task--" + id

    @staticmethod
    def generate_id_from_data(data):
        """Generate a STIX ID from Task data.

        :param data: Dictionary containing 'name' and 'created' keys
        :type data: dict
        :return: STIX ID for the Task
        :rtype: str
        """
        return Task.generate_id(data["name"], data["created"])

    def create(self, **kwargs):
        """Create a Task object.

        :param name: the name of the Task
        :type name: str
        :param description: the description of the Task
        :type description: str
        :param due_date: the due date of the Task
        :type due_date: str
        :param createdBy: the creator of the Task
        :type createdBy: str
        :param update: (optional) whether to update if exists (default: False)
        :type update: bool
        :param files: (optional) list of File objects to attach
        :type files: list
        :param filesMarkings: (optional) list of lists of marking definition IDs for each file
        :type filesMarkings: list
        :return: Task object
        :rtype: dict or None
        """
        objects = kwargs.get("objects", None)
        created = kwargs.get("created", None)
        name = kwargs.get("name", None)
        description = kwargs.get("description", None)
        due_date = kwargs.get("due_date", None)
        created_by = kwargs.get("createdBy", None)
        object_marking = kwargs.get("objectMarking", None)
        object_label = kwargs.get("objectLabel", None)
        object_assignee = kwargs.get("objectAssignee", None)
        object_participant = kwargs.get("objectParticipant", None)
        granted_refs = kwargs.get("objectOrganization", None)
        x_opencti_workflow_id = kwargs.get("x_opencti_workflow_id", None)
        x_opencti_modified_at = kwargs.get("x_opencti_modified_at", None)
        update = kwargs.get("update", False)
        files = kwargs.get("files", None)
        files_markings = kwargs.get("filesMarkings", None)
        no_trigger_import = kwargs.get("noTriggerImport", None)
        embedded = kwargs.get("embedded", None)
        upsert_operations = kwargs.get("upsert_operations", None)

        if name is not None:
            self.opencti.app_logger.info("Creating Task", {"name": name})
            query = """
                mutation TaskAdd($input: TaskAddInput!) {
                    taskAdd(input: $input) {
                        id
                        standard_id
                        entity_type
                        parent_types
                    }
                }
            """
            result = self.opencti.query(
                query,
                {
                    "input": {
                        "created": created,
                        "name": name,
                        "description": description,
                        "due_date": due_date,
                        "objects": objects,
                        "createdBy": created_by,
                        "objectLabel": object_label,
                        "objectMarking": object_marking,
                        "objectOrganization": granted_refs,
                        "objectAssignee": object_assignee,
                        "objectParticipant": object_participant,
                        "x_opencti_workflow_id": x_opencti_workflow_id,
                        "x_opencti_modified_at": x_opencti_modified_at,
                        "update": update,
                        "files": files,
                        "filesMarkings": files_markings,
                        "noTriggerImport": no_trigger_import,
                        "embedded": embedded,
                        "upsertOperations": upsert_operations,
                    }
                },
            )
            return self.opencti.process_multiple_fields(result["data"]["taskAdd"])
        else:
            self.opencti.app_logger.error("[opencti_task] Missing parameters: name")
            return None

    def update_field(self, **kwargs):
        """Update a field of a Task object.

        :param id: the id of the Task
        :type id: str
        :param input: the input containing field(s) to update
        :type input: list
        :return: Task object
        :rtype: dict or None
        """
        self.opencti.app_logger.info("Updating Task", {"data": json.dumps(kwargs)})
        id = kwargs.get("id", None)
        input = kwargs.get("input", None)
        if id is not None and input is not None:
            query = """
                        mutation TaskEdit($id: ID!, $input: [EditInput!]!) {
                           taskFieldPatch(id: $id, input: $input) {
                                id
                                standard_id
                                entity_type
                           }
                        }
                    """
            result = self.opencti.query(query, {"id": id, "input": input})
            return self.opencti.process_multiple_fields(
                result["data"]["taskFieldPatch"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_task] Missing parameters: id and input"
            )
            return None

    def import_from_stix2(self, **kwargs):
        """Import a Task object from a STIX2 object.

        :param stixObject: the Stix-Object Task
        :type stixObject: dict
        :param extras: additional parameters like created_by_id, object_marking_ids
        :type extras: dict
        :param update: whether to update existing object
        :type update: bool
        :return: Task object
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
                created=stix_object["created"] if "created" in stix_object else None,
                name=stix_object["name"],
                description=(
                    self.opencti.stix2.convert_markdown(stix_object["description"])
                    if "description" in stix_object
                    else None
                ),
                due_date=stix_object["due_date"] if "due_date" in stix_object else None,
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
                "[opencti_task] Missing parameters: stixObject"
            )
            return None

    def delete(self, **kwargs):
        """Delete a Task object.

        :param id: the id of the Task to delete
        :type id: str
        :return: None
        """
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.app_logger.info("Deleting Task", {"id": id})
            query = """
                 mutation TaskDelete($id: ID!) {
                     taskDelete(id: $id)
                 }
             """
            self.opencti.query(query, {"id": id})
        else:
            self.opencti.app_logger.error("[opencti_task] Missing parameters: id")
            return None
