import datetime
import json
import uuid

from dateutil.parser import parse
from stix2.canonicalization.Canonicalize import canonicalize


class CaseRft:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
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
                    }
                }
            }
        """
        self.properties_with_files = """
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
                name
                description
                severity
                priority
                takedown_types
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
                        }
                    }
                }
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
    def generate_id(name, created):
        name = name.lower().strip()
        if isinstance(created, datetime.datetime):
            created = created.isoformat()
        data = {"name": name, "created": created}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "case-rft--" + id

    @staticmethod
    def generate_id_from_data(data):
        return CaseRft.generate_id(data["name"], data["created"])

    """
        List Case Rft objects

        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Case Rft objects
    """

    def list(self, **kwargs):
        filters = kwargs.get("filters", None)
        search = kwargs.get("search", None)
        first = kwargs.get("first", 500)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        custom_attributes = kwargs.get("customAttributes", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)
        with_files = kwargs.get("withFiles", False)
        self.opencti.app_logger.info(
            "Listing Case Rfts with filters", {"filters": json.dumps(filters)}
        )
        query = (
            """
                        query CaseRfts($filters: FilterGroup, $search: String, $first: Int, $after: ID, $orderBy: CaseRftsOrdering, $orderMode: OrderingMode) {
                            caseRfts(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
                                edges {
                                    node {
                                        """
            + (
                custom_attributes
                if custom_attributes is not None
                else (self.properties_with_files if with_files else self.properties)
            )
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
                "search": search,
                "first": first,
                "after": after,
                "orderBy": order_by,
                "orderMode": order_mode,
            },
        )
        if get_all:
            final_data = []
            data = self.opencti.process_multiple(result["data"]["caseRfts"])
            final_data = final_data + data
            while result["data"]["caseRfts"]["pageInfo"]["hasNextPage"]:
                after = result["date"]["caseRfts"]["pageInfo"]["endCursor"]
                self.opencti.app_logger.info("Listing Case Rfts", {"after": after})
                result = self.opencti.query(
                    query,
                    {
                        "filters": filters,
                        "search": search,
                        "first": first,
                        "after": after,
                        "orderBy": order_by,
                        "orderMode": order_mode,
                    },
                )
                data = self.opencti.process_multiple(result["data"]["caseRfts"])
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["caseRfts"], with_pagination
            )

    """
        Read a Case Rft object

        :param id: the id of the Case Rft
        :param filters: the filters to apply if no id provided
        :return Case Rft object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        with_files = kwargs.get("withFiles", False)
        if id is not None:
            self.opencti.app_logger.info("Reading Case Rft", {"id": id})
            query = (
                """
                            query CaseRft($id: String!) {
                                caseRft(id: $id) {
                                    """
                + (
                    custom_attributes
                    if custom_attributes is not None
                    else (self.properties_with_files if with_files else self.properties)
                )
                + """
                    }
                }
            """
            )
            result = self.opencti.query(query, {"id": id})
            return self.opencti.process_multiple_fields(result["data"]["caseRft"])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None

    """
        Read a Case Rft object by stix_id or name

        :param type: the Stix-Domain-Entity type
        :param stix_id: the STIX ID of the Stix-Domain-Entity
        :param name: the name of the Stix-Domain-Entity
        :return Stix-Domain-Entity object
    """

    def get_by_stix_id_or_name(self, **kwargs):
        stix_id = kwargs.get("stix_id", None)
        name = kwargs.get("name", None)
        created = kwargs.get("created", None)
        custom_attributes = kwargs.get("customAttributes", None)
        object_result = None
        if stix_id is not None:
            object_result = self.read(id=stix_id, customAttributes=custom_attributes)
        if object_result is None and name is not None and created is not None:
            created_final = parse(created).strftime("%Y-%m-%d")
            object_result = self.read(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "name", "values": [name]},
                        {"key": "created_day", "values": [created_final]},
                    ],
                    "filterGroups": [],
                },
                customAttributes=custom_attributes,
            )
        return object_result

    """
        Check if a case rft already contains a thing (Stix Object or Stix Relationship)

        :param id: the id of the Case Rft
        :param stixObjectOrStixRelationshipId: the id of the Stix-Entity
        :return Boolean
    """

    def contains_stix_object_or_stix_relationship(self, **kwargs):
        id = kwargs.get("id", None)
        stix_object_or_stix_relationship_id = kwargs.get(
            "stixObjectOrStixRelationshipId", None
        )
        if id is not None and stix_object_or_stix_relationship_id is not None:
            self.opencti.app_logger.info(
                "Checking StixObjectOrStixRelationship in CaseRft",
                {
                    "stix_object_or_stix_relationship_id": stix_object_or_stix_relationship_id,
                    "id": id,
                },
            )
            query = """
                query CaseRftContainsStixObjectOrStixRelationship($id: String!, $stixObjectOrStixRelationshipId: String!) {
                    caseRftContainsStixObjectOrStixRelationship(id: $id, stixObjectOrStixRelationshipId: $stixObjectOrStixRelationshipId)
                }
            """
            result = self.opencti.query(
                query,
                {
                    "id": id,
                    "stixObjectOrStixRelationshipId": stix_object_or_stix_relationship_id,
                },
            )
            return result["data"]["caseRftContainsStixObjectOrStixRelationship"]
        else:
            self.opencti.app_logger.error(
                "[opencti_caseRft] Missing parameters: id or stixObjectOrStixRelationshipId"
            )

    """
        Create a Case Rft object

        :param name: the name of the Case Rft
        :return Case Rft object
    """

    def create(self, **kwargs):
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
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        name = kwargs.get("name", None)
        description = kwargs.get("description", None)
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        granted_refs = kwargs.get("objectOrganization", None)
        x_opencti_workflow_id = kwargs.get("x_opencti_workflow_id", None)
        update = kwargs.get("update", False)
        takedown_types = kwargs.get("takedown_types", None)

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
            result = self.opencti.query(
                query,
                {
                    "input": {
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
                        "confidence": confidence,
                        "lang": lang,
                        "created": created,
                        "modified": modified,
                        "name": name,
                        "description": description,
                        "x_opencti_stix_ids": x_opencti_stix_ids,
                        "x_opencti_workflow_id": x_opencti_workflow_id,
                        "update": update,
                        "takedown_types": takedown_types,
                    }
                },
            )
            return self.opencti.process_multiple_fields(result["data"]["caseRftAdd"])
        else:
            self.opencti.app_logger.error("[opencti_caseRft] Missing parameters: name")

        """
        Add a Stix-Entity object to Case Rft object (object_refs)

        :param id: the id of the Case Rft
        :param stixObjectOrStixRelationshipId: the id of the Stix-Entity
        :return Boolean
    """

    def add_stix_object_or_stix_relationship(self, **kwargs):
        id = kwargs.get("id", None)
        stix_object_or_stix_relationship_id = kwargs.get(
            "stixObjectOrStixRelationshipId", None
        )
        if id is not None and stix_object_or_stix_relationship_id is not None:
            self.opencti.app_logger.info(
                "Adding StixObjectOrStixRelationship in CaseRft",
                {
                    "stix_object_or_stix_relationship_id": stix_object_or_stix_relationship_id,
                    "id": id,
                },
            )
            query = """
               mutation CaseRftEditRelationAdd($id: ID!, $input: StixRefRelationshipAddInput!) {
                   stixDomainObjectEdit(id: $id) {
                        relationAdd(input: $input) {
                            id
                        }
                   }
               }
            """
            self.opencti.query(
                query,
                {
                    "id": id,
                    "input": {
                        "toId": stix_object_or_stix_relationship_id,
                        "relationship_type": "object",
                    },
                },
            )
            return True
        else:
            self.opencti.app_logger.info(
                "[opencti_caseRft] Missing parameters: id and stixObjectOrStixRelationshipId"
            )
            return False

    """
        Remove a Stix-Entity object to Case Rft object (object_refs)

        :param id: the id of the Case Rft
        :param stixObjectOrStixRelationshipId: the id of the Stix-Entity
        :return Boolean
    """

    def remove_stix_object_or_stix_relationship(self, **kwargs):
        id = kwargs.get("id", None)
        stix_object_or_stix_relationship_id = kwargs.get(
            "stixObjectOrStixRelationshipId", None
        )
        if id is not None and stix_object_or_stix_relationship_id is not None:
            self.opencti.app_logger.info(
                "Removing StixObjectOrStixRelationship in CaseRft",
                {
                    "stix_object_or_stix_relationship_id": stix_object_or_stix_relationship_id,
                    "id": id,
                },
            )
            query = """
               mutation CaseRftEditRelationDelete($id: ID!, $toId: StixRef!, $relationship_type: String!) {
                   stixDomainObjectEdit(id: $id) {
                        relationDelete(toId: $toId, relationship_type: $relationship_type) {
                            id
                        }
                   }
               }
            """
            self.opencti.query(
                query,
                {
                    "id": id,
                    "toId": stix_object_or_stix_relationship_id,
                    "relationship_type": "object",
                },
            )
            return True
        else:
            self.opencti.app_logger.error(
                "[opencti_caseRft] Missing parameters: id and stixObjectOrStixRelationshipId"
            )
            return False

        """
        Import a Case Rft object from a STIX2 object

        :param stixObject: the Stix-Object Case Rft
        :return Case Rft object
        """

    def import_from_stix2(self, **kwargs):
        stix_object = kwargs.get("stixObject", None)
        extras = kwargs.get("extras", {})
        update = kwargs.get("update", False)
        if stix_object is not None:
            # Search in extensions
            if "x_opencti_stix_ids" not in stix_object:
                stix_object["x_opencti_stix_ids"] = (
                    self.opencti.get_attribute_in_extension("stix_ids", stix_object)
                )
            if "x_opencti_granted_refs" not in stix_object:
                stix_object["x_opencti_granted_refs"] = (
                    self.opencti.get_attribute_in_extension("granted_refs", stix_object)
                )
            if "x_opencti_workflow_id" not in stix_object:
                stix_object["x_opencti_workflow_id"] = (
                    self.opencti.get_attribute_in_extension("workflow_id", stix_object)
                )
            if "x_opencti_assignee_ids" not in stix_object:
                stix_object["x_opencti_assignee_ids"] = (
                    self.opencti.get_attribute_in_extension("assignee_ids", stix_object)
                )
            if "x_opencti_participant_ids" not in stix_object:
                stix_object["x_opencti_participant_ids"] = (
                    self.opencti.get_attribute_in_extension(
                        "participant_ids", stix_object
                    )
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
                update=update,
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_caseRft] Missing parameters: stixObject"
            )

    def delete(self, **kwargs):
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
