import json
import uuid

from dateutil.parser import parse
from stix2.canonicalization.Canonicalize import canonicalize

from pycti.entities import LOGGER


class CaseTask:
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
                        edges {
                            node {
                                id
                                value
                                color
                            }
                        }
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
                edges {
                    node {
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
                }
            }
            objectLabel {
                edges {
                    node {
                        id
                        value
                        color
                    }
                }
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
            dueDate
            objects {
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
    def generate_id(name):
        name = name.lower().strip()
        data = {"name": name}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "case-task--" + id

    """
        List Case Task objects
        
        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Case Task objects
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
        if get_all:
            first = 500

        self.opencti.log(
            "info",
            "Listing Case Tasks with filters " + json.dumps(filters) + ".",
        )
        query = (
            """
                            query CaseTasks($filters: [CaseTasksFiltering!], $search: String, $first: Int, $after: ID, $orderBy: CaseTasksOrdering, $orderMode: OrderingMode) {
                                caseTasks(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
                "search": search,
                "first": first,
                "after": after,
                "orderBy": order_by,
                "orderMode": order_mode,
            },
        )
        if get_all:
            final_data = []
            data = self.opencti.process_multiple(result["data"]["caseTasks"])
            final_data = final_data + data
            while result["data"]["caseTasks"]["pageInfo"]["hasNextPage"]:
                after = result["date"]["caseTasks"]["pageInfo"]["endCursor"]
                self.opencti.log("info", "Listing Case Tasks after " + after)
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
                data = self.opencti.process_multiple(result["data"]["caseTasks"])
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["caseTasks"], with_pagination
            )

    """
        Read a Case Task object

        :param id: the id of the Case Task
        :param filters: the filters to apply if no id provided
        :return Case Task object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.log("info", "Reading Case Task { " + id + "}.")
            query = (
                """
                                query CaseTask($id: String!) {
                                    caseTask(id: $id) {
                                        """
                + (
                    custom_attributes
                    if custom_attributes is not None
                    else self.properties
                )
                + """
                    }
                }
            """
            )
            result = self.opencti.query(query, {"id": id})
            return self.opencti.process_multiple_fields(result["data"]["caseTask"])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None

    """
        Read a Case Task object by stix_id or name

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
                filters=[
                    {"key": "name", "values": [name]},
                    {"key": "created_day", "values": [created_final]},
                ],
                customAttributes=custom_attributes,
            )
        return object_result

    """
        Check if a case task already contains a thing (Stix Object or Stix Relationship)

        :param id: the id of the Case Task
        :param stixObjectOrStixRelationshipId: the id of the Stix-Entity
        :return Boolean
    """

    def contains_stix_object_or_stix_relationship(self, **kwargs):
        id = kwargs.get("id", None)
        stix_object_or_stix_relationship_id = kwargs.get(
            "stixObjectOrStixRelationshipId", None
        )
        if id is not None and stix_object_or_stix_relationship_id is not None:
            self.opencti.log(
                "info",
                "Checking StixObjectOrStixRelationship {"
                + stix_object_or_stix_relationship_id
                + "} in CaseTask {"
                + id
                + "}",
            )
            query = """
                query CaseTaskContainsStixObjectOrStixRelationship($id: String!, $stixObjectOrStixRelationshipId: String!) {
                    caseTaskContainsStixObjectOrStixRelationship(id: $id, stixObjectOrStixRelationshipId: $stixObjectOrStixRelationshipId)
                }
            """
            result = self.opencti.query(
                query,
                {
                    "id": id,
                    "stixObjectOrStixRelationshipId": stix_object_or_stix_relationship_id,
                },
            )
            return result["data"]["caseTaskContainsStixObjectOrStixRelationship"]
        else:
            self.opencti.log(
                "error",
                "[opencti_caseTask] Missing parameters: id or stixObjectOrStixRelationshipId",
            )

    """
        Create a Case Task object

        :param name: the name of the Case Task
        :return Case Task object
    """

    def create(self, **kwargs):
        objects = kwargs.get("objects", None)
        created = kwargs.get("created", None)
        name = kwargs.get("name", None)
        description = kwargs.get("description", "")
        due_date = kwargs.get("dueDate", None)

        if name is not None:
            self.opencti.log("info", "Creating Case Task {" + name + "}.")
            query = """
                mutation CaseTaskAdd($input: CaseTaskAddInput!) {
                    caseTaskAdd(input: $input) {
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
                        "dueDate": due_date,
                        "objects": objects,
                    }
                },
            )
            return self.opencti.process_multiple_fields(result["data"]["caseTaskAdd"])
        else:
            self.opencti.log(
                "error",
                "[opencti_caseTask] Missing parameters: name",
            )

    def update_field(self, **kwargs):
        LOGGER.info("Updating Case Task {%s}.", json.dumps(kwargs))
        id = kwargs.get("id", None)
        input = kwargs.get("input", None)
        if id is not None and input is not None:
            query = """
                        mutation CaseTaskEdit($id: ID!, $input: [EditInput!]!) {
                           caseTaskFieldPatch(id: $id, input: $input) {
                                id
                                standard_id
                                entity_type
                           }
                        }
                    """
            result = self.opencti.query(query, {"id": id, "input": input})
            return self.opencti.process_multiple_fields(
                result["data"]["caseTaskFieldPatch"]
            )
        else:
            LOGGER.error("[opencti_Case_task] Missing parameters: id and key and value")
            return None

        """
        Add a Stix-Entity object to Case Task object (object_refs)

        :param id: the id of the Case Task
        :param stixObjectOrStixRelationshipId: the id of the Stix-Entity
        :return Boolean
    """

    def add_stix_object_or_stix_relationship(self, **kwargs):
        id = kwargs.get("id", None)
        stix_object_or_stix_relationship_id = kwargs.get(
            "stixObjectOrStixRelationshipId", None
        )
        if id is not None and stix_object_or_stix_relationship_id is not None:
            self.opencti.log(
                "info",
                "Adding StixObjectOrStixRelationship {"
                + stix_object_or_stix_relationship_id
                + "} to CaseTask {"
                + id
                + "}",
            )
            query = """
               mutation CaseTaskEditRelationAdd($id: ID!, $input: StixMetaRelationshipAddInput) {
                   caseTaskEdit(id: $id) {
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
            self.opencti.log(
                "error",
                "[opencti_caseTask] Missing parameters: id and stixObjectOrStixRelationshipId",
            )
            return False

        """
        Remove a Stix-Entity object to Case Task object (object_refs)

        :param id: the id of the Case Task
        :param stixObjectOrStixRelationshipId: the id of the Stix-Entity
        :return Boolean
    """

    def remove_stix_object_or_stix_relationship(self, **kwargs):
        id = kwargs.get("id", None)
        stix_object_or_stix_relationship_id = kwargs.get(
            "stixObjectOrStixRelationshipId", None
        )
        if id is not None and stix_object_or_stix_relationship_id is not None:
            self.opencti.log(
                "info",
                "Removing StixObjectOrStixRelationship {"
                + stix_object_or_stix_relationship_id
                + "} to CaseTask {"
                + id
                + "}",
            )
            query = """
               mutation CaseTaskEditRelationDelete($id: ID!, $toId: StixRef!, $relationship_type: String!) {
                   caseTaskEdit(id: $id) {
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
            self.opencti.log(
                "error",
                "[opencti_caseTask] Missing parameters: id and stixObjectOrStixRelationshipId",
            )
            return False

        """
        Import a Case Task object from a STIX2 object

        :param stixObject: the Stix-Object Case Task
        :return Case Task object
        """

    def import_from_stix2(self, **kwargs):
        stix_object = kwargs.get("stixObject", None)
        extras = kwargs.get("extras", {})
        if stix_object is not None:
            # Search in extensions
            if "x_opencti_stix_ids" not in stix_object:
                stix_object[
                    "x_opencti_stix_ids"
                ] = self.opencti.get_attribute_in_extension("stix_ids", stix_object)
            if "granted_refs" not in stix_object:
                stix_object["granted_refs"] = self.opencti.get_attribute_in_extension(
                    "granted_refs", stix_object
                )

            return self.create(
                objects=extras["object_ids"] if "object_ids" in extras else [],
                created=stix_object["created"] if "created" in stix_object else None,
                name=stix_object["name"],
                description=self.opencti.stix2.convert_markdown(
                    stix_object["description"]
                )
                if "description" in stix_object
                else "",
                dueDate=stix_object["due_date"] if "due_date" in stix_object else None,
            )
        else:
            self.opencti.log(
                "error", "[opencti_caseTask] Missing parameters: stixObject"
            )
