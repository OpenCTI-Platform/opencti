# coding: utf-8

import json
import uuid

from stix2.canonicalization.Canonicalize import canonicalize


class CourseOfAction:
    """Main CourseOfAction class for OpenCTI

    Manages courses of action (mitigations) in the OpenCTI platform.

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type opencti: OpenCTIApiClient
    """

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
            x_opencti_aliases
            x_mitre_id
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
            x_opencti_aliases
            x_mitre_id
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
    def generate_id(name, x_mitre_id=None):
        """Generate a STIX ID for a Course of Action.

        :param name: The name of the course of action
        :type name: str
        :param x_mitre_id: Optional MITRE ATT&CK ID
        :type x_mitre_id: str or None
        :return: STIX ID for the course of action
        :rtype: str
        """
        if x_mitre_id is not None:
            data = {"x_mitre_id": x_mitre_id.strip()}
        else:
            data = {"name": name.lower().strip()}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "course-of-action--" + id

    @staticmethod
    def generate_id_from_data(data):
        """Generate a STIX ID from course of action data.

        :param data: Dictionary containing 'name' and optionally 'x_mitre_id' keys
        :type data: dict
        :return: STIX ID for the course of action
        :rtype: str
        """
        return CourseOfAction.generate_id(data.get("name"), data.get("x_mitre_id"))

    def list(self, **kwargs):
        """List Course of Action objects.

        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :param orderBy: field to order results by
        :param orderMode: ordering mode (asc/desc)
        :param customAttributes: custom attributes to return
        :param getAll: whether to retrieve all results
        :param withPagination: whether to include pagination info
        :param withFiles: whether to include files
        :return: List of Course of Action objects
        :rtype: list
        """
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
            "Listing Courses-Of-Action with filters", {"filters": json.dumps(filters)}
        )
        query = (
            """
            query CoursesOfAction($filters: FilterGroup, $search: String, $first: Int, $after: ID, $orderBy: CoursesOfActionOrdering, $orderMode: OrderingMode) {
                coursesOfAction(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
            data = self.opencti.process_multiple(result["data"]["coursesOfAction"])
            final_data = final_data + data
            while result["data"]["coursesOfAction"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["coursesOfAction"]["pageInfo"]["endCursor"]
                self.opencti.app_logger.info(
                    "Listing Courses-Of-Action", {"after": after}
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
                data = self.opencti.process_multiple(result["data"]["coursesOfAction"])
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["coursesOfAction"], with_pagination
            )

    def read(self, **kwargs):
        """Read a Course of Action object.

        :param id: the id of the Course of Action
        :param filters: the filters to apply if no id provided
        :param customAttributes: custom attributes to return
        :param withFiles: whether to include files
        :return: Course of Action object
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        with_files = kwargs.get("withFiles", False)
        if id is not None:
            self.opencti.app_logger.info("Reading Course-Of-Action", {"id": id})
            query = (
                """
                query CourseOfAction($id: String!) {
                    courseOfAction(id: $id) {
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
            return self.opencti.process_multiple_fields(
                result["data"]["courseOfAction"]
            )
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.app_logger.error(
                "[opencti_course_of_action] Missing parameters: id or filters"
            )
            return None

    def create(self, **kwargs):
        """Create a Course of Action object.

        :param name: the name of the Course of Action (required)
        :param stix_id: (optional) the STIX ID
        :param createdBy: (optional) the author ID
        :param objectMarking: (optional) list of marking definition IDs
        :param objectLabel: (optional) list of label IDs
        :param externalReferences: (optional) list of external reference IDs
        :param revoked: (optional) whether the course of action is revoked
        :param confidence: (optional) confidence level (0-100)
        :param lang: (optional) language
        :param created: (optional) creation date
        :param modified: (optional) modification date
        :param description: (optional) description
        :param x_opencti_aliases: (optional) list of aliases
        :param x_mitre_id: (optional) MITRE ATT&CK ID
        :param x_opencti_stix_ids: (optional) list of additional STIX IDs
        :param objectOrganization: (optional) list of organization IDs
        :param x_opencti_workflow_id: (optional) workflow ID
        :param x_opencti_modified_at: (optional) custom modification date
        :param update: (optional) whether to update if exists (default: False)
        :param file: (optional) File object to attach
        :param fileMarkings: (optional) list of marking definition IDs for the file
        :return: Course of Action object
        :rtype: dict or None
        """
        stix_id = kwargs.get("stix_id", None)
        created_by = kwargs.get("createdBy", None)
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
        x_opencti_aliases = kwargs.get("x_opencti_aliases", None)
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        x_mitre_id = kwargs.get("x_mitre_id", None)
        granted_refs = kwargs.get("objectOrganization", None)
        x_opencti_workflow_id = kwargs.get("x_opencti_workflow_id", None)
        x_opencti_modified_at = kwargs.get("x_opencti_modified_at", None)
        update = kwargs.get("update", False)
        file = kwargs.get("file", None)
        file_markings = kwargs.get("fileMarkings", None)

        if name is not None:
            self.opencti.app_logger.info("Creating Course Of Action", {"name": name})
            query = """
                mutation CourseOfActionAdd($input: CourseOfActionAddInput!) {
                    courseOfActionAdd(input: $input) {
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
                        "externalReferences": external_references,
                        "revoked": revoked,
                        "confidence": confidence,
                        "lang": lang,
                        "created": created,
                        "modified": modified,
                        "name": name,
                        "description": description,
                        "x_opencti_aliases": x_opencti_aliases,
                        "x_opencti_stix_ids": x_opencti_stix_ids,
                        "x_mitre_id": x_mitre_id,
                        "x_opencti_workflow_id": x_opencti_workflow_id,
                        "x_opencti_modified_at": x_opencti_modified_at,
                        "update": update,
                        "file": file,
                        "fileMarkings": file_markings,
                    }
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["courseOfActionAdd"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_course_of_action] Missing parameters: name"
            )
            return None

    def import_from_stix2(self, **kwargs):
        """Import a Course of Action object from a STIX2 object.

        :param stixObject: the STIX2 Course of Action object
        :param extras: extra parameters including created_by_id, object_marking_ids, etc.
        :param update: whether to update if the entity already exists
        :return: Course of Action object
        :rtype: dict or None
        """
        stix_object = kwargs.get("stixObject", None)
        extras = kwargs.get("extras", {})
        update = kwargs.get("update", False)
        if stix_object is not None:
            # Extract external ID
            x_mitre_id = None
            if "x_mitre_id" in stix_object:
                x_mitre_id = stix_object["x_mitre_id"]
            elif (
                self.opencti.get_attribute_in_mitre_extension("id", stix_object)
                is not None
            ):
                x_mitre_id = self.opencti.get_attribute_in_mitre_extension(
                    "id", stix_object
                )
            elif "external_references" in stix_object:
                for external_reference in stix_object["external_references"]:
                    if (
                        external_reference["source_name"] == "mitre-attack"
                        or external_reference["source_name"] == "mitre-pre-attack"
                        or external_reference["source_name"] == "mitre-mobile-attack"
                        or external_reference["source_name"] == "amitt-attack"
                    ):
                        x_mitre_id = external_reference.get("external_id", None)

            # Search in extensions
            if "x_opencti_aliases" not in stix_object:
                stix_object["x_opencti_aliases"] = (
                    self.opencti.get_attribute_in_extension("aliases", stix_object)
                )
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
            if "x_opencti_modified_at" not in stix_object:
                stix_object["x_opencti_modified_at"] = (
                    self.opencti.get_attribute_in_extension("modified_at", stix_object)
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
                x_opencti_stix_ids=(
                    stix_object["x_opencti_stix_ids"]
                    if "x_opencti_stix_ids" in stix_object
                    else None
                ),
                x_opencti_aliases=self.opencti.stix2.pick_aliases(stix_object),
                x_mitre_id=x_mitre_id,
                objectOrganization=(
                    stix_object["x_opencti_granted_refs"]
                    if "x_opencti_granted_refs" in stix_object
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
                file=extras.get("file"),
                fileMarkings=extras.get("fileMarkings"),
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_course_of_action] Missing parameters: stixObject"
            )
            return None
