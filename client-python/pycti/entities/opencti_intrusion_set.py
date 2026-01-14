# coding: utf-8

import json
import uuid

from stix2.canonicalization.Canonicalize import canonicalize


class IntrusionSet:
    """Main IntrusionSet class for OpenCTI

    Manages intrusion sets (APT groups) in the OpenCTI platform.

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type opencti: OpenCTIApiClient
    """

    def __init__(self, opencti):
        """Initialize the IntrusionSet instance.

        :param opencti: OpenCTI API client instance
        :type opencti: OpenCTIApiClient
        """
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
            aliases
            first_seen
            last_seen
            goals
            resource_level
            primary_motivation
            secondary_motivations
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
            aliases
            first_seen
            last_seen
            goals
            resource_level
            primary_motivation
            secondary_motivations
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
        """Generate a STIX ID for an Intrusion Set.

        :param name: The name of the intrusion set
        :type name: str
        :return: STIX ID for the intrusion set
        :rtype: str
        """
        name = name.lower().strip()
        data = {"name": name}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "intrusion-set--" + id

    @staticmethod
    def generate_id_from_data(data):
        """Generate a STIX ID from intrusion set data.

        :param data: Dictionary containing 'name' key
        :type data: dict
        :return: STIX ID for the intrusion set
        :rtype: str
        """
        return IntrusionSet.generate_id(data["name"])

    def list(self, **kwargs):
        """List Intrusion Set objects.

        :param filters: the filters to apply
        :type filters: dict
        :param search: the search keyword
        :type search: str
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :type first: int
        :param after: ID of the first row for pagination
        :type after: str
        :param orderBy: field to order results by
        :type orderBy: str
        :param orderMode: ordering mode (asc/desc)
        :type orderMode: str
        :param customAttributes: custom attributes to return
        :type customAttributes: str
        :param getAll: whether to retrieve all results
        :type getAll: bool
        :param withPagination: whether to include pagination info
        :type withPagination: bool
        :param withFiles: whether to include files
        :type withFiles: bool
        :return: List of Intrusion Set objects
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
            "Listing Intrusion-Sets with filters", {"filters": json.dumps(filters)}
        )
        query = (
            """
            query IntrusionSets($filters: FilterGroup, $search: String, $first: Int, $after: ID, $orderBy: IntrusionSetsOrdering, $orderMode: OrderingMode) {
                intrusionSets(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
        variables = {
            "filters": filters,
            "search": search,
            "first": first,
            "after": after,
            "orderBy": order_by,
            "orderMode": order_mode,
        }
        result = self.opencti.query(query, variables)
        if get_all:
            final_data = []
            data = self.opencti.process_multiple(result["data"]["intrusionSets"])
            final_data = final_data + data
            while result["data"]["intrusionSets"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["intrusionSets"]["pageInfo"]["endCursor"]
                self.opencti.app_logger.debug(
                    "Listing Intrusion-Sets", {"after": after}
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
                data = self.opencti.process_multiple(result["data"]["intrusionSets"])
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["intrusionSets"], with_pagination
            )

    def read(self, **kwargs):
        """Read an Intrusion Set object.

        :param id: the id of the Intrusion Set
        :type id: str
        :param filters: the filters to apply if no id provided
        :type filters: dict
        :param customAttributes: custom attributes to return
        :type customAttributes: str
        :param withFiles: whether to include files
        :type withFiles: bool
        :return: Intrusion Set object
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        with_files = kwargs.get("withFiles", False)
        if id is not None:
            self.opencti.app_logger.info("Reading Intrusion-Set", {"id": id})
            query = (
                """
                query IntrusionSet($id: String!) {
                    intrusionSet(id: $id) {
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
            return self.opencti.process_multiple_fields(result["data"]["intrusionSet"])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.app_logger.error(
                "[opencti_intrusion_set] Missing parameters: id or filters"
            )
            return None

    def create(self, **kwargs):
        """Create an Intrusion Set object.

        :param stix_id: (optional) the STIX ID
        :type stix_id: str
        :param name: the name of the Intrusion Set (required)
        :type name: str
        :param description: description of the intrusion set
        :type description: str
        :param aliases: list of aliases
        :type aliases: list
        :param first_seen: first seen date
        :type first_seen: str
        :param last_seen: last seen date
        :type last_seen: str
        :param goals: goals of the intrusion set
        :type goals: list
        :param resource_level: resource level
        :type resource_level: str
        :param primary_motivation: primary motivation
        :type primary_motivation: str
        :param secondary_motivations: secondary motivations
        :type secondary_motivations: list
        :param createdBy: creator identity ID
        :type createdBy: str
        :param objectMarking: marking definition IDs
        :type objectMarking: list
        :param objectLabel: label IDs
        :type objectLabel: list
        :param externalReferences: external reference IDs
        :type externalReferences: list
        :param objectOrganization: organization IDs
        :type objectOrganization: list
        :param revoked: whether the intrusion set is revoked
        :type revoked: bool
        :param confidence: confidence level (0-100)
        :type confidence: int
        :param lang: language
        :type lang: str
        :param created: creation date
        :type created: str
        :param modified: modification date
        :type modified: str
        :param x_opencti_stix_ids: additional STIX IDs
        :type x_opencti_stix_ids: list
        :param x_opencti_workflow_id: workflow ID
        :type x_opencti_workflow_id: str
        :param x_opencti_modified_at: custom modification date
        :type x_opencti_modified_at: str
        :param update: whether to update existing intrusion set
        :type update: bool
        :param files: (optional) list of File objects to attach
        :type files: list
        :param filesMarkings: (optional) list of lists of marking definition IDs for each file
        :type filesMarkings: list
        :return: Intrusion Set object
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
        aliases = kwargs.get("aliases", None)
        first_seen = kwargs.get("first_seen", None)
        last_seen = kwargs.get("last_seen", None)
        goals = kwargs.get("goals", None)
        resource_level = kwargs.get("resource_level", None)
        primary_motivation = kwargs.get("primary_motivation", None)
        secondary_motivations = kwargs.get("secondary_motivations", None)
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        granted_refs = kwargs.get("objectOrganization", None)
        x_opencti_workflow_id = kwargs.get("x_opencti_workflow_id", None)
        x_opencti_modified_at = kwargs.get("x_opencti_modified_at", None)
        update = kwargs.get("update", False)
        files = kwargs.get("files", None)
        files_markings = kwargs.get("filesMarkings", None)
        upsert_operations = kwargs.get("upsert_operations", None)

        if name is not None:
            self.opencti.app_logger.info("Creating Intrusion-Set", {"name": name})
            query = """
                mutation IntrusionSetAdd($input: IntrusionSetAddInput!) {
                    intrusionSetAdd(input: $input) {
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
                        "aliases": aliases,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "goals": goals,
                        "resource_level": resource_level,
                        "primary_motivation": primary_motivation,
                        "secondary_motivations": secondary_motivations,
                        "x_opencti_stix_ids": x_opencti_stix_ids,
                        "x_opencti_workflow_id": x_opencti_workflow_id,
                        "x_opencti_modified_at": x_opencti_modified_at,
                        "update": update,
                        "files": files,
                        "filesMarkings": files_markings,
                        "upsertOperations": upsert_operations,
                    }
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["intrusionSetAdd"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_intrusion_set] Missing parameters: name"
            )
            return None

    def import_from_stix2(self, **kwargs):
        """Import an Intrusion Set object from a STIX2 object.

        :param stixObject: the STIX2 Intrusion Set object
        :type stixObject: dict
        :param extras: extra parameters including created_by_id, object_marking_ids, etc.
        :type extras: dict
        :param update: whether to update if the entity already exists
        :type update: bool
        :return: Intrusion Set object
        :rtype: dict or None
        """
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
            if "x_opencti_modified_at" not in stix_object:
                stix_object["x_opencti_modified_at"] = (
                    self.opencti.get_attribute_in_extension("modified_at", stix_object)
                )
            if "opencti_upsert_operations" not in stix_object:
                stix_object["opencti_upsert_operations"] = (
                    self.opencti.get_attribute_in_extension(
                        "opencti_upsert_operations", stix_object
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
                aliases=self.opencti.stix2.pick_aliases(stix_object),
                first_seen=(
                    stix_object["first_seen"] if "first_seen" in stix_object else None
                ),
                last_seen=(
                    stix_object["last_seen"] if "last_seen" in stix_object else None
                ),
                goals=stix_object["goals"] if "goals" in stix_object else None,
                resource_level=(
                    stix_object["resource_level"]
                    if "resource_level" in stix_object
                    else None
                ),
                primary_motivation=(
                    stix_object["primary_motivation"]
                    if "primary_motivation" in stix_object
                    else None
                ),
                secondary_motivations=(
                    stix_object["secondary_motivations"]
                    if "secondary_motivations" in stix_object
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
                upsert_operations=(
                    stix_object["opencti_upsert_operations"]
                    if "opencti_upsert_operations" in stix_object
                    else None
                ),
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_intrusion_set] Missing parameters: stixObject"
            )
            return None
