# coding: utf-8

import json
import uuid
from typing import Union

from stix2.canonicalization.Canonicalize import canonicalize


class ThreatActorGroup:
    """Main ThreatActorGroup class for OpenCTI

    Manages threat actor group entities in the OpenCTI platform.

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
            threat_actor_types
            first_seen
            last_seen
            roles
            goals
            sophistication
            resource_level
            primary_motivation
            secondary_motivations
            personal_motivations
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
        """Generate a STIX ID for a Threat Actor Group.

        :param name: The name of the threat actor group
        :type name: str
        :return: STIX ID for the threat actor group
        :rtype: str
        """
        name = name.lower().strip()
        data = {"name": name, "opencti_type": "Threat-Actor-Group"}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "threat-actor--" + id

    @staticmethod
    def generate_id_from_data(data):
        """Generate a STIX ID from threat actor group data.

        :param data: Dictionary containing 'name' key
        :type data: dict
        :return: STIX ID for the threat actor group
        :rtype: str
        """
        return ThreatActorGroup.generate_id(data["name"])

    def list(self, **kwargs) -> dict:
        """List Threat-Actor-Group objects

        :param filters: (optional) the filters to apply
        :type filters: list
        :param search: (optional) a search keyword to apply for the listing
        :type search: str
        :param first: (optional) return the first n rows from the `after` ID
                            or the beginning if not set
        :type first: int
        :param after: (optional) OpenCTI object ID of the first row for pagination
        :type after: str
        :param orderBy: (optional) the field to order the response on
        :type orderBy: str
        :param orderMode: (optional) either "`asc`" or "`desc`"
        :type orderMode: str
        :param withPagination: (optional) switch to use pagination
        :type withPagination: bool
        :return: List of Threat-Actor-Group objects
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

        self.opencti.app_logger.info(
            "Listing Threat-Actors-Group with filters", {"filters": json.dumps(filters)}
        )
        query = (
            """
            query ThreatActorsGroup($filters: FilterGroup, $search: String, $first: Int, $after: ID, $orderBy: ThreatActorsOrdering, $orderMode: OrderingMode) {
                threatActorsGroup(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
            data = self.opencti.process_multiple(result["data"]["threatActorsGroup"])
            final_data = final_data + data
            while result["data"]["threatActorsGroup"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["threatActorsGroup"]["pageInfo"]["endCursor"]
                self.opencti.app_logger.info(
                    "Listing threatActorsGroup", {"after": after}
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
                data = self.opencti.process_multiple(
                    result["data"]["threatActorsGroup"]
                )
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["threatActorsGroup"], with_pagination
            )

    def read(self, **kwargs) -> Union[dict, None]:
        """Read a Threat-Actor-Group object

        read can be either used with a known OpenCTI entity `id` or by using a
        valid filter to search and return a single Threat-Actor-Group entity or None.

        Note: either `id` or `filters` is required.

        :param id: the id of the Threat-Actor-Group
        :type id: str
        :param filters: the filters to apply if no id provided
        :type filters: list
        :return: Threat-Actor-Group object
        :rtype: dict or None
        """

        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.app_logger.info("Reading Threat-Actor-Group", {"id": id})
            query = (
                """
                query ThreatActorGroup($id: String!) {
                    threatActorGroup(id: $id) {
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
            return self.opencti.process_multiple_fields(
                result["data"]["threatActorGroup"]
            )
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.app_logger.error(
                "[opencti_threat_actor_group] Missing parameters: id or filters"
            )
            return None

    def create(self, **kwargs):
        """Create a Threat-Actor-Group object

        The Threat-Actor-Group entity will only be created if it doesn't exists
        By setting `update` to `True` it acts like an upsert and updates
        fields of an existing Threat-Actor-Group entity.

        Note: `name` and `description` or `stix_id` is required.

        :param stix_id: stix2 id reference for the Threat-Actor-Group entity
        :type stix_id: str
        :param createdBy: (optional) id of the organization that created the knowledge
        :type createdBy: str
        :param objectMarking: (optional) list of OpenCTI marking definition ids
        :type objectMarking: list
        :param objectLabel: (optional) list of OpenCTI label ids
        :type objectLabel: list
        :param externalReferences: (optional) list of OpenCTI external references ids
        :type externalReferences: list
        :param revoked: is this entity revoked
        :type revoked: bool
        :param confidence: confidence level
        :type confidence: int
        :param lang: language
        :type lang: str
        :param created: (optional) date in OpenCTI date format
        :type created: str
        :param modified: (optional) date in OpenCTI date format
        :type modified: str
        :param name: name of the threat actor group
        :type name: str
        :param description: description of the threat actor group
        :type description: str
        :param aliases: (optional) list of alias names for the Threat-Actor-Group
        :type aliases: list
        :param threat_actor_types: (optional) list of threat actor types
        :type threat_actor_types: list
        :param first_seen: (optional) date in OpenCTI date format
        :type first_seen: str
        :param last_seen: (optional) date in OpenCTI date format
        :type last_seen: str
        :param roles: (optional) list of roles
        :type roles: list
        :param goals: (optional) list of goals
        :type goals: list
        :param sophistication: (optional) describe the actors sophistication in text
        :type sophistication: str
        :param resource_level: (optional) describe the actors resource_level in text
        :type resource_level: str
        :param primary_motivation: (optional) describe the actors primary_motivation in text
        :type primary_motivation: str
        :param secondary_motivations: (optional) describe the actors secondary_motivations in list of string
        :type secondary_motivations: list
        :param personal_motivations: (optional) describe the actors personal_motivations in list of strings
        :type personal_motivations: list
        :param update: (optional) choose to updated an existing Threat-Actor-Group entity, default `False`
        :type update: bool
        :return: Threat-Actor-Group object
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
        threat_actor_types = kwargs.get("threat_actor_types", None)
        first_seen = kwargs.get("first_seen", None)
        last_seen = kwargs.get("last_seen", None)
        roles = kwargs.get("roles", None)
        goals = kwargs.get("goals", None)
        sophistication = kwargs.get("sophistication", None)
        resource_level = kwargs.get("resource_level", None)
        primary_motivation = kwargs.get("primary_motivation", None)
        secondary_motivations = kwargs.get("secondary_motivations", None)
        personal_motivations = kwargs.get("personal_motivations", None)
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        granted_refs = kwargs.get("objectOrganization", None)
        x_opencti_workflow_id = kwargs.get("x_opencti_workflow_id", None)
        x_opencti_modified_at = kwargs.get("x_opencti_modified_at", None)
        update = kwargs.get("update", False)
        file = kwargs.get("file", None)
        file_markings = kwargs.get("fileMarkings", None)

        if name is not None:
            self.opencti.app_logger.info("Creating Threat-Actor-Group", {"name": name})
            query = """
                mutation ThreatActorGroupAdd($input: ThreatActorGroupAddInput!) {
                    threatActorGroupAdd(input: $input) {
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
                        "threat_actor_types": threat_actor_types,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "roles": roles,
                        "goals": goals,
                        "sophistication": sophistication,
                        "resource_level": resource_level,
                        "primary_motivation": primary_motivation,
                        "secondary_motivations": secondary_motivations,
                        "personal_motivations": personal_motivations,
                        "x_opencti_stix_ids": x_opencti_stix_ids,
                        "x_opencti_workflow_id": x_opencti_workflow_id,
                        "x_opencti_modified_at": x_opencti_modified_at,
                        "update": update,
                        "file": file,
                        "fileMarkings": file_markings,
                    }
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["threatActorGroupAdd"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_threat_actor_group] Missing parameters: name"
            )
            return None

    def import_from_stix2(self, **kwargs):
        """Import a Threat Actor Group object from a STIX2 object.

        :param stixObject: the STIX2 Threat Actor object
        :param extras: extra parameters including created_by_id, object_marking_ids, etc.
        :param update: whether to update if the entity already exists
        :return: Threat Actor Group object
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
                threat_actor_types=(
                    stix_object["threat_actor_types"]
                    if "threat_actor_types" in stix_object
                    else None
                ),
                first_seen=(
                    stix_object["first_seen"] if "first_seen" in stix_object else None
                ),
                last_seen=(
                    stix_object["last_seen"] if "last_seen" in stix_object else None
                ),
                roles=stix_object["roles"] if "roles" in stix_object else None,
                goals=stix_object["goals"] if "goals" in stix_object else None,
                sophistication=(
                    stix_object["sophistication"]
                    if "sophistication" in stix_object
                    else None
                ),
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
                personal_motivations=(
                    stix_object["personal_motivations"]
                    if "personal_motivations" in stix_object
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
                file=extras.get("file"),
                fileMarkings=extras.get("fileMarkings"),
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_threat_actor_group] Missing parameters: stixObject"
            )
            return None
