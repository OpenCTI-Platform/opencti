# coding: utf-8

import json
import uuid

from stix2.canonicalization.Canonicalize import canonicalize

from pycti.utils.constants import IdentityTypes


class Identity:
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
                    x_opencti_reliability
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
            objectOrganization {
                id
                standard_id
                name
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
            identity_class
            name
            description
            x_opencti_aliases
            x_opencti_reliability
            contact_information
            ... on Individual {
                x_opencti_firstname
                x_opencti_lastname
            }
            ... on Organization {
                x_opencti_organization_type
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
                    x_opencti_reliability
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
            objectOrganization {
                id
                standard_id
                name
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
            identity_class
            name
            description
            x_opencti_aliases
            x_opencti_reliability
            contact_information
            ... on Individual {
                x_opencti_firstname
                x_opencti_lastname
            }
            ... on Organization {
                x_opencti_organization_type
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
    def generate_id(name, identity_class):
        data = {"name": name.lower().strip(), "identity_class": identity_class.lower()}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "identity--" + id

    @staticmethod
    def generate_id_from_data(data):
        return Identity.generate_id(data["name"], data["identity_class"])

    """
        List Identity objects

        :param types: the list of types
        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Identity objects
    """

    def list(self, **kwargs):
        types = kwargs.get("types", None)
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
            "Listing Identities with filters", {"filters": json.dumps(filters)}
        )
        query = (
            """
            query Identities($types: [String], $filters: FilterGroup, $search: String, $first: Int, $after: ID, $orderBy: IdentitiesOrdering, $orderMode: OrderingMode) {
                identities(types: $types, filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
                "types": types,
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
            data = self.opencti.process_multiple(result["data"]["identities"])
            final_data = final_data + data
            while result["data"]["identities"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["identities"]["pageInfo"]["endCursor"]
                self.opencti.app_logger.info("Listing Identities", {"after": after})
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
                data = self.opencti.process_multiple(result["data"]["identities"])
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["identities"], with_pagination
            )

    """
        Read a Identity object

        :param id: the id of the Identity
        :param filters: the filters to apply if no id provided
        :return Identity object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        with_files = kwargs.get("withFiles", False)
        if id is not None:
            self.opencti.app_logger.info("Reading Identity", {"id": id})
            query = (
                """
                query Identity($id: String!) {
                    identity(id: $id) {
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
            return self.opencti.process_multiple_fields(result["data"]["identity"])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.app_logger.error(
                "[opencti_identity] Missing parameters: id or filters"
            )
            return None

    """
        Create a Identity object

        :param name: the name of the Identity
        :return Identity object
    """

    def create(self, **kwargs):
        type = kwargs.get("type", None)
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
        contact_information = kwargs.get("contact_information", None)
        roles = kwargs.get("roles", None)
        x_opencti_aliases = kwargs.get("x_opencti_aliases", None)
        x_opencti_organization_type = kwargs.get("x_opencti_organization_type", None)
        x_opencti_reliability = kwargs.get("x_opencti_reliability", None)
        x_opencti_firstname = kwargs.get("x_opencti_firstname", None)
        x_opencti_lastname = kwargs.get("x_opencti_lastname", None)
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        granted_refs = kwargs.get("objectOrganization", None)
        x_opencti_workflow_id = kwargs.get("x_opencti_workflow_id", None)
        update = kwargs.get("update", False)

        if type is not None and name is not None:
            self.opencti.app_logger.info("Creating Identity", {"name": name})
            input_variables = {
                "stix_id": stix_id,
                "createdBy": created_by,
                "objectMarking": object_marking,
                "objectLabel": object_label,
                "externalReferences": external_references,
                "revoked": revoked,
                "confidence": confidence,
                "lang": lang,
                "created": created,
                "modified": modified,
                "name": name,
                "description": description,
                "contact_information": contact_information,
                "roles": roles,
                "x_opencti_aliases": x_opencti_aliases,
                "x_opencti_stix_ids": x_opencti_stix_ids,
                "x_opencti_workflow_id": x_opencti_workflow_id,
                "update": update,
            }
            if type == IdentityTypes.ORGANIZATION.value:
                query = """
                    mutation OrganizationAdd($input: OrganizationAddInput!) {
                        organizationAdd(input: $input) {
                            id
                            standard_id
                            entity_type
                            parent_types
                        }
                    }
                """
                input_variables["x_opencti_organization_type"] = (
                    x_opencti_organization_type
                )
                input_variables["x_opencti_reliability"] = x_opencti_reliability
                result_data_field = "organizationAdd"
            elif type == IdentityTypes.INDIVIDUAL.value:
                query = """
                    mutation IndividualAdd($input: IndividualAddInput!) {
                        individualAdd(input: $input) {
                            id
                            standard_id
                            entity_type
                            parent_types
                        }
                    }
                """
                input_variables["objectOrganization"] = granted_refs
                input_variables["x_opencti_firstname"] = x_opencti_firstname
                input_variables["x_opencti_lastname"] = x_opencti_lastname
                input_variables["x_opencti_reliability"] = x_opencti_reliability
                result_data_field = "individualAdd"
            elif type == IdentityTypes.SYSTEM.value:
                query = """
                    mutation SystemAdd($input: SystemAddInput!) {
                        systemAdd(input: $input) {
                            id
                            standard_id
                            entity_type
                            parent_types
                        }
                    }
                """
                input_variables["objectOrganization"] = granted_refs
                input_variables["x_opencti_firstname"] = x_opencti_firstname
                input_variables["x_opencti_lastname"] = x_opencti_lastname
                input_variables["x_opencti_reliability"] = x_opencti_reliability
                result_data_field = "systemAdd"
            else:
                query = """
                    mutation IdentityAdd($input: IdentityAddInput!) {
                        identityAdd(input: $input) {
                            id
                            standard_id
                            entity_type
                            parent_types
                        }
                    }
                """
                input_variables["type"] = type
                result_data_field = "identityAdd"
            result = self.opencti.query(
                query,
                {
                    "input": input_variables,
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"][result_data_field]
            )
        else:
            self.opencti.app_logger.error(
                "Missing parameters: type, name and description"
            )

    """
        Import an Identity object from a STIX2 object

        :param stixObject: the Stix-Object Identity
        :return Identity object
    """

    def import_from_stix2(self, **kwargs):
        stix_object = kwargs.get("stixObject", None)
        extras = kwargs.get("extras", {})
        update = kwargs.get("update", False)
        if stix_object is not None:
            type = "Organization"
            if "identity_class" in stix_object:
                if stix_object["identity_class"] == "individual":
                    type = "Individual"
                elif stix_object["identity_class"] == "class":
                    type = "Sector"
                elif stix_object["identity_class"] == "system":
                    type = "System"

            # Search in extensions
            if "x_opencti_aliases" not in stix_object:
                stix_object["x_opencti_aliases"] = (
                    self.opencti.get_attribute_in_extension("aliases", stix_object)
                )
            if "x_opencti_organization_type" not in stix_object:
                stix_object["x_opencti_organization_type"] = (
                    self.opencti.get_attribute_in_extension(
                        "organization_type", stix_object
                    )
                )
            if "x_opencti_reliability" not in stix_object:
                stix_object["x_opencti_reliability"] = (
                    self.opencti.get_attribute_in_extension("reliability", stix_object)
                )
            if "x_opencti_organization_type" not in stix_object:
                stix_object["x_opencti_organization_type"] = (
                    self.opencti.get_attribute_in_extension(
                        "organization_type", stix_object
                    )
                )
            if "x_opencti_firstname" not in stix_object:
                stix_object["x_opencti_firstname"] = (
                    self.opencti.get_attribute_in_extension("firstname", stix_object)
                )
            if "x_opencti_lastname" not in stix_object:
                stix_object["x_opencti_lastname"] = (
                    self.opencti.get_attribute_in_extension("lastname", stix_object)
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

            return self.create(
                type=type,
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
                contact_information=(
                    self.opencti.stix2.convert_markdown(
                        stix_object["contact_information"]
                    )
                    if "contact_information" in stix_object
                    else None
                ),
                roles=stix_object["roles"] if "roles" in stix_object else None,
                x_opencti_aliases=self.opencti.stix2.pick_aliases(stix_object),
                x_opencti_organization_type=(
                    stix_object["x_opencti_organization_type"]
                    if "x_opencti_organization_type" in stix_object
                    else None
                ),
                x_opencti_reliability=(
                    stix_object["x_opencti_reliability"]
                    if "x_opencti_reliability" in stix_object
                    else None
                ),
                x_opencti_firstname=(
                    stix_object["x_opencti_firstname"]
                    if "x_opencti_firstname" in stix_object
                    else None
                ),
                x_opencti_lastname=(
                    stix_object["x_opencti_lastname"]
                    if "x_opencti_lastname" in stix_object
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
                update=update,
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_identity] Missing parameters: stixObject"
            )
