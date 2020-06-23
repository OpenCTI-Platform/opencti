# coding: utf-8

import json
from pycti.utils.constants import CustomProperties, IdentityTypes
from pycti.utils.opencti_stix2 import SPEC_VERSION


class Identity:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            stix_id_key
            stix_label
            entity_type
            parent_types
            name
            alias
            description
            contact_information
            created
            modified            
            created_at
            updated_at
            ... on Organization {
                organization_class
                reliability
            }
            createdByRef {
                node {
                    id
                    entity_type
                    stix_id_key
                    stix_label
                    name
                    alias
                    description
                    created
                    modified
                    ... on Organization {
                        organization_class
                        reliability
                    }
                }
                relation {
                    id
                }
            }            
            markingDefinitions {
                edges {
                    node {
                        id
                        entity_type
                        stix_id_key
                        definition_type
                        definition
                        level
                        color
                        created
                        modified
                    }
                    relation {
                        id
                    }
                }
            }
            tags {
                edges {
                    node {
                        id
                        tag_type
                        value
                        color
                    }
                    relation {
                        id
                    }
                }
            }
            externalReferences {
                edges {
                    node {
                        id
                        entity_type
                        stix_id_key
                        source_name
                        description
                        url
                        hash
                        external_id
                        created
                        modified
                    }
                    relation {
                        id
                    }
                }
            }
        """

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
        if get_all:
            first = 500

        self.opencti.log(
            "info", "Listing Identities with filters " + json.dumps(filters) + "."
        )
        query = (
            """
            query Identities($types: [String], $filters: [IdentitiesFiltering], $search: String, $first: Int, $after: ID, $orderBy: IdentitiesOrdering, $orderMode: OrderingMode) {
                identities(types: $types, filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
                "types": types,
                "filters": filters,
                "search": search,
                "first": first,
                "after": after,
                "orderBy": order_by,
                "orderMode": order_mode,
            },
        )
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
        if id is not None:
            self.opencti.log("info", "Reading Identity {" + id + "}.")
            query = (
                """
                query Identity($id: String!) {
                    identity(id: $id) {
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
            return self.opencti.process_multiple_fields(result["data"]["identity"])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.log(
                "error", "[opencti_identity] Missing parameters: id or filters"
            )
            return None

    """
        Create a Identity object

        :param name: the name of the Identity
        :return Identity object
    """

    def create_raw(self, **kwargs):
        type = kwargs.get("type", None)
        name = kwargs.get("name", None)
        description = kwargs.get("description", None)
        contact_information = kwargs.get("contact_information", None)
        alias = kwargs.get("alias", None)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by_ref = kwargs.get("createdByRef", None)
        marking_definitions = kwargs.get("markingDefinitions", None)
        tags = kwargs.get("tags", None)
        organization_class = kwargs.get("organization_class", None)
        reliability = kwargs.get("reliability", None)

        if name is not None and description is not None:
            self.opencti.log("info", "Creating Identity {" + name + "}.")
            input_variables = {
                "name": name,
                "description": description,
                "contact_information": contact_information,
                "alias": alias,
                "internal_id_key": id,
                "stix_id_key": stix_id_key,
                "created": created,
                "modified": modified,
                "createdByRef": created_by_ref,
                "markingDefinitions": marking_definitions,
                "tags": tags,
            }
            if type == IdentityTypes.ORGANIZATION.value:
                query = """
                    mutation OrganizationAdd($input: OrganizationAddInput) {
                        organizationAdd(input: $input) {
                            id
                            stix_id_key
                            entity_type
                            parent_types
                        }
                    }
                """
                input_variables["organization_class"] = organization_class
                input_variables["reliability"] = reliability
                result_data_field = "organizationAdd"
            else:
                query = """
                    mutation IdentityAdd($input: IdentityAddInput) {
                        identityAdd(input: $input) {
                            id
                            stix_id_key
                            entity_type
                            parent_types
                        }
                    }
                """
                input_variables["type"] = type
                result_data_field = "identityAdd"
            result = self.opencti.query(query, {"input": input_variables,},)
            return self.opencti.process_multiple_fields(
                result["data"][result_data_field]
            )
        else:
            self.opencti.log("error", "Missing parameters: name and description")

    """
        Create a  Identity object only if it not exists, update it on request

        :param name: the name of the Identity
        :return Identity object
    """

    def create(self, **kwargs):
        type = kwargs.get("type", None)
        name = kwargs.get("name", None)
        description = kwargs.get("description", None)
        contact_information = kwargs.get("contact_information", None)
        alias = kwargs.get("alias", None)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by_ref = kwargs.get("createdByRef", None)
        marking_definitions = kwargs.get("markingDefinitions", None)
        tags = kwargs.get("tags", None)
        organization_class = kwargs.get("organization_class", None)
        reliability = kwargs.get("reliability", None)
        update = kwargs.get("update", False)
        custom_attributes = """
            id
            stix_id_key
            entity_type
            name
            description 
            alias
            ... on Identity {
                contact_information
            }
            ... on Organization {
                organization_class
                reliability
            }
            createdByRef {
                node {
                    id
                }
            }            
        """
        object_result = self.opencti.stix_domain_entity.get_by_stix_id_or_name(
            types=[type],
            stix_id_key=stix_id_key,
            name=name,
            customAttributes=custom_attributes,
        )
        if object_result is not None:
            if update or object_result["createdByRefId"] == created_by_ref:
                # name
                if object_result["name"] != name:
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"], key="name", value=name
                    )
                    object_result["name"] = name
                # description
                if (
                    self.opencti.not_empty(description)
                    and object_result["description"] != description
                ):
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"], key="description", value=description
                    )
                    object_result["description"] = description
                # contact_information
                if (
                    self.opencti.not_empty(contact_information)
                    and object_result["contact_information"] != contact_information
                ):
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"],
                        key="contact_information",
                        value=contact_information,
                    )
                    object_result["contact_information"] = contact_information
                # alias
                if self.opencti.not_empty(alias) and object_result["alias"] != alias:
                    if "alias" in object_result:
                        new_aliases = object_result["alias"] + list(
                            set(alias) - set(object_result["alias"])
                        )
                    else:
                        new_aliases = alias
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"], key="alias", value=new_aliases
                    )
                    object_result["alias"] = new_aliases
                # organization_class
                if (
                    self.opencti.not_empty(organization_class)
                    and "organization_class" in object_result
                    and object_result["organization_class"] != organization_class
                ):
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"],
                        key="organization_class",
                        value=organization_class,
                    )
                    object_result["organization_class"] = organization_class
                # reliability
                if (
                    self.opencti.not_empty(reliability)
                    and "reliability" in object_result
                    and object_result["reliability"] != reliability
                ):
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"], key="reliability", value=reliability,
                    )
                    object_result["reliability"] = reliability
            return object_result
        else:
            return self.create_raw(
                type=type,
                name=name,
                description=description,
                contact_information=contact_information,
                alias=alias,
                id=id,
                stix_id_key=stix_id_key,
                created=created,
                modified=modified,
                createdByRef=created_by_ref,
                markingDefinitions=marking_definitions,
                tags=tags,
                organization_class=organization_class,
                reliability=reliability,
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
            if CustomProperties.IDENTITY_TYPE in stix_object:
                type = stix_object[CustomProperties.IDENTITY_TYPE].capitalize()
            else:
                if stix_object["identity_class"] == "individual":
                    type = "User"
                elif stix_object["identity_class"] == "organization":
                    type = "Organization"
                elif stix_object["identity_class"] == "group":
                    type = "Organization"
                elif stix_object["identity_class"] == "class":
                    type = "Sector"
                else:
                    return None
            return self.create(
                type=type,
                name=stix_object["name"],
                description=self.opencti.stix2.convert_markdown(
                    stix_object["description"]
                )
                if "description" in stix_object
                else "",
                contact_information=self.opencti.stix2.convert_markdown(
                    stix_object["contact_information"]
                )
                if "contact_information" in stix_object
                else "",
                alias=self.opencti.stix2.pick_aliases(stix_object),
                id=stix_object[CustomProperties.ID]
                if CustomProperties.ID in stix_object
                else None,
                stix_id_key=stix_object["id"] if "id" in stix_object else None,
                created=stix_object["created"] if "created" in stix_object else None,
                modified=stix_object["modified"] if "modified" in stix_object else None,
                createdByRef=extras["created_by_ref_id"]
                if "created_by_ref_id" in extras
                else None,
                markingDefinitions=extras["marking_definitions_ids"]
                if "marking_definitions_ids" in extras
                else [],
                tags=extras["tags_ids"] if "tags_ids" in extras else [],
                organization_class=stix_object[CustomProperties.ORG_CLASS]
                if CustomProperties.ORG_CLASS in stix_object
                else None,
                reliability=stix_object[CustomProperties.RELIABILITY]
                if CustomProperties.RELIABILITY in stix_object
                else None,
                update=update,
            )
        else:
            self.opencti.log(
                "error", "[opencti_identity] Missing parameters: stixObject"
            )

    """
        Export an Identity object in STIX2
    
        :param id: the id of the Identity
        :return Identity object
    """

    def to_stix2(self, **kwargs):
        id = kwargs.get("id", None)
        mode = kwargs.get("mode", "simple")
        max_marking_definition_entity = kwargs.get(
            "max_marking_definition_entity", None
        )
        entity = kwargs.get("entity", None)
        if id is not None and entity is None:
            entity = self.read(id=id)
        if entity is not None:
            if entity["entity_type"] == "user":
                identity_class = "individual"
            elif entity["entity_type"] == "sector":
                identity_class = "class"
            else:
                identity_class = "organization"
            identity = dict()
            identity["id"] = entity["stix_id_key"]
            identity["type"] = "identity"
            identity["spec_version"] = SPEC_VERSION
            identity["name"] = entity["name"]
            identity["identity_class"] = identity_class
            if self.opencti.not_empty(entity["stix_label"]):
                identity["labels"] = entity["stix_label"]
            else:
                identity["labels"] = ["identity"]
            if self.opencti.not_empty(entity["description"]):
                identity["description"] = entity["description"]
            if self.opencti.not_empty(entity["contact_information"]):
                identity["contact_information"] = entity["contact_information"]
            identity["created"] = self.opencti.stix2.format_date(entity["created"])
            identity["modified"] = self.opencti.stix2.format_date(entity["modified"])
            if self.opencti.not_empty(entity["alias"]):
                identity["aliases"] = entity["alias"]
            if entity["entity_type"] == "organization":
                if "organization_class" in entity and self.opencti.not_empty(
                    entity["organization_class"]
                ):
                    identity[CustomProperties.ORG_CLASS] = entity["organization_class"]
                if "reliability" in entity and self.opencti.not_empty(
                    entity["reliability"]
                ):
                    identity[CustomProperties.RELIABILITY] = entity["reliability"]
            identity[CustomProperties.IDENTITY_TYPE] = entity["entity_type"]
            identity[CustomProperties.ID] = entity["id"]
            return self.opencti.stix2.prepare_export(
                entity, identity, mode, max_marking_definition_entity
            )
        else:
            self.opencti.log("error", "Missing parameters: id or entity")
