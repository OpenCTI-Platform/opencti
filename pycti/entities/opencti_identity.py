# coding: utf-8

import json
from pycti.utils.constants import CustomProperties


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
            created
            modified            
            created_at
            updated_at
            ... on Organization {
                organization_class
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
        get_all = kwargs.get("getAll", False)
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
            + self.properties
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
        return self.opencti.process_multiple(result["data"]["identities"])

    """
        Read a Identity object
        
        :param id: the id of the Identity
        :param filters: the filters to apply if no id provided
        :return Identity object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        if id is not None:
            self.opencti.log("info", "Reading Identity {" + id + "}.")
            query = (
                """
                query Identity($id: String!) {
                    identity(id: $id) {
                        """
                + self.properties
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
            self.opencti.log("error", "Missing parameters: id or filters")
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
        alias = kwargs.get("alias", None)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by_ref = kwargs.get("createdByRef", None)
        marking_definitions = kwargs.get("markingDefinitions", None)

        if name is not None and description is not None:
            self.opencti.log("info", "Creating Identity {" + name + "}.")
            query = (
                """
                mutation IdentityAdd($input: IdentityAddInput) {
                    identityAdd(input: $input) {
                         """
                + self.properties
                + """
                    }
                }
            """
            )
            result = self.opencti.query(
                query,
                {
                    "input": {
                        "name": name,
                        "description": description,
                        "alias": alias,
                        "type": type,
                        "internal_id_key": id,
                        "stix_id_key": stix_id_key,
                        "created": created,
                        "modified": modified,
                        "createdByRef": created_by_ref,
                        "markingDefinitions": marking_definitions,
                    }
                },
            )
            return self.opencti.process_multiple_fields(result["data"]["identityAdd"])
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
        alias = kwargs.get("alias", None)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by_ref = kwargs.get("createdByRef", None)
        marking_definitions = kwargs.get("markingDefinitions", None)
        update = kwargs.get("update", False)

        object_result = self.opencti.stix_domain_entity.get_by_stix_id_or_name(
            types=[type], stix_id_key=stix_id_key, name=name
        )
        if object_result is not None:
            if update:
                # name
                if object_result["name"] != name:
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"], key="name", value=name
                    )
                    object_result["name"] = name
                # description
                if object_result["description"] != description:
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"], key="description", value=description
                    )
                    object_result["description"] = description
                # alias
                if alias is not None and object_result["alias"] != alias:
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
            return object_result
        else:
            return self.create_raw(
                type=type,
                name=name,
                description=description,
                alias=alias,
                id=id,
                stix_id_key=stix_id_key,
                created=created,
                modified=modified,
                createdByRef=created_by_ref,
                markingDefinitions=marking_definitions,
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
            identity["name"] = entity["name"]
            identity["identity_class"] = identity_class
            if self.opencti.not_empty(entity["stix_label"]):
                identity["labels"] = entity["stix_label"]
            else:
                identity["labels"] = ["identity"]
            if self.opencti.not_empty(entity["description"]):
                identity["description"] = entity["description"]
            identity["created"] = self.opencti.stix2.format_date(entity["created"])
            identity["modified"] = self.opencti.stix2.format_date(entity["modified"])
            if self.opencti.not_empty(entity["alias"]):
                identity["aliases"] = entity["alias"]
            if (
                entity["entity_type"] == "organization"
                and "organization_class" in entity
            ):
                identity[CustomProperties.ORG_CLASS] = entity["organization_class"]
            identity[CustomProperties.IDENTITY_TYPE] = entity["entity_type"]
            identity[CustomProperties.ID] = entity["id"]
            return self.opencti.stix2.prepare_export(
                entity, identity, mode, max_marking_definition_entity
            )
        else:
            self.opencti.log("error", "Missing parameters: id or entity")
