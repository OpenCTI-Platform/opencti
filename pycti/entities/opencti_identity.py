# coding: utf-8

import json
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
                    name
                    aliases
                    description
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
            contact_information
            ... on Individual {
                x_opencti_firstname
                x_opencti_lastname
            }
            ... on Organization {
                x_opencti_organization_type
                x_opencti_reliability
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
        description = kwargs.get("description", "")
        aliases = kwargs.get("aliases", None)
        contact_information = kwargs.get("contact_information", None)
        x_opencti_organization_type = kwargs.get("x_opencti_organization_type", None)
        x_opencti_reliability = kwargs.get("x_opencti_reliability", None)
        x_opencti_firstname = kwargs.get("x_opencti_firstname", None)
        x_opencti_lastname = kwargs.get("x_opencti_lastname", None)
        if name is not None and description is not None:
            self.opencti.log("info", "Creating Identity {" + name + "}.")
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
                "aliases": aliases,
                "contact_information": contact_information,
            }
            if type == IdentityTypes.ORGANIZATION.value:
                query = """
                    mutation OrganizationAdd($input: OrganizationAddInput) {
                        organizationAdd(input: $input) {
                            id
                            standard_id
                            entity_type
                            parent_types
                        }
                    }
                """
                input_variables[
                    "x_opencti_organization_type"
                ] = x_opencti_organization_type
                input_variables["x_opencti_reliability"] = x_opencti_reliability
                result_data_field = "organizationAdd"
            elif type == IdentityTypes.INDIVIDUAL.value:
                query = """
                    mutation IndividualAdd($input: IndividualAddInput) {
                        individualAdd(input: $input) {
                            id
                            standard_id
                            entity_type
                            parent_types
                        }
                    }
                """
                input_variables["x_opencti_firstname"] = x_opencti_firstname
                input_variables["x_opencti_lastname"] = x_opencti_lastname
                result_data_field = "individualAdd"
            else:
                query = """
                    mutation IdentityAdd($input: IdentityAddInput) {
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
        stix_id = kwargs.get("stix_id", None)
        created_by = kwargs.get("createdBy", None)
        object_marking = kwargs.get("objectMarking", None)
        object_label = kwargs.get("objectLabel", None)
        external_references = kwargs.get("externalReferences", None)
        revoked = kwargs.get("revoked", False)
        confidence = kwargs.get("confidence", 0)
        lang = kwargs.get("lang", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        name = kwargs.get("name", None)
        description = kwargs.get("description", "")
        aliases = kwargs.get("aliases", None)
        contact_information = kwargs.get("contact_information", None)
        x_opencti_organization_type = kwargs.get("x_opencti_organization_type", None)
        x_opencti_reliability = kwargs.get("x_opencti_reliability", None)
        x_opencti_firstname = kwargs.get("x_opencti_firstname", None)
        x_opencti_lastname = kwargs.get("x_opencti_lastname", None)
        update = kwargs.get("update", False)
        custom_attributes = """
            id
            standard_id
            entity_type
            parent_types
            ... on Identity {
                name
                description 
                aliases
                contact_information
            }
            ... on Organization {
                x_opencti_organization_type
                x_opencti_reliability
            }
            ... on Individual {
                x_opencti_firstname
                x_opencti_lastname
            }
            createdBy {
                ... on Identity {
                    id
                }
            }
        """
        object_result = self.opencti.stix_domain_object.get_by_stix_id_or_name(
            types=[type],
            stix_id=stix_id,
            name=name,
            customAttributes=custom_attributes,
        )
        if object_result is not None:
            if update or object_result["createdById"] == created_by:
                # name
                if object_result["name"] != name:
                    self.opencti.stix_domain_object.update_field(
                        id=object_result["id"], key="name", value=name
                    )
                    object_result["name"] = name
                # description
                if (
                    self.opencti.not_empty(description)
                    and object_result["description"] != description
                ):
                    self.opencti.stix_domain_object.update_field(
                        id=object_result["id"], key="description", value=description
                    )
                    object_result["description"] = description
                # aliases
                if (
                    self.opencti.not_empty(aliases)
                    and object_result["aliases"] != aliases
                ):
                    if "aliases" in object_result:
                        new_aliases = object_result["aliases"] + list(
                            set(aliases) - set(object_result["aliases"])
                        )
                    else:
                        new_aliases = aliases
                    self.opencti.stix_domain_object.update_field(
                        id=object_result["id"], key="aliases", value=new_aliases
                    )
                    object_result["aliases"] = new_aliases
                # contact_information
                if (
                    self.opencti.not_empty(contact_information)
                    and object_result["contact_information"] != contact_information
                ):
                    self.opencti.stix_domain_object.update_field(
                        id=object_result["id"],
                        key="contact_information",
                        value=contact_information,
                    )
                    object_result["contact_information"] = contact_information
                # x_opencti_organization_type
                if (
                    self.opencti.not_empty(x_opencti_organization_type)
                    and "x_opencti_organization_type" in object_result
                    and object_result["x_opencti_organization_type"]
                    != x_opencti_organization_type
                ):
                    self.opencti.stix_domain_object.update_field(
                        id=object_result["id"],
                        key="x_opencti_organization_type",
                        value=x_opencti_organization_type,
                    )
                    object_result[
                        "x_opencti_organization_type"
                    ] = x_opencti_organization_type
                # x_opencti_reliability
                if (
                    self.opencti.not_empty(x_opencti_reliability)
                    and "x_opencti_reliability" in object_result
                    and object_result["x_opencti_reliability"] != x_opencti_reliability
                ):
                    self.opencti.stix_domain_object.update_field(
                        id=object_result["id"],
                        key="x_opencti_reliability",
                        value=x_opencti_reliability,
                    )
                    object_result["x_opencti_reliability"] = x_opencti_reliability
            return object_result
        else:
            return self.create_raw(
                type=type,
                stix_id=stix_id,
                createdBy=created_by,
                objectMarking=object_marking,
                objectLabel=object_label,
                externalReferences=external_references,
                revoked=revoked,
                confidence=confidence,
                lang=lang,
                created=created,
                modified=modified,
                name=name,
                description=description,
                aliases=aliases,
                contact_information=contact_information,
                x_opencti_organization_type=x_opencti_organization_type,
                x_opencti_reliability=x_opencti_reliability,
                x_opencti_firstname=x_opencti_firstname,
                x_opencti_lastname=x_opencti_lastname,
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
            return self.create(
                type=type,
                stix_id=stix_object["id"],
                createdBy=extras["created_by_id"]
                if "created_by_id" in extras
                else None,
                objectMarking=extras["object_marking_ids"]
                if "object_marking_ids" in extras
                else [],
                objectLabel=extras["object_label_ids"]
                if "object_label_ids" in extras
                else [],
                externalReferences=extras["external_references_ids"]
                if "external_references_ids" in extras
                else [],
                revoked=stix_object["revoked"] if "revoked" in stix_object else None,
                confidence=stix_object["confidence"]
                if "confidence" in stix_object
                else None,
                lang=stix_object["lang"] if "lang" in stix_object else None,
                created=stix_object["created"] if "created" in stix_object else None,
                modified=stix_object["modified"] if "modified" in stix_object else None,
                name=stix_object["name"],
                description=self.opencti.stix2.convert_markdown(
                    stix_object["description"]
                )
                if "description" in stix_object
                else "",
                aliases=self.opencti.stix2.pick_aliases(stix_object),
                contact_information=self.opencti.stix2.convert_markdown(
                    stix_object["contact_information"]
                )
                if "contact_information" in stix_object
                else None,
                x_opencti_organization_type=stix_object["x_opencti_organization_type"]
                if "x_opencti_organization_type" in stix_object
                else None,
                x_opencti_reliability=stix_object["x_opencti_reliability"]
                if "x_opencti_reliability" in stix_object
                else None,
                x_opencti_firstname=stix_object["x_opencti_firstname"]
                if "x_opencti_firstname" in stix_object
                else None,
                x_opencti_lastname=stix_object["x_opencti_lastname"]
                if "x_opencti_lastname" in stix_object
                else None,
                update=update,
            )
        else:
            self.opencti.log(
                "error", "[opencti_identity] Missing parameters: stixObject"
            )
