# coding: utf-8

import json
import uuid

from stix2.canonicalization.Canonicalize import canonicalize


class Tool:
    """Main Tool class for OpenCTI

    Manages tools used by threat actors in the OpenCTI platform.

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
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
            tool_types
            tool_version
            killChainPhases {
              id
              standard_id
              entity_type
              kill_chain_name
              phase_name
              x_opencti_order
              created
              modified
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
                    }
                }
            }
        """

    @staticmethod
    def generate_id(name):
        """Generate a STIX ID for a Tool.

        :param name: The name of the tool
        :type name: str
        :return: STIX ID for the tool
        :rtype: str
        """
        name = name.lower().strip()
        data = {"name": name}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "tool--" + id

    @staticmethod
    def generate_id_from_data(data):
        """Generate a STIX ID from tool data.

        :param data: Dictionary containing 'name' key
        :type data: dict
        :return: STIX ID for the tool
        :rtype: str
        """
        return Tool.generate_id(data["name"])

    def list(self, **kwargs):
        """List Tool objects.

        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :param orderBy: field to order results by
        :param orderMode: ordering mode (asc/desc)
        :param customAttributes: custom attributes to return
        :param getAll: whether to retrieve all results
        :param withPagination: whether to include pagination info
        :return: List of Tool objects
        :rtype: list
        """
        filters = kwargs.get("filters", None)
        search = kwargs.get("search", None)
        first = kwargs.get("first", 100)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        custom_attributes = kwargs.get("customAttributes", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)

        self.opencti.app_logger.info(
            "Listing Tools with filters", {"filters": json.dumps(filters)}
        )
        query = (
            """
            query Tools($filters: FilterGroup, $search: String, $first: Int, $after: ID, $orderBy: ToolsOrdering, $orderMode: OrderingMode) {
                tools(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
            data = self.opencti.process_multiple(result["data"]["tools"])
            final_data = final_data + data
            while result["data"]["tools"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["tools"]["pageInfo"]["endCursor"]
                self.opencti.app_logger.debug("Listing Tools", {"after": after})
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
                data = self.opencti.process_multiple(result["data"]["tools"])
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["tools"], with_pagination
            )

    def read(self, **kwargs):
        """Read a Tool object.

        :param id: the id of the Tool
        :param filters: the filters to apply if no id provided
        :param customAttributes: custom attributes to return
        :return: Tool object
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.app_logger.info("Reading Tool", {"id": id})
            query = (
                """
                query Tool($id: String!) {
                    tool(id: $id) {
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
            return self.opencti.process_multiple_fields(result["data"]["tool"])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.app_logger.error(
                "[opencti_tool] Missing parameters: id or filters"
            )
            return None

    def create(self, **kwargs):
        """Create a Tool object.

        :param name: the name of the Tool
        :param description: description of the tool
        :param aliases: list of aliases
        :param tool_types: types of tool
        :param tool_version: version of the tool
        :param killChainPhases: kill chain phases
        :param createdBy: creator identity
        :param objectMarking: marking definitions
        :param objectLabel: labels
        :param externalReferences: external references
        :param update: whether to update existing tool
        :return: Tool object
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
        tool_types = kwargs.get("tool_types", None)
        tool_version = kwargs.get("tool_version", None)
        kill_chain_phases = kwargs.get("killChainPhases", None)
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        granted_refs = kwargs.get("objectOrganization", None)
        x_opencti_workflow_id = kwargs.get("x_opencti_workflow_id", None)
        x_opencti_modified_at = kwargs.get("x_opencti_modified_at", None)
        update = kwargs.get("update", False)

        if name is not None:
            self.opencti.app_logger.info("Creating Tool", {"name": name})
            query = """
                mutation ToolAdd($input: ToolAddInput!) {
                    toolAdd(input: $input) {
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
                        "tool_types": tool_types,
                        "tool_version": tool_version,
                        "killChainPhases": kill_chain_phases,
                        "x_opencti_stix_ids": x_opencti_stix_ids,
                        "x_opencti_workflow_id": x_opencti_workflow_id,
                        "x_opencti_modified_at": x_opencti_modified_at,
                        "update": update,
                    }
                },
            )
            return self.opencti.process_multiple_fields(result["data"]["toolAdd"])
        else:
            self.opencti.app_logger.error(
                "[opencti_tool] Missing parameters: name and description"
            )

    """
        Import an Tool object from a STIX2 object

        :param stixObject: the Stix-Object Tool
        :return Tool object
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
            if "x_opencti_modified_at" not in stix_object:
                stix_object["x_opencti_modified_at"] = (
                    self.opencti.get_attribute_in_extension("modified_at", stix_object)
                )

            return self.opencti.tool.create(
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
                tool_types=(
                    stix_object["tool_types"] if "tool_types" in stix_object else None
                ),
                tool_version=(
                    stix_object["tool_version"]
                    if "tool_version" in stix_object
                    else None
                ),
                killChainPhases=(
                    extras["kill_chain_phases_ids"]
                    if "kill_chain_phases_ids" in extras
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
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_tool] Missing parameters: stixObject"
            )
