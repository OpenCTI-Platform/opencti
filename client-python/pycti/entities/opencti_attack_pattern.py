# coding: utf-8

import json
import uuid

from stix2.canonicalization.Canonicalize import canonicalize


class AttackPattern:
    """Main AttackPattern class for OpenCTI

    Manages MITRE ATT&CK patterns and techniques in the OpenCTI platform.

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type opencti: OpenCTIApiClient
    """

    def __init__(self, opencti):
        """Initialize the AttackPattern instance.

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
            x_mitre_platforms
            x_mitre_permissions_required
            x_mitre_detection
            x_mitre_id
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
            x_mitre_platforms
            x_mitre_permissions_required
            x_mitre_detection
            x_mitre_id
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
                    }
                }
            }
        """

    @staticmethod
    def generate_id(name, x_mitre_id=None):
        """Generate a STIX ID for an Attack Pattern.

        :param name: The name of the attack pattern
        :type name: str
        :param x_mitre_id: Optional MITRE ATT&CK ID
        :type x_mitre_id: str or None
        :return: STIX ID for the attack pattern
        :rtype: str
        """
        if x_mitre_id is not None:
            data = {"x_mitre_id": x_mitre_id.strip()}
        else:
            data = {"name": name.lower().strip()}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "attack-pattern--" + id

    @staticmethod
    def generate_id_from_data(data):
        """Generate a STIX ID from attack pattern data.

        :param data: Dictionary containing 'name' and optionally 'x_mitre_id' keys
        :type data: dict
        :return: STIX ID for the attack pattern
        :rtype: str
        """
        external_id = data.get("x_mitre_id") or data.get("x_opencti_external_id")
        return AttackPattern.generate_id(data.get("name"), external_id)

    def list(self, **kwargs):
        """List Attack Pattern objects.

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
        :return: List of Attack Pattern objects
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
            "Listing Attack-Patterns with filters", {"filters": json.dumps(filters)}
        )
        query = (
            """
            query AttackPatterns($filters: FilterGroup, $search: String, $first: Int, $after: ID, $orderBy: AttackPatternsOrdering, $orderMode: OrderingMode) {
                attackPatterns(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
            data = self.opencti.process_multiple(result["data"]["attackPatterns"])
            final_data = final_data + data
            while result["data"]["attackPatterns"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["attackPatterns"]["pageInfo"]["endCursor"]
                self.opencti.app_logger.info(
                    "Listing Attack-Patterns", {"after": after}
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
                data = self.opencti.process_multiple(result["data"]["attackPatterns"])
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["attackPatterns"], with_pagination
            )

    def read(self, **kwargs):
        """Read an Attack Pattern object.

        :param id: the id of the Attack Pattern
        :type id: str
        :param filters: the filters to apply if no id provided
        :type filters: dict
        :param customAttributes: custom attributes to return
        :type customAttributes: str
        :param withFiles: whether to include files
        :type withFiles: bool
        :return: Attack Pattern object
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        with_files = kwargs.get("withFiles", False)
        if id is not None:
            self.opencti.app_logger.info("Reading Attack-Pattern", {"id": id})
            query = (
                """
                query AttackPattern($id: String!) {
                    attackPattern(id: $id) {
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
            return self.opencti.process_multiple_fields(result["data"]["attackPattern"])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.app_logger.error(
                "[opencti_attack_pattern] Missing parameters: id or filters"
            )
            return None

    def create(self, **kwargs):
        """Create an Attack Pattern object.

        :param stix_id: (optional) the STIX ID
        :type stix_id: str
        :param createdBy: (optional) the author ID
        :type createdBy: str
        :param objectMarking: (optional) list of marking definition IDs
        :type objectMarking: list
        :param objectLabel: (optional) list of label IDs
        :type objectLabel: list
        :param externalReferences: (optional) list of external reference IDs
        :type externalReferences: list
        :param revoked: (optional) whether the attack pattern is revoked
        :type revoked: bool
        :param confidence: (optional) confidence level (0-100)
        :type confidence: int
        :param lang: (optional) language
        :type lang: str
        :param created: (optional) creation date
        :type created: str
        :param modified: (optional) modification date
        :type modified: str
        :param name: the name of the Attack Pattern (required)
        :type name: str
        :param description: (optional) description
        :type description: str
        :param aliases: (optional) list of aliases
        :type aliases: list
        :param x_mitre_platforms: (optional) list of MITRE platforms
        :type x_mitre_platforms: list
        :param x_mitre_permissions_required: (optional) list of required permissions
        :type x_mitre_permissions_required: list
        :param x_mitre_detection: (optional) detection guidance
        :type x_mitre_detection: str
        :param x_mitre_id: (optional) MITRE ATT&CK ID
        :type x_mitre_id: str
        :param killChainPhases: (optional) list of kill chain phase IDs
        :type killChainPhases: list
        :param x_opencti_stix_ids: (optional) list of additional STIX IDs
        :type x_opencti_stix_ids: list
        :param objectOrganization: (optional) list of organization IDs
        :type objectOrganization: list
        :param x_opencti_workflow_id: (optional) workflow ID
        :type x_opencti_workflow_id: str
        :param x_opencti_modified_at: (optional) custom modification date
        :type x_opencti_modified_at: str
        :param update: (optional) whether to update if exists (default: False)
        :type update: bool
        :param file: (optional) File object to attach
        :type file: dict
        :param fileMarkings: (optional) list of marking definition IDs for the file
        :type fileMarkings: list
        :return: Attack Pattern object
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
        x_mitre_platforms = kwargs.get("x_mitre_platforms", None)
        x_mitre_permissions_required = kwargs.get("x_mitre_permissions_required", None)
        x_mitre_detection = kwargs.get("x_mitre_detection", None)
        x_mitre_id = kwargs.get("x_mitre_id", None)
        kill_chain_phases = kwargs.get("killChainPhases", None)
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        granted_refs = kwargs.get("objectOrganization", None)
        x_opencti_workflow_id = kwargs.get("x_opencti_workflow_id", None)
        x_opencti_modified_at = kwargs.get("x_opencti_modified_at", None)
        update = kwargs.get("update", False)
        file = kwargs.get("file", None)
        file_markings = kwargs.get("fileMarkings", None)

        if name is not None:
            self.opencti.app_logger.info("Creating Attack-Pattern", {"name": name})
            query = """
                mutation AttackPatternAdd($input: AttackPatternAddInput!) {
                    attackPatternAdd(input: $input) {
                        id
                        standard_id
                        entity_type
                        parent_types
                    }
                }
            """
            input_variables = {
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
                "x_mitre_platforms": x_mitre_platforms,
                "x_mitre_permissions_required": x_mitre_permissions_required,
                "x_mitre_detection": x_mitre_detection,
                "x_mitre_id": x_mitre_id,
                "killChainPhases": kill_chain_phases,
                "x_opencti_stix_ids": x_opencti_stix_ids,
                "x_opencti_workflow_id": x_opencti_workflow_id,
                "x_opencti_modified_at": x_opencti_modified_at,
                "update": update,
                "file": file,
                "fileMarkings": file_markings,
            }
            result = self.opencti.query(query, {"input": input_variables})
            return self.opencti.process_multiple_fields(
                result["data"]["attackPatternAdd"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_attack_pattern] Missing parameters: name"
            )
            return None

    def import_from_stix2(self, **kwargs):
        """Import an Attack Pattern object from a STIX2 object.

        :param stixObject: the STIX2 Attack Pattern object
        :type stixObject: dict
        :param extras: extra parameters including created_by_id, object_marking_ids, etc.
        :type extras: dict
        :param update: whether to update if the entity already exists
        :type update: bool
        :return: Attack Pattern object
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
                    if external_reference["source_name"].startswith("mitre-"):
                        x_mitre_id = (
                            external_reference["external_id"]
                            if "external_id" in external_reference
                            else None
                        )

            # Search in extensions
            if "x_opencti_order" not in stix_object:
                stix_object["x_opencti_order"] = (
                    self.opencti.get_attribute_in_extension("order", stix_object)
                    if self.opencti.get_attribute_in_extension("order", stix_object)
                    is not None
                    else 0
                )
            if "x_mitre_platforms" not in stix_object:
                stix_object["x_mitre_platforms"] = (
                    self.opencti.get_attribute_in_mitre_extension(
                        "platforms", stix_object
                    )
                )
            if "x_mitre_permissions_required" not in stix_object:
                stix_object["x_mitre_permissions_required"] = (
                    self.opencti.get_attribute_in_mitre_extension(
                        "permissions_required", stix_object
                    )
                )
            if "x_mitre_detection" not in stix_object:
                stix_object["x_mitre_detection"] = (
                    self.opencti.get_attribute_in_mitre_extension(
                        "detection", stix_object
                    )
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
                aliases=self.opencti.stix2.pick_aliases(stix_object),
                x_mitre_platforms=(
                    stix_object["x_mitre_platforms"]
                    if "x_mitre_platforms" in stix_object
                    else (
                        stix_object["x_amitt_platforms"]
                        if "x_amitt_platforms" in stix_object
                        else None
                    )
                ),
                x_mitre_permissions_required=(
                    stix_object["x_mitre_permissions_required"]
                    if "x_mitre_permissions_required" in stix_object
                    else None
                ),
                x_mitre_detection=(
                    stix_object["x_mitre_detection"]
                    if "x_mitre_detection" in stix_object
                    else None
                ),
                x_mitre_id=x_mitre_id,
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
                file=extras.get("file"),
                fileMarkings=extras.get("fileMarkings"),
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_attack_pattern] Missing parameters: stixObject"
            )
            return None

    def delete(self, **kwargs):
        """Delete an Attack Pattern object.

        :param id: the id of the Attack Pattern to delete
        :type id: str
        :return: None
        """
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.app_logger.info("Deleting Attack Pattern", {"id": id})
            query = """
                 mutation AttackPatternEdit($id: ID!) {
                     attackPatternEdit(id: $id) {
                         delete
                     }
                 }
             """
            self.opencti.query(query, {"id": id})
        else:
            self.opencti.app_logger.error(
                "[opencti_attack_pattern] Missing parameters: id"
            )
            return None
