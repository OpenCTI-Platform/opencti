# coding: utf-8

import json
import uuid

from stix2.canonicalization.Canonicalize import canonicalize

from pycti.entities import LOGGER


class AttackPattern:
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
            aliases
            x_mitre_platforms
            x_mitre_permissions_required
            x_mitre_detection
            x_mitre_id
            killChainPhases {
                edges {
                    node {
                        id
                        standard_id
                        entity_type
                        kill_chain_name
                        phase_name
                        x_opencti_order
                        created
                        modified
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
    def generate_id(name, x_mitre_id=None):
        name = name.lower().strip()
        if x_mitre_id is not None:
            data = {"x_mitre_id": x_mitre_id}
        else:
            data = {"name": name}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "attack-pattern--" + id

    """
        List Attack-Pattern objects

        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Attack-Pattern objects
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

        LOGGER.info("Listing Attack-Patterns with filters %s.", json.dumps(filters))
        query = (
            """
            query AttackPatterns($filters: [AttackPatternsFiltering], $search: String, $first: Int, $after: ID, $orderBy: AttackPatternsOrdering, $orderMode: OrderingMode) {
                attackPatterns(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
            data = self.opencti.process_multiple(result["data"]["attackPatterns"])
            final_data = final_data + data
            while result["data"]["attackPatterns"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["attackPatterns"]["pageInfo"]["endCursor"]
                LOGGER.info("Listing Attack-Patterns after " + after)
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

    """
        Read a Attack-Pattern object

        :param id: the id of the Attack-Pattern
        :param filters: the filters to apply if no id provided
        :return Attack-Pattern object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            LOGGER.info("Reading Attack-Pattern {%s}.", id)
            query = (
                """
                query AttackPattern($id: String!) {
                    attackPattern(id: $id) {
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
            return self.opencti.process_multiple_fields(result["data"]["attackPattern"])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            LOGGER.error("[opencti_attack_pattern] Missing parameters: id or filters")
            return None

    """
        Create a Attack-Pattern object

        :param name: the name of the Attack Pattern
        :return Attack-Pattern object
    """

    def create(self, **kwargs):
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
        update = kwargs.get("update", False)

        if name is not None:
            LOGGER.info("Creating Attack-Pattern {%s}.", name)
            query = """
                mutation AttackPatternAdd($input: AttackPatternAddInput) {
                    attackPatternAdd(input: $input) {
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
                        "x_mitre_platforms": x_mitre_platforms,
                        "x_mitre_permissions_required": x_mitre_permissions_required,
                        "x_mitre_detection": x_mitre_detection,
                        "x_mitre_id": x_mitre_id,
                        "killChainPhases": kill_chain_phases,
                        "x_opencti_stix_ids": x_opencti_stix_ids,
                        "update": update,
                    }
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["attackPatternAdd"]
            )
        else:
            LOGGER.error(
                "[opencti_attack_pattern] Missing parameters: name and description"
            )

    """
        Import an Attack-Pattern object from a STIX2 object

        :param stixObject: the Stix-Object Attack-Pattern
        :return Attack-Pattern object
    """

    def import_from_stix2(self, **kwargs):
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
                        or external_reference["source_name"] == "mitre-ics-attack"
                        or external_reference["source_name"] == "amitt-attack"
                    ):
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
                stix_object[
                    "x_mitre_platforms"
                ] = self.opencti.get_attribute_in_mitre_extension(
                    "platforms", stix_object
                )
            if "x_mitre_permissions_required" not in stix_object:
                stix_object[
                    "x_mitre_permissions_required"
                ] = self.opencti.get_attribute_in_mitre_extension(
                    "permissions_required", stix_object
                )
            if "x_mitre_detection" not in stix_object:
                stix_object[
                    "x_mitre_detection"
                ] = self.opencti.get_attribute_in_mitre_extension(
                    "detection", stix_object
                )
            if "x_opencti_stix_ids" not in stix_object:
                stix_object[
                    "x_opencti_stix_ids"
                ] = self.opencti.get_attribute_in_extension("stix_ids", stix_object)
            if "granted_refs" not in stix_object:
                stix_object["granted_refs"] = self.opencti.get_attribute_in_extension(
                    "granted_refs", stix_object
                )

            return self.create(
                stix_id=stix_object["id"],
                createdBy=extras["created_by_id"]
                if "created_by_id" in extras
                else None,
                objectMarking=extras["object_marking_ids"]
                if "object_marking_ids" in extras
                else None,
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
                x_mitre_platforms=stix_object["x_mitre_platforms"]
                if "x_mitre_platforms" in stix_object
                else stix_object["x_amitt_platforms"]
                if "x_amitt_platforms" in stix_object
                else None,
                x_mitre_permissions_required=stix_object["x_mitre_permissions_required"]
                if "x_mitre_permissions_required" in stix_object
                else None,
                x_mitre_detection=stix_object["x_mitre_detection"]
                if "x_mitre_detection" in stix_object
                else None,
                x_mitre_id=x_mitre_id,
                killChainPhases=extras["kill_chain_phases_ids"]
                if "kill_chain_phases_ids" in extras
                else None,
                x_opencti_stix_ids=stix_object["x_opencti_stix_ids"]
                if "x_opencti_stix_ids" in stix_object
                else None,
                objectOrganization=stix_object["granted_refs"]
                if "granted_refs" in stix_object
                else None,
                update=update,
            )
        else:
            LOGGER.error("[opencti_attack_pattern] Missing parameters: stixObject")

    def delete(self, **kwargs):
        id = kwargs.get("id", None)
        if id is not None:
            LOGGER.info("Deleting Attack Pattern {%s}.", id)
            query = """
                 mutation AttackPatternEdit($id: ID!) {
                     attackPatternEdit(id: $id) {
                         delete
                     }
                 }
             """
            self.opencti.query(query, {"id": id})
        else:
            LOGGER.error("[attack_pattern] Missing parameters: id")
            return None
