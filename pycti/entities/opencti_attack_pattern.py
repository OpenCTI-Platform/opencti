# coding: utf-8

import json
from pycti.utils.constants import CustomProperties
from pycti.utils.opencti_stix2 import SPEC_VERSION


class AttackPattern:
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
            confidence
            graph_data
            platform
            required_permission
            external_id
            created
            modified
            created_at
            updated_at
            killChainPhases {
                edges {
                    node {
                        id
                        entity_type
                        stix_id_key
                        kill_chain_name
                        phase_name
                        phase_order
                        created
                        modified
                    }
                    relation {
                        id
                    }
                }
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

        self.opencti.log(
            "info", "Listing Attack-Patterns with filters " + json.dumps(filters) + "."
        )
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
                self.opencti.log("info", "Listing Attack-Patterns after " + after)
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
            self.opencti.log("info", "Reading Attack-Pattern {" + id + "}.")
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
            self.opencti.log(
                "error", "[opencti_attack_pattern] Missing parameters: id or filters"
            )
            return None

    """
        Create a Attack-Pattern object

        :param name: the name of the Attack Pattern
        :return Attack-Pattern object
    """

    def create_raw(self, **kwargs):
        name = kwargs.get("name", None)
        description = kwargs.get("description", None)
        alias = kwargs.get("alias", None)
        platform = kwargs.get("platform", None)
        required_permission = kwargs.get("required_permission", None)
        external_id = kwargs.get("external_id", None)
        confidence = kwargs.get("confidence", 50)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by_ref = kwargs.get("createdByRef", None)
        marking_definitions = kwargs.get("markingDefinitions", None)
        tags = kwargs.get("tags", None)
        kill_chain_phases = kwargs.get("killChainPhases", None)

        if name is not None and description is not None:
            self.opencti.log("info", "Creating Attack-Pattern {" + name + "}.")
            query = """
                mutation AttackPatternAdd($input: AttackPatternAddInput) {
                    attackPatternAdd(input: $input) {
                        id
                        stix_id_key
                        entity_type
                        parent_types
                    }
                }
            """
            result = self.opencti.query(
                query,
                {
                    "input": {
                        "name": name,
                        "description": description,
                        "alias": alias,
                        "platform": platform,
                        "required_permission": required_permission,
                        "external_id": external_id,
                        "confidence": confidence,
                        "internal_id_key": id,
                        "stix_id_key": stix_id_key,
                        "created": created,
                        "modified": modified,
                        "createdByRef": created_by_ref,
                        "markingDefinitions": marking_definitions,
                        "tags": tags,
                        "killChainPhases": kill_chain_phases,
                    }
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["attackPatternAdd"]
            )
        else:
            self.opencti.log(
                "error",
                "[opencti_attack_pattern] Missing parameters: name and description",
            )

    """
        Create a Attack-Pattern object only if it not exists, update it on request

        :param name: the name of the Attack-Pattern
        :return Attack-Pattern object
    """

    def create(self, **kwargs):
        name = kwargs.get("name", None)
        description = kwargs.get("description", None)
        alias = kwargs.get("alias", None)
        platform = kwargs.get("platform", None)
        required_permission = kwargs.get("required_permission", None)
        external_id = kwargs.get("external_id", None)
        confidence = kwargs.get("confidence", 50)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by_ref = kwargs.get("createdByRef", None)
        marking_definitions = kwargs.get("markingDefinitions", None)
        tags = kwargs.get("tags", None)
        kill_chain_phases = kwargs.get("killChainPhases", None)
        update = kwargs.get("update", False)
        custom_attributes = """
            id
            entity_type
            name
            description 
            alias
            confidence
            createdByRef {
                node {
                    id
                }
            }
            ... on AttackPattern {
                 killChainPhases {
                    edges {
                        node {
                            id
                            kill_chain_name
                            phase_name
                        }
                    }
                }
                platform
                required_permission
                external_id       
            }
        """
        object_result = None
        if stix_id_key is not None:
            object_result = self.read(
                id=stix_id_key, customAttributes=custom_attributes
            )
        if object_result is None and external_id is not None:
            object_result = self.read(
                filters=[{"key": "external_id", "values": [external_id]}]
            )
        if object_result is None and name is not None:
            object_result = self.read(
                filters=[{"key": "name", "values": [name]}],
                customAttributes=custom_attributes,
            )
            if object_result is None:
                object_result = self.read(
                    filters=[{"key": "alias", "values": [name]}],
                    customAttributes=custom_attributes,
                )
            if object_result is not None:
                # Check kill chain phase
                if (
                    kill_chain_phases is not None
                    and "killChainPhasesIds" in object_result
                    and len(object_result["killChainPhasesIds"]) > 0
                ):
                    is_kill_chain_phase_match = False
                    for kill_chain_phase in kill_chain_phases:
                        for kill_chain_phase_id in object_result["killChainPhasesIds"]:
                            if kill_chain_phase_id == kill_chain_phase:
                                is_kill_chain_phase_match = True
                    if not is_kill_chain_phase_match:
                        object_result = None

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
                    description is not None
                    and object_result["description"] != description
                ):
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
                # platform
                if platform is not None and object_result["platform"] != platform:
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"], key="platform", value=platform
                    )
                    object_result["platform"] = platform
                # required_permission
                if (
                    required_permission is not None
                    and object_result["required_permission"] != required_permission
                ):
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"],
                        key="required_permission",
                        value=required_permission,
                    )
                    object_result["required_permission"] = required_permission
                # external_id
                if (
                    external_id is not None
                    and object_result["external_id"] != external_id
                ):
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"],
                        key="external_id",
                        value=str(external_id),
                    )
                    object_result["external_id"] = external_id
                # confidence
                if confidence is not None and object_result["confidence"] != confidence:
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"], key="confidence", value=str(confidence)
                    )
                    object_result["confidence"] = confidence
            return object_result
        else:
            return self.create_raw(
                name=name,
                description=description,
                alias=alias,
                platform=platform,
                required_permission=required_permission,
                external_id=external_id,
                confidence=confidence,
                id=id,
                stix_id_key=stix_id_key,
                created=created,
                modified=modified,
                createdByRef=created_by_ref,
                markingDefinitions=marking_definitions,
                tags=tags,
                killChainPhases=kill_chain_phases,
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
            external_id = None
            if CustomProperties.EXTERNAL_ID in stix_object:
                external_id = stix_object[CustomProperties.EXTERNAL_ID]
            if "external_references" in stix_object:
                for external_reference in stix_object["external_references"]:
                    if (
                        external_reference["source_name"] == "mitre-attack"
                        or external_reference["source_name"] == "mitre-pre-attack"
                        or external_reference["source_name"] == "amitt-attack"
                    ):
                        external_id = external_reference["external_id"]
            return self.create(
                name=stix_object["name"],
                description=self.opencti.stix2.convert_markdown(
                    stix_object["description"]
                )
                if "description" in stix_object
                else "",
                alias=self.opencti.stix2.pick_aliases(stix_object),
                platform=stix_object["x_mitre_platforms"]
                if "x_mitre_platforms" in stix_object
                else stix_object["x_amitt_platforms"]
                if "x_amitt_platforms" in stix_object
                else None,
                required_permission=stix_object["x_mitre_permissions_required"]
                if "x_mitre_permissions_required" in stix_object
                else None,
                external_id=external_id,
                confidence=stix_object["confidence"]
                if "confidence" in stix_object
                else None,
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
                killChainPhases=extras["kill_chain_phases_ids"]
                if "kill_chain_phases_ids" in extras
                else [],
                update=update,
            )
        else:
            self.opencti.log(
                "error", "[opencti_attack_pattern] Missing parameters: stixObject"
            )

    """
        Export an Attack-Pattern object in STIX2
    
        :param id: the id of the Attack-Pattern
        :return Attack-Pattern object
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
            attack_pattern = dict()
            attack_pattern["id"] = entity["stix_id_key"]
            attack_pattern["type"] = "attack-pattern"
            attack_pattern["spec_version"] = SPEC_VERSION
            if self.opencti.not_empty(entity["external_id"]):
                attack_pattern[CustomProperties.EXTERNAL_ID] = entity["external_id"]
            attack_pattern["name"] = entity["name"]
            if self.opencti.not_empty(entity["stix_label"]):
                attack_pattern["labels"] = entity["stix_label"]
            else:
                attack_pattern["labels"] = ["attack-pattern"]
            if self.opencti.not_empty(entity["description"]):
                attack_pattern["description"] = entity["description"]
            attack_pattern["created"] = self.opencti.stix2.format_date(
                entity["created"]
            )
            attack_pattern["modified"] = self.opencti.stix2.format_date(
                entity["modified"]
            )
            if self.opencti.not_empty(entity["platform"]):
                attack_pattern["x_mitre_platforms"] = entity["platform"]
            if self.opencti.not_empty(entity["required_permission"]):
                attack_pattern["x_mitre_permissions_required"] = entity[
                    "required_permission"
                ]
            if self.opencti.not_empty(entity["alias"]):
                attack_pattern[CustomProperties.ALIASES] = entity["alias"]
            attack_pattern[CustomProperties.ID] = entity["id"]
            return self.opencti.stix2.prepare_export(
                entity, attack_pattern, mode, max_marking_definition_entity
            )
        else:
            self.opencti.log(
                "error", "[opencti_attack_pattern] Missing parameters: id or entity"
            )
