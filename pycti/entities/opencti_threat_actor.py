# coding: utf-8

import json
from pycti.utils.constants import CustomProperties


class ThreatActor:
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
            graph_data
            goal
            sophistication
            resource_level
            primary_motivation
            secondary_motivation
            personal_motivation
            created
            modified            
            created_at
            updated_at
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
        List Threat-Actor objects

        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Threat-Actor objects
    """

    def list(self, **kwargs):
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
            "info", "Listing Threat-Actors with filters " + json.dumps(filters) + "."
        )
        query = (
            """
            query ThreatActors($filters: [ThreatActorsFiltering], $search: String, $first: Int, $after: ID, $orderBy: ThreatActorsOrdering, $orderMode: OrderingMode) {
                threatActors(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
                "filters": filters,
                "search": search,
                "first": first,
                "after": after,
                "orderBy": order_by,
                "orderMode": order_mode,
            },
        )
        return self.opencti.process_multiple(result["data"]["threatActors"])

    """
        Read a Threat-Actor object
        
        :param id: the id of the Threat-Actor
        :param filters: the filters to apply if no id provided
        :return Threat-Actor object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        if id is not None:
            self.opencti.log("info", "Reading Threat-Actor {" + id + "}.")
            query = (
                """
                query ThreatActor($id: String!) {
                    threatActor(id: $id) {
                        """
                + self.properties
                + """
                    }
                }
             """
            )
            result = self.opencti.query(query, {"id": id})
            return self.opencti.process_multiple_fields(result["data"]["threatActor"])
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
        Create a Threat-Actor object

        :param name: the name of the Threat-Actor
        :return Threat-Actor object
    """

    def create_raw(self, **kwargs):
        name = kwargs.get("name", None)
        description = kwargs.get("description", None)
        alias = kwargs.get("alias", None)
        goal = kwargs.get("goal", None)
        sophistication = kwargs.get("sophistication", None)
        resource_level = kwargs.get("resource_level", None)
        primary_motivation = kwargs.get("primary_motivation", None)
        secondary_motivation = kwargs.get("secondary_motivation", None)
        personal_motivation = kwargs.get("personal_motivation", None)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by_ref = kwargs.get("createdByRef", None)
        marking_definitions = kwargs.get("markingDefinitions", None)

        if name is not None and description is not None:
            self.opencti.log("info", "Creating Threat-Actor {" + name + "}.")
            query = (
                """
                mutation ThreatActorAdd($input: ThreatActorAddInput) {
                    threatActorAdd(input: $input) {
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
                        "goal": goal,
                        "sophistication": sophistication,
                        "resource_level": resource_level,
                        "primary_motivation": primary_motivation,
                        "secondary_motivation": secondary_motivation,
                        "personal_motivation": personal_motivation,
                        "internal_id_key": id,
                        "stix_id_key": stix_id_key,
                        "created": created,
                        "modified": modified,
                        "createdByRef": created_by_ref,
                        "markingDefinitions": marking_definitions,
                    }
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["threatActorAdd"]
            )
        else:
            self.opencti.log(
                "error",
                "[opencti_threat_actor] Missing parameters: name and description",
            )

    """
        Create a Threat-Actor object only if it not exists, update it on request

        :param name: the name of the Threat-Actor
        :return Threat-Actor object
    """

    def create(self, **kwargs):
        name = kwargs.get("name", None)
        description = kwargs.get("description", None)
        alias = kwargs.get("alias", None)
        goal = kwargs.get("goal", None)
        sophistication = kwargs.get("sophistication", None)
        resource_level = kwargs.get("resource_level", None)
        primary_motivation = kwargs.get("primary_motivation", None)
        secondary_motivation = kwargs.get("secondary_motivation", None)
        personal_motivation = kwargs.get("personal_motivation", None)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by_ref = kwargs.get("createdByRef", None)
        marking_definitions = kwargs.get("markingDefinitions", None)
        update = kwargs.get("update", False)

        object_result = self.opencti.stix_domain_entity.get_by_stix_id_or_name(
            types=["Threat-Actor"], stix_id_key=stix_id_key, name=name
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
                # goal
                if goal is not None and object_result["goal"] != goal:
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"], key="goal", value=goal
                    )
                    object_result["goal"] = goal
                # sophistication
                if (
                    sophistication is not None
                    and object_result["sophistication"] != sophistication
                ):
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"],
                        key="sophistication",
                        value=sophistication,
                    )
                    object_result["sophistication"] = sophistication
                # resource_level
                if (
                    resource_level is not None
                    and object_result["resource_level"] != resource_level
                ):
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"],
                        key="resource_level",
                        value=resource_level,
                    )
                    object_result["resource_level"] = resource_level
                # primary_motivation
                if (
                    primary_motivation is not None
                    and object_result["primary_motivation"] != primary_motivation
                ):
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"],
                        key="primary_motivation",
                        value=primary_motivation,
                    )
                    object_result["primary_motivation"] = primary_motivation
                # secondary_motivation
                if (
                    secondary_motivation is not None
                    and object_result["secondary_motivation"] != secondary_motivation
                ):
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"],
                        key="secondary_motivation",
                        value=secondary_motivation,
                    )
                    object_result["secondary_motivation"] = secondary_motivation
                # personal_motivation
                if (
                    personal_motivation is not None
                    and object_result["personal_motivation"] != personal_motivation
                ):
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"],
                        key="personal_motivation",
                        value=personal_motivation,
                    )
                    object_result["personal_motivation"] = personal_motivation
            return object_result
        else:
            return self.create_raw(
                name=name,
                description=description,
                alias=alias,
                goal=goal,
                sophistication=sophistication,
                resource_level=resource_level,
                primary_motivation=primary_motivation,
                secondary_motivation=secondary_motivation,
                personal_motivation=personal_motivation,
                id=id,
                stix_id_key=stix_id_key,
                created=created,
                modified=modified,
                createdByRef=created_by_ref,
                markingDefinitions=marking_definitions,
            )

    """
        Export an Threat-Actor object in STIX2
    
        :param id: the id of the Threat-Actor
        :return Threat-Actor object
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
            threat_actor = dict()
            threat_actor["id"] = entity["stix_id_key"]
            threat_actor["type"] = "threat-actor"
            threat_actor["name"] = entity["name"]
            if self.opencti.not_empty(entity["stix_label"]):
                threat_actor["labels"] = entity["stix_label"]
            else:
                threat_actor["labels"] = ["threat-actor"]
            if self.opencti.not_empty(entity["alias"]):
                threat_actor["aliases"] = entity["alias"]
            if self.opencti.not_empty(entity["description"]):
                threat_actor["description"] = entity["description"]
            if self.opencti.not_empty(entity["goal"]):
                threat_actor["goals"] = entity["goal"]
            if self.opencti.not_empty(entity["sophistication"]):
                threat_actor["sophistication"] = entity["sophistication"]
            if self.opencti.not_empty(entity["resource_level"]):
                threat_actor["resource_level"] = entity["resource_level"]
            if self.opencti.not_empty(entity["primary_motivation"]):
                threat_actor["primary_motivation"] = entity["primary_motivation"]
            if self.opencti.not_empty(entity["secondary_motivation"]):
                threat_actor["secondary_motivations"] = entity["secondary_motivation"]
            threat_actor["created"] = self.opencti.stix2.format_date(entity["created"])
            threat_actor["modified"] = self.opencti.stix2.format_date(
                entity["modified"]
            )
            threat_actor[CustomProperties.ID] = entity["id"]
            return self.opencti.stix2.prepare_export(
                entity, threat_actor, mode, max_marking_definition_entity
            )
        else:
            self.opencti.log("error", "Missing parameters: id or entity")
