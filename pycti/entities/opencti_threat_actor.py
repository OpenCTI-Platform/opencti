# coding: utf-8

import json

from typing import Union

from pycti.utils.constants import CustomProperties
from pycti.utils.opencti_stix2 import SPEC_VERSION


class ThreatActor:
    """Main ThreatActor class for OpenCTI

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    """

    def __init__(self, opencti):
        """Create an instance of ThreatActor
        """

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
            first_seen
            last_seen
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

    def list(self, **kwargs) -> dict:
        """List Threat-Actor objects

        The list method accepts the following \**kwargs:

        :param dict filters: (optional) the filters to apply
        :param str search: (optional) a search keyword to apply for the listing
        :param int first: (optional) return the first n rows from the `after` ID
                            or the beginning if not set
        :param str after: (optional) OpenCTI object ID of the first row for pagination
        :param str orderBy: (optional) the field to order the response on
        :param bool orderMode: (optional) either "`asc`" or "`desc`"
        :param bool getAll: (optional) switch to return the first 500 entries
        :param bool withPagination: (optional) switch to use pagination
        """

        filters = kwargs.get("filters", None)
        search = kwargs.get("search", None)
        first = kwargs.get("first", 500)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)
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
        return self.opencti.process_multiple(
            result["data"]["threatActors"], with_pagination
        )

    def read(self, **kwargs) -> Union[dict, None]:
        """Read a Threat-Actor object

        read can be either used with a known OpenCTI entity `id` or by using a
        valid filter to search and return a single Threat-Actor entity or None.

        The list method accepts the following \**kwargs.

        Note: either `id` or `filters` is required.

        :param str id: the id of the Threat-Actor
        :param dict filters: the filters to apply if no id provided
        """

        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.log("info", "Reading Threat-Actor {" + id + "}.")
            query = (
                """
                query ThreatActor($id: String!) {
                    threatActor(id: $id) {
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
            return self.opencti.process_multiple_fields(result["data"]["threatActor"])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.log(
                "error", "[opencti_threat_actor] Missing parameters: id or filters"
            )
            return None

    def _create_raw(self, **kwargs):
        """Create a Threat-Actor object
        """

        name = kwargs.get("name", None)
        description = kwargs.get("description", None)
        alias = kwargs.get("alias", None)
        first_seen = kwargs.get("first_seen", None)
        last_seen = kwargs.get("last_seen", None)
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
        tags = kwargs.get("tags", None)

        if name is not None and description is not None:
            self.opencti.log("info", "Creating Threat-Actor {" + name + "}.")
            query = """
                mutation ThreatActorAdd($input: ThreatActorAddInput) {
                    threatActorAdd(input: $input) {
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
                        "first_seen": first_seen,
                        "last_seen": last_seen,
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
                        "tags": tags,
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

    def create(self, **kwargs):
        """Create a Threat-Actor object

        The Threat-Actor entity will only be created if it doesn't exists
        By setting `update` to `True` it acts like an upsert and updates
        fields of an existing Threat-Actor entity.

        The create method accepts the following \**kwargs.

        Note: `name` and `description` or `stix_id_key` is required.

        :param str id: (optional) OpenCTI `id` for the Threat-Actor
        :param str name: the name of the Threat-Actor
        :param str description: descriptive text
        :param str stix_id_key: stix2 id reference for the Threat-Actor entity
        :param list alias: (optional) list of alias names for the Threat-Actor
        :param str first_seen: (optional) date in OpenCTI date format
        :param str last_seen: (optional) date in OpenCTI date format
        :param str goal: (optional) describe the actors goal in text
        :param str sophistication: (optional) describe the actors
                                   sophistication in text
        :param str resource_level: (optional) describe the actors
                                   resource_level in text
        :param str primary_motivation: (optional) describe the actors
                                       primary_motivation in text
        :param str secondary_motivation: (optional) describe the actors
                                         secondary_motivation in text
        :param str personal_motivation: (optional) describe the actors
                                        personal_motivation in text
        :param str created: (optional) date in OpenCTI date format
        :param str modified: (optional) date in OpenCTI date format
        :param str createdByRef: (optional) id of the organization that
                                 created the knowledge
        :param list markingDefinitions: (optional) list of OpenCTI marking
                                        definition ids
        :param tags: TODO (optional)
        :param bool update: (optional) choose to updated an existing
                            Threat-Actor entity, default `False`
        """

        id = kwargs.get("id", None)
        name = kwargs.get("name", None)
        description = kwargs.get("description", None)
        alias = kwargs.get("alias", None)
        first_seen = kwargs.get("first_seen", None)
        last_seen = kwargs.get("last_seen", None)
        goal = kwargs.get("goal", None)
        sophistication = kwargs.get("sophistication", None)
        resource_level = kwargs.get("resource_level", None)
        primary_motivation = kwargs.get("primary_motivation", None)
        secondary_motivation = kwargs.get("secondary_motivation", None)
        personal_motivation = kwargs.get("personal_motivation", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by_ref = kwargs.get("createdByRef", None)
        marking_definitions = kwargs.get("markingDefinitions", None)
        tags = kwargs.get("tags", None)
        update = kwargs.get("update", False)
        custom_attributes = """
            id
            entity_type
            name
            description
            alias
            createdByRef {
                node {
                    id
                }
            }
            ... on ThreatActor {
                first_seen
                last_seen
                goal
                sophistication
                resource_level
                primary_motivation
                secondary_motivation
                personal_motivation
            }
        """
        object_result = self.opencti.stix_domain_entity.get_by_stix_id_or_name(
            types=["Threat-Actor"],
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
                # first_seen
                if first_seen is not None and object_result["first_seen"] != first_seen:
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"], key="first_seen", value=first_seen
                    )
                    object_result["first_seen"] = first_seen
                # last_seen
                if last_seen is not None and object_result["last_seen"] != last_seen:
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"], key="last_seen", value=last_seen
                    )
                    object_result["last_seen"] = last_seen
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
            return self._create_raw(
                name=name,
                description=description,
                alias=alias,
                first_seen=first_seen,
                last_seen=last_seen,
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
                tags=tags,
            )

    def to_stix2(self, **kwargs):
        """Returns a Stix2 object for a Threat-Actor id

        Takes either an `id` or a Threat-Actor python object via `entity` and
        returns a stix2 representation of it.

        The to_stix2 method accepts the following \**kwargs.

        :param id: (optional) `id` of the Threat-Actor you want to convert to stix2
        :param mode: (optional) either `simple` or `full`, default: `simple`
        :param entity: (optional) Threat-Actor object to convert
        """
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
            threat_actor["spec_version"] = SPEC_VERSION
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
            if self.opencti.not_empty(entity["first_seen"]):
                threat_actor["first_seen"] = self.opencti.stix2.format_date(
                    entity["first_seen"]
                )
            if self.opencti.not_empty(entity["last_seen"]):
                threat_actor["last_seen"] = self.opencti.stix2.format_date(
                    entity["last_seen"]
                )
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
