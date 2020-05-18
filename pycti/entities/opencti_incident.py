# coding: utf-8

import json
from pycti.utils.constants import CustomProperties
from pycti.utils.opencti_stix2 import SPEC_VERSION


class Incident:
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
            objective
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
            observableRefs {
                edges {
                    node {
                        id
                        entity_type
                        stix_id_key
                        observable_value
                    }
                    relation {
                        id
                    }
                }
            }
        """

    """
        List Incident objects

        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Incident objects
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
            "info", "Listing Incidents with filters " + json.dumps(filters) + "."
        )
        query = (
            """
            query Incidents($filters: [IncidentsFiltering], $search: String, $first: Int, $after: ID, $orderBy: IncidentsOrdering, $orderMode: OrderingMode) {
                incidents(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
        return self.opencti.process_multiple(
            result["data"]["incidents"], with_pagination
        )

    """
        Read a Incident object
        
        :param id: the id of the Incident
        :param filters: the filters to apply if no id provided
        :return Incident object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.log("info", "Reading Incident {" + id + "}.")
            query = (
                """
                query Incident($id: String!) {
                    incident(id: $id) {
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
            return self.opencti.process_multiple_fields(result["data"]["incident"])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.log(
                "error", "[opencti_incident] Missing parameters: id or filters"
            )
            return None

    """
        Create a Incident object

        :param name: the name of the Incident
        :return Incident object
    """

    def create_raw(self, **kwargs):
        name = kwargs.get("name", None)
        description = kwargs.get("description", None)
        alias = kwargs.get("alias", None)
        first_seen = kwargs.get("first_seen", None)
        last_seen = kwargs.get("last_seen", None)
        objective = kwargs.get("objective", None)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by_ref = kwargs.get("createdByRef", None)
        marking_definitions = kwargs.get("markingDefinitions", None)
        tags = kwargs.get("tags", None)

        if name is not None and description is not None:
            self.opencti.log("info", "Creating Incident {" + name + "}.")
            query = """
                mutation IncidentAdd($input: IncidentAddInput) {
                    incidentAdd(input: $input) {
                        id
                        stix_id_key
                        entity_type
                        parent_types
                        observableRefs {
                            edges {
                                node {
                                    id
                                    entity_type
                                    stix_id_key
                                    observable_value
                                }
                                relation {
                                    id
                                }
                            }
                        }                 
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
                        "objective": objective,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
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
            return self.opencti.process_multiple_fields(result["data"]["incidentAdd"])
        else:
            self.opencti.log("error", "Missing parameters: name and description")

    """
         Create a Incident object only if it not exists, update it on request

         :param name: the name of the Incident
         :return Incident object
     """

    def create(self, **kwargs):
        name = kwargs.get("name", None)
        description = kwargs.get("description", None)
        alias = kwargs.get("alias", None)
        first_seen = kwargs.get("first_seen", None)
        last_seen = kwargs.get("last_seen", None)
        objective = kwargs.get("objective", None)
        id = kwargs.get("id", None)
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
            ... on Incident {
                first_seen
                last_seen
                objective
            }
        """
        object_result = self.opencti.stix_domain_entity.get_by_stix_id_or_name(
            types=["Incident"],
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
                # objective
                if objective is not None and object_result["objective"] != objective:
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"], key="objective", value=objective
                    )
                    object_result["objective"] = objective
            return object_result
        else:
            return self.create_raw(
                name=name,
                description=description,
                alias=alias,
                first_seen=first_seen,
                last_seen=last_seen,
                objective=objective,
                id=id,
                stix_id_key=stix_id_key,
                created=created,
                modified=modified,
                createdByRef=created_by_ref,
                markingDefinitions=marking_definitions,
                tags=tags,
            )

    """
        Add a Stix-Observable object to Incident object (observable_refs)

        :param id: the id of the Incident
        :param entity_id: the id of the Stix-Observable
        :return Boolean
    """

    def add_stix_observable(self, **kwargs):
        id = kwargs.get("id", None)
        incident = kwargs.get("incident", None)
        stix_observable_id = kwargs.get("stix_observable_id", None)
        if id is not None and stix_observable_id is not None:
            if incident is None:
                incident = self.read(id=id)
            if incident is None:
                self.opencti.log(
                    "error",
                    "[opencti_incident] Cannot add Object Ref, incident not found",
                )
                return False
            if stix_observable_id in incident["observableRefsIds"]:
                return True
            else:
                self.opencti.log(
                    "info",
                    "Adding Stix-Observable {"
                    + stix_observable_id
                    + "} to Incident {"
                    + id
                    + "}",
                )
                query = """
                   mutation IncidentEdit($id: ID!, $input: RelationAddInput) {
                       incidentEdit(id: $id) {
                            relationAdd(input: $input) {
                                id
                            }
                       }
                   }
                """
                self.opencti.query(
                    query,
                    {
                        "id": id,
                        "input": {
                            "fromRole": "observables_aggregation",
                            "toId": stix_observable_id,
                            "toRole": "soo",
                            "through": "observable_refs",
                        },
                    },
                )
                return True
        else:
            self.opencti.log(
                "error",
                "[opencti_incident] Missing parameters: id and stix_observable_id",
            )
            return False

    """
        Export an Incident object in STIX2
    
        :param id: the id of the Incident
        :return Incident object
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
            incident = dict()
            incident["id"] = entity["stix_id_key"]
            incident["type"] = "x-opencti-incident"
            incident["spec_version"] = SPEC_VERSION
            incident["name"] = entity["name"]
            if self.opencti.not_empty(entity["stix_label"]):
                incident["labels"] = entity["stix_label"]
            else:
                incident["labels"] = ["x-opencti-incident"]
            if self.opencti.not_empty(entity["alias"]):
                incident["aliases"] = entity["alias"]
            if self.opencti.not_empty(entity["description"]):
                incident["description"] = entity["description"]
            if self.opencti.not_empty(entity["objective"]):
                incident["objective"] = entity["objective"]
            if self.opencti.not_empty(entity["first_seen"]):
                incident["first_seen"] = self.opencti.stix2.format_date(
                    entity["first_seen"]
                )
            if self.opencti.not_empty(entity["last_seen"]):
                incident["last_seen"] = self.opencti.stix2.format_date(
                    entity["last_seen"]
                )
            incident["created"] = self.opencti.stix2.format_date(entity["created"])
            incident["modified"] = self.opencti.stix2.format_date(entity["modified"])
            incident[CustomProperties.ID] = entity["id"]
            return self.opencti.stix2.prepare_export(
                entity, incident, mode, max_marking_definition_entity
            )
        else:
            self.opencti.log("error", "Missing parameters: id or entity")
