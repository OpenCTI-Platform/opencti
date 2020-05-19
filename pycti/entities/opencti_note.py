# coding: utf-8

import json

from pycti.utils.constants import CustomProperties
from pycti.utils.opencti_stix2 import SPEC_VERSION


class Note:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            stix_id_key
            entity_type
            stix_label
            name
            alias
            description
            content
            graph_data
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
            objectRefs {
                edges {
                    node {
                        id
                        stix_id_key
                        entity_type
                    }
                }
            }
            observableRefs {
                edges {
                    node {
                        id
                        stix_id_key
                        entity_type
                        observable_value
                    }
                }
            }
            relationRefs {
                edges {
                    node {
                        id
                        stix_id_key
                    }
                }
            }
        """

    """
        List Note objects

        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Note objects
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
            "info", "Listing Notes with filters " + json.dumps(filters) + "."
        )
        query = (
            """
            query Notes($filters: [NotesFiltering], $search: String, $first: Int, $after: ID, $orderBy: NotesOrdering, $orderMode: OrderingMode) {
                notes(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
        return self.opencti.process_multiple(result["data"]["notes"], with_pagination)

    """
        Read a Note object

        :param id: the id of the Note
        :param filters: the filters to apply if no id provided
        :return Note object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.log("info", "Reading Note {" + id + "}.")
            query = (
                """
                query Note($id: String!) {
                    note(id: $id) {
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
            return self.opencti.process_multiple_fields(result["data"]["note"])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None

    """
        Read a Note object by stix_id or name

        :param type: the Stix-Domain-Entity type
        :param stix_id_key: the STIX ID of the Stix-Domain-Entity
        :param name: the name of the Stix-Domain-Entity
        :return Stix-Domain-Entity object
    """

    def get_by_stix_id_or_name(self, **kwargs):
        stix_id_key = kwargs.get("stix_id_key", None)
        description = kwargs.get("description", None)
        content = kwargs.get("content", None)
        custom_attributes = kwargs.get("customAttributes", None)
        object_result = None
        if stix_id_key is not None:
            object_result = self.read(
                id=stix_id_key, customAttributes=custom_attributes
            )
        if object_result is None and description is not None and content is not None:
            object_result = self.read(
                filters=[
                    {"key": "description", "values": [description]},
                    {"key": "content", "values": [content]},
                ],
                customAttributes=custom_attributes,
            )
        return object_result

    """
        Check if a note already contains a STIX entity
        
        :return Boolean
    """

    def contains_stix_entity(self, **kwargs):
        id = kwargs.get("id", None)
        entity_id = kwargs.get("entity_id", None)
        if id is not None and entity_id is not None:
            self.opencti.log(
                "info", "Checking Stix-Entity {" + entity_id + "} in Note {" + id + "}",
            )
            query = """
                query NoteContainsStixDomainEntity($id: String!, $objectId: String!) {
                    noteContainsStixDomainEntity(id: $id, objectId: $objectId)
                }
            """
            result = self.opencti.query(query, {"id": id, "objectId": entity_id})
            if result["data"]["noteContainsStixDomainEntity"]:
                return True
            query = """
                query NoteContainsStixRelation($id: String!, $objectId: String!) {
                    noteContainsStixRelation(id: $id, objectId: $objectId)
                }
            """
            result = self.opencti.query(query, {"id": id, "objectId": entity_id})
            return result["data"]["noteContainsStixRelation"]
        else:
            self.opencti.log(
                "error", "[opencti_note] Missing parameters: id or entity_id",
            )

    """
        Check if a note already contains a STIX observable

        :return Boolean
    """

    def contains_stix_observable(self, **kwargs):
        id = kwargs.get("id", None)
        stix_observable_id = kwargs.get("stix_observable_id", None)
        if id is not None and stix_observable_id is not None:
            self.opencti.log(
                "info",
                "Checking Stix-Observable {"
                + stix_observable_id
                + "} in Note {"
                + id
                + "}",
            )
            query = """
                query NoteContainsStixObservable($id: String!, $objectId: String!) {
                    noteContainsStixObservable(id: $id, objectId: $objectId)
                }
            """
            result = self.opencti.query(
                query, {"id": id, "objectId": stix_observable_id}
            )
            return result["data"]["noteContainsStixObservable"]
        else:
            self.opencti.log(
                "error", "[opencti_note] Missing parameters: id or stix_observable_id",
            )

    """
        Create a Note object

        :param name: the name of the Note
        :return Note object
    """

    def create_raw(self, **kwargs):
        name = kwargs.get("name", None)
        description = kwargs.get("description", None)
        content = kwargs.get("content", None)
        graph_data = kwargs.get("graph_data", None)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by_ref = kwargs.get("createdByRef", None)
        marking_definitions = kwargs.get("markingDefinitions", None)

        if name is not None and description is not None and content is not None:
            self.opencti.log("info", "Creating Note {" + description + "}.")
            query = """
                mutation NoteAdd($input: NoteAddInput) {
                    noteAdd(input: $input) {
                        id
                        stix_id_key
                        entity_type
                        parent_types
                        observableRefs {
                            edges {
                                node {
                                    id
                                    stix_id_key
                                    entity_type
                                    observable_value
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
                        "content": content,
                        "graph_data": graph_data,
                        "internal_id_key": id,
                        "stix_id_key": stix_id_key,
                        "created": created,
                        "modified": modified,
                        "createdByRef": created_by_ref,
                        "markingDefinitions": marking_definitions,
                    }
                },
            )
            return self.opencti.process_multiple_fields(result["data"]["noteAdd"])
        else:
            self.opencti.log(
                "error",
                "[opencti_note] Missing parameters: name and description and published and note_class",
            )

    """
         Create a Note object only if it not exists, update it on request

         :param name: the name of the Note
         :param description: the description of the Note
         :param published: the publication date of the Note
         :return Note object
     """

    def create(self, **kwargs):
        name = kwargs.get("name", None)
        external_reference_id = kwargs.get("external_reference_id", None)
        description = kwargs.get("description", None)
        content = kwargs.get("content", None)
        graph_data = kwargs.get("graph_data", None)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by_ref = kwargs.get("createdByRef", None)
        marking_definitions = kwargs.get("markingDefinitions", None)
        update = kwargs.get("update", False)
        custom_attributes = """
            id
            entity_type
            name
            description 
            createdByRef {
                node {
                    id
                }
            }
            externalReferences {
                edges {
                    node {
                        id
                        stix_id_key
                        source_name
                        description
                        url
                    }
                }
            }
        """
        object_result = None
        if external_reference_id is not None:
            object_result = self.opencti.stix_domain_entity.read(
                types=["Note"],
                filters=[
                    {"key": "hasExternalReference", "values": [external_reference_id]}
                ],
                customAttributes=custom_attributes,
            )
        if object_result is None and description is not None and content is not None:
            object_result = self.get_by_stix_id_or_name(
                stix_id_key=stix_id_key,
                description=description,
                content=content,
                custom_attributes=custom_attributes,
            )
        if object_result is not None:
            if update or object_result["createdByRefId"] == created_by_ref:
                if name is not None and object_result["name"] != name:
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"], key="name", value=name
                    )
                    object_result["name"] = name
                if (
                    description is not None
                    and object_result["description"] != description
                ):
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"], key="description", value=description
                    )
                    object_result["description"] = description
                if content is not None and object_result["content"] != content:
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"], key="content", value=content
                    )
                    object_result["content"] = content
            if external_reference_id is not None:
                self.opencti.stix_entity.add_external_reference(
                    id=object_result["id"], external_reference_id=external_reference_id,
                )
            return object_result
        else:
            note = self.create_raw(
                name=name,
                description=description,
                content=content,
                graph_data=graph_data,
                id=id,
                stix_id_key=stix_id_key,
                created=created,
                modified=modified,
                createdByRef=created_by_ref,
                markingDefinitions=marking_definitions,
            )
            if external_reference_id is not None:
                self.opencti.stix_entity.add_external_reference(
                    id=note["id"], external_reference_id=external_reference_id,
                )
            return note

    """
        Add a Stix-Entity object to Note object (object_refs)

        :param id: the id of the Note
        :param entity_id: the id of the Stix-Entity
        :return Boolean
    """

    def add_stix_entity(self, **kwargs):
        id = kwargs.get("id", None)
        note = kwargs.get("note", None)
        entity_id = kwargs.get("entity_id", None)
        if id is not None and entity_id is not None:
            if note is not None:
                if (
                    entity_id in note["objectRefsIds"]
                    or entity_id in note["relationRefsIds"]
                ):
                    return True
            else:
                if self.contains_stix_entity(id=id, entity_id=entity_id):
                    return True
            self.opencti.log(
                "info", "Adding Stix-Entity {" + entity_id + "} to Note {" + id + "}",
            )
            query = """
               mutation NoteEdit($id: ID!, $input: RelationAddInput) {
                   noteEdit(id: $id) {
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
                        "fromRole": "knowledge_aggregation",
                        "toId": entity_id,
                        "toRole": "so",
                        "through": "object_refs",
                    },
                },
            )
            return True
        else:
            self.opencti.log(
                "error", "[opencti_note] Missing parameters: id and entity_id"
            )
            return False

    """
        Add a Stix-Observable object to Note object (observable_refs)

        :param id: the id of the Note
        :param entity_id: the id of the Stix-Observable
        :return Boolean
    """

    def add_stix_observable(self, **kwargs):
        id = kwargs.get("id", None)
        note = kwargs.get("note", None)
        stix_observable_id = kwargs.get("stix_observable_id", None)
        if id is not None and stix_observable_id is not None:
            if note is not None:
                if stix_observable_id in note["observableRefsIds"]:
                    return True
            else:
                if self.contains_stix_observable(
                    id=id, stix_observable_id=stix_observable_id
                ):
                    return True
            self.opencti.log(
                "info",
                "Adding Stix-Observable {"
                + stix_observable_id
                + "} to Note {"
                + id
                + "}",
            )
            query = """
               mutation NoteEdit($id: ID!, $input: RelationAddInput) {
                   noteEdit(id: $id) {
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
                "error", "[opencti_note] Missing parameters: id and stix_observable_id",
            )
            return False

    """
        Import a Note object from a STIX2 object

        :param stixObject: the Stix-Object Note
        :return Note object
    """

    def import_from_stix2(self, **kwargs):
        stix_object = kwargs.get("stixObject", None)
        extras = kwargs.get("extras", {})
        update = kwargs.get("update", False)
        if stix_object is not None:
            if CustomProperties.NAME in stix_object:
                name = stix_object[CustomProperties.NAME]
            elif "abstract" in stix_object:
                name = stix_object["abstract"]
            else:
                name = ""
            return self.create(
                description=self.opencti.stix2.convert_markdown(stix_object["abstract"])
                if "abstract" in stix_object
                else "",
                content=self.opencti.stix2.convert_markdown(stix_object["content"])
                if "content" in stix_object
                else "",
                name=name,
                graph_data=stix_object[CustomProperties.GRAPH_DATA]
                if CustomProperties.GRAPH_DATA in stix_object
                else "",
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
                update=update,
            )
        else:
            self.opencti.log(
                "error", "[opencti_attack_pattern] Missing parameters: stixObject"
            )

    """
        Export a Note object in STIX2

        :param id: the id of the Note
        :return Note object
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
            note = dict()
            note["id"] = entity["stix_id_key"]
            note["type"] = "note"
            note["spec_version"] = SPEC_VERSION
            note["content"] = entity["content"]
            if self.opencti.not_empty(entity["stix_label"]):
                note["labels"] = entity["stix_label"]
            else:
                note["labels"] = ["note"]
            if self.opencti.not_empty(entity["description"]):
                note["abstract"] = entity["description"]
            elif self.opencti.not_empty(entity["name"]):
                note["abstract"] = entity["name"]
            note["created"] = self.opencti.stix2.format_date(entity["created"])
            note["modified"] = self.opencti.stix2.format_date(entity["modified"])
            if self.opencti.not_empty(entity["alias"]):
                note[CustomProperties.ALIASES] = entity["alias"]
            if self.opencti.not_empty(entity["name"]):
                note[CustomProperties.NAME] = entity["name"]
            if self.opencti.not_empty(entity["graph_data"]):
                note[CustomProperties.GRAPH_DATA] = entity["graph_data"]
            note[CustomProperties.ID] = entity["id"]
            return self.opencti.stix2.prepare_export(
                entity, note, mode, max_marking_definition_entity
            )
        else:
            self.opencti.log("error", "[opencti_note] Missing parameters: id or entity")
