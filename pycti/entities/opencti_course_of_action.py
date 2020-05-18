# coding: utf-8

import json
from pycti.utils.constants import CustomProperties
from pycti.utils.opencti_stix2 import SPEC_VERSION


class CourseOfAction:
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
        List Course-Of-Action objects

        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Course-Of-Action objects
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
            "info",
            "Listing Course-Of-Actions with filters " + json.dumps(filters) + ".",
        )
        query = (
            """
            query CourseOfActions($filters: [CourseOfActionsFiltering], $search: String, $first: Int, $after: ID, $orderBy: CoursesOfActionOrdering, $orderMode: OrderingMode) {
                courseOfActions(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
            result["data"]["courseOfActions"], with_pagination
        )

    """
        Read a Course-Of-Action object
        
        :param id: the id of the Course-Of-Action
        :param filters: the filters to apply if no id provided
        :return Course-Of-Action object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.log("info", "Reading Course-Of-Action {" + id + "}.")
            query = (
                """
                query CourseOfAction($id: String!) {
                    courseOfAction(id: $id) {
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
            return self.opencti.process_multiple_fields(
                result["data"]["courseOfAction"]
            )
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.log(
                "error", "[opencti_course_of_action] Missing parameters: id or filters"
            )
            return None

    """
        Create a Course Of Action object

        :param name: the name of the Course Of Action
        :return Course Of Action object
    """

    def create_raw(self, **kwargs):
        name = kwargs.get("name", None)
        description = kwargs.get("description", None)
        alias = kwargs.get("alias", None)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by_ref = kwargs.get("createdByRef", None)
        marking_definitions = kwargs.get("markingDefinitions", None)
        tags = kwargs.get("tags", None)

        if name is not None and description is not None:
            self.opencti.log("info", "Creating Course Of Action {" + name + "}.")
            query = """
                mutation CourseOfActionAdd($input: CourseOfActionAddInput) {
                    courseOfActionAdd(input: $input) {
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
                result["data"]["courseOfActionAdd"]
            )
        else:
            self.opencti.log(
                "error",
                "[opencti_course_of_action] Missing parameters: name and description",
            )

    """
        Create a Course Of Action object only if it not exists, update it on request

        :param name: the name of the Course Of Action
        :return Course Of Action object
    """

    def create(self, **kwargs):
        name = kwargs.get("name", None)
        description = kwargs.get("description", None)
        alias = kwargs.get("alias", None)
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
        """
        object_result = self.opencti.stix_domain_entity.get_by_stix_id_or_name(
            types=["Course-Of-Action"],
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
            return object_result
        else:
            return self.create_raw(
                name=name,
                description=description,
                alias=alias,
                id=id,
                stix_id_key=stix_id_key,
                created=created,
                modified=modified,
                createdByRef=created_by_ref,
                markingDefinitions=marking_definitions,
                tags=tags,
            )

    """
        Export an Course-Of-Action object in STIX2
    
        :param id: the id of the Course-Of-Action
        :return Course-Of-Action object
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
            course_of_action = dict()
            course_of_action["id"] = entity["stix_id_key"]
            course_of_action["type"] = "course-of-action"
            course_of_action["spec_version"] = SPEC_VERSION
            course_of_action["name"] = entity["name"]
            if self.opencti.not_empty(entity["stix_label"]):
                course_of_action["labels"] = entity["stix_label"]
            else:
                course_of_action["labels"] = ["course-of-action"]
            if self.opencti.not_empty(entity["description"]):
                course_of_action["description"] = entity["description"]
            course_of_action["created"] = self.opencti.stix2.format_date(
                entity["created"]
            )
            course_of_action["modified"] = self.opencti.stix2.format_date(
                entity["modified"]
            )
            if self.opencti.not_empty(entity["alias"]):
                course_of_action[CustomProperties.ALIASES] = entity["alias"]
            course_of_action[CustomProperties.ID] = entity["id"]
            return self.opencti.stix2.prepare_export(
                entity, course_of_action, mode, max_marking_definition_entity
            )
        else:
            self.opencti.log("error", "Missing parameters: id or entity")
