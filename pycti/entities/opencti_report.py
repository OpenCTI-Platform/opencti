# coding: utf-8

import json

from dateutil.parser import parse
from pycti.utils.constants import CustomProperties
from pycti.utils.opencti_stix2 import SPEC_VERSION


class Report:
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
            report_class
            published
            object_status
            source_confidence_level
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
        List Report objects

        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Report objects
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
            "info", "Listing Reports with filters " + json.dumps(filters) + "."
        )
        query = (
            """
            query Reports($filters: [ReportsFiltering], $search: String, $first: Int, $after: ID, $orderBy: ReportsOrdering, $orderMode: OrderingMode) {
                reports(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
        return self.opencti.process_multiple(result["data"]["reports"], with_pagination)

    """
        Read a Report object

        :param id: the id of the Report
        :param filters: the filters to apply if no id provided
        :return Report object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.log("info", "Reading Report {" + id + "}.")
            query = (
                """
                query Report($id: String!) {
                    report(id: $id) {
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
            return self.opencti.process_multiple_fields(result["data"]["report"])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None

    """
        Read a Report object by stix_id or name

        :param type: the Stix-Domain-Entity type
        :param stix_id_key: the STIX ID of the Stix-Domain-Entity
        :param name: the name of the Stix-Domain-Entity
        :return Stix-Domain-Entity object
    """

    def get_by_stix_id_or_name(self, **kwargs):
        stix_id_key = kwargs.get("stix_id_key", None)
        name = kwargs.get("name", None)
        published = kwargs.get("published", None)
        custom_attributes = kwargs.get("customAttributes", None)
        object_result = None
        if stix_id_key is not None:
            object_result = self.read(
                id=stix_id_key, customAttributes=custom_attributes
            )
        if object_result is None and name is not None and published is not None:
            published_final = parse(published).strftime("%Y-%m-%d")
            object_result = self.read(
                filters=[
                    {"key": "name", "values": [name]},
                    {"key": "published_day", "values": [published_final]},
                ],
                customAttributes=custom_attributes,
            )
        return object_result

    """
        Check if a report already contains a STIX entity
        
        :return Boolean
    """

    def contains_stix_entity(self, **kwargs):
        id = kwargs.get("id", None)
        entity_id = kwargs.get("entity_id", None)
        if id is not None and entity_id is not None:
            self.opencti.log(
                "info",
                "Checking Stix-Entity {" + entity_id + "} in Report {" + id + "}",
            )
            query = """
                query ReportContainsStixDomainEntity($id: String!, $objectId: String!) {
                    reportContainsStixDomainEntity(id: $id, objectId: $objectId)
                }
            """
            result = self.opencti.query(query, {"id": id, "objectId": entity_id})
            if result["data"]["reportContainsStixDomainEntity"]:
                return True
            query = """
                query ReportContainsStixRelation($id: String!, $objectId: String!) {
                    reportContainsStixRelation(id: $id, objectId: $objectId)
                }
            """
            result = self.opencti.query(query, {"id": id, "objectId": entity_id})
            return result["data"]["reportContainsStixRelation"]
        else:
            self.opencti.log(
                "error", "[opencti_report] Missing parameters: id or entity_id",
            )

    """
        Check if a report already contains a STIX observable

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
                + "} in Report {"
                + id
                + "}",
            )
            query = """
                query ReportContainsStixObservable($id: String!, $objectId: String!) {
                    reportContainsStixObservable(id: $id, objectId: $objectId)
                }
            """
            result = self.opencti.query(
                query, {"id": id, "objectId": stix_observable_id}
            )
            return result["data"]["reportContainsStixObservable"]
        else:
            self.opencti.log(
                "error",
                "[opencti_report] Missing parameters: id or stix_observable_id",
            )

    """
        Create a Report object

        :param name: the name of the Report
        :return Report object
    """

    def create_raw(self, **kwargs):
        name = kwargs.get("name", None)
        description = kwargs.get("description", None)
        published = kwargs.get("published", None)
        report_class = kwargs.get("report_class", None)
        object_status = kwargs.get("object_status", None)
        source_confidence_level = kwargs.get("source_confidence_level", None)
        graph_data = kwargs.get("graph_data", None)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by_ref = kwargs.get("createdByRef", None)
        marking_definitions = kwargs.get("markingDefinitions", None)
        tags = kwargs.get("tags", None)

        if (
            name is not None
            and description is not None
            and published is not None
            and report_class is not None
        ):
            self.opencti.log("info", "Creating Report {" + name + "}.")
            query = """
                mutation ReportAdd($input: ReportAddInput) {
                    reportAdd(input: $input) {
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
                        "published": published,
                        "report_class": report_class,
                        "object_status": object_status,
                        "source_confidence_level": source_confidence_level,
                        "graph_data": graph_data,
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
            return self.opencti.process_multiple_fields(result["data"]["reportAdd"])
        else:
            self.opencti.log(
                "error",
                "[opencti_report] Missing parameters: name and description and published and report_class",
            )

    """
         Create a Report object only if it not exists, update it on request

         :param name: the name of the Report
         :param description: the description of the Report
         :param published: the publication date of the Report
         :return Report object
     """

    def create(self, **kwargs):
        name = kwargs.get("name", None)
        external_reference_id = kwargs.get("external_reference_id", None)
        description = kwargs.get("description", None)
        published = kwargs.get("published", None)
        report_class = kwargs.get("report_class", None)
        object_status = kwargs.get("object_status", None)
        source_confidence_level = kwargs.get("source_confidence_level", None)
        graph_data = kwargs.get("graph_data", None)
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
                types=["Report"],
                filters=[
                    {"key": "hasExternalReference", "values": [external_reference_id]}
                ],
                customAttributes=custom_attributes,
            )
        if object_result is None and name is not None:
            object_result = self.get_by_stix_id_or_name(
                stix_id_key=stix_id_key,
                name=name,
                published=published,
                custom_attributes=custom_attributes,
            )
        if object_result is not None:
            if update or object_result["createdByRefId"] == created_by_ref:
                if object_result["name"] != name:
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
            if external_reference_id is not None:
                self.opencti.stix_entity.add_external_reference(
                    id=object_result["id"], external_reference_id=external_reference_id,
                )
            return object_result
        else:
            report = self.create_raw(
                name=name,
                description=description,
                published=published,
                report_class=report_class,
                object_status=object_status,
                source_confidence_level=source_confidence_level,
                graph_data=graph_data,
                id=id,
                stix_id_key=stix_id_key,
                created=created,
                modified=modified,
                createdByRef=created_by_ref,
                markingDefinitions=marking_definitions,
                tags=tags,
            )
            if external_reference_id is not None:
                self.opencti.stix_entity.add_external_reference(
                    id=report["id"], external_reference_id=external_reference_id,
                )
            return report

    """
        Add a Stix-Entity object to Report object (object_refs)

        :param id: the id of the Report
        :param entity_id: the id of the Stix-Entity
        :return Boolean
    """

    def add_stix_entity(self, **kwargs):
        id = kwargs.get("id", None)
        report = kwargs.get("report", None)
        entity_id = kwargs.get("entity_id", None)
        if id is not None and entity_id is not None:
            if report is not None:
                if (
                    entity_id in report["objectRefsIds"]
                    or entity_id in report["relationRefsIds"]
                ):
                    return True
            else:
                if self.contains_stix_entity(id=id, entity_id=entity_id):
                    return True
            self.opencti.log(
                "info", "Adding Stix-Entity {" + entity_id + "} to Report {" + id + "}",
            )
            query = """
               mutation ReportEditRelationAdd($id: ID!, $input: RelationAddInput) {
                   reportEdit(id: $id) {
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
                "error", "[opencti_report] Missing parameters: id and entity_id"
            )
            return False

    """
        Add a Stix-Observable object to Report object (observable_refs)

        :param id: the id of the Report
        :param entity_id: the id of the Stix-Observable
        :return Boolean
    """

    def add_stix_observable(self, **kwargs):
        id = kwargs.get("id", None)
        report = kwargs.get("report", None)
        stix_observable_id = kwargs.get("stix_observable_id", None)
        if id is not None and stix_observable_id is not None:
            if report is not None:
                if stix_observable_id in report["observableRefsIds"]:
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
                + "} to Report {"
                + id
                + "}",
            )
            query = """
               mutation ReportEditRelationAdd($id: ID!, $input: RelationAddInput) {
                   reportEdit(id: $id) {
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
                "[opencti_report] Missing parameters: id and stix_observable_id",
            )
            return False

    """
        Import a Report object from a STIX2 object

        :param stixObject: the Stix-Object Report
        :return Report object
    """

    def import_from_stix2(self, **kwargs):
        stix_object = kwargs.get("stixObject", None)
        extras = kwargs.get("extras", {})
        update = kwargs.get("update", False)
        if stix_object is not None:
            return self.create(
                name=stix_object["name"],
                description=self.opencti.stix2.convert_markdown(
                    stix_object["description"]
                )
                if "description" in stix_object
                else "",
                published=stix_object["published"]
                if "published" in stix_object
                else "",
                report_class=stix_object[CustomProperties.REPORT_CLASS]
                if CustomProperties.REPORT_CLASS in stix_object
                else "Threat Report",
                object_status=stix_object[CustomProperties.OBJECT_STATUS]
                if CustomProperties.OBJECT_STATUS in stix_object
                else 0,
                source_confidence_level=stix_object[CustomProperties.SRC_CONF_LEVEL]
                if CustomProperties.SRC_CONF_LEVEL in stix_object
                else 1,
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
                tags=extras["tags_ids"] if "tags_ids" in extras else [],
                update=update,
            )
        else:
            self.opencti.log(
                "error", "[opencti_attack_pattern] Missing parameters: stixObject"
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
            report = dict()
            report["id"] = entity["stix_id_key"]
            report["type"] = "report"
            report["spec_version"] = SPEC_VERSION
            report["name"] = entity["name"]
            if self.opencti.not_empty(entity["stix_label"]):
                report["labels"] = entity["stix_label"]
            else:
                report["labels"] = ["report"]
            if self.opencti.not_empty(entity["description"]):
                report["description"] = entity["description"]
            report["published"] = self.opencti.stix2.format_date(entity["published"])
            report["created"] = self.opencti.stix2.format_date(entity["created"])
            report["modified"] = self.opencti.stix2.format_date(entity["modified"])
            if self.opencti.not_empty(entity["alias"]):
                report[CustomProperties.ALIASES] = entity["alias"]
            if self.opencti.not_empty(entity["report_class"]):
                report[CustomProperties.REPORT_CLASS] = entity["report_class"]
            if self.opencti.not_empty(entity["object_status"]):
                report[CustomProperties.OBJECT_STATUS] = entity["object_status"]
            if self.opencti.not_empty(entity["source_confidence_level"]):
                report[CustomProperties.SRC_CONF_LEVEL] = entity[
                    "source_confidence_level"
                ]
            if self.opencti.not_empty(entity["graph_data"]):
                report[CustomProperties.GRAPH_DATA] = entity["graph_data"]
            report[CustomProperties.ID] = entity["id"]
            return self.opencti.stix2.prepare_export(
                entity, report, mode, max_marking_definition_entity
            )
        else:
            self.opencti.log(
                "error", "[opencti_report] Missing parameters: id or entity"
            )
