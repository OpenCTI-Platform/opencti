# coding: utf-8

import datetime
import json
import uuid

from dateutil.parser import parse
from stix2.canonicalization.Canonicalize import canonicalize


class Report:
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
            report_types
            published
            objects {
                edges {
                    node {
                        ... on BasicObject {
                            id
                            entity_type
                            parent_types
                        }
                        ... on BasicRelationship {
                            id
                            entity_type
                            parent_types
                        }
                        ... on StixObject {
                            standard_id
                            spec_version
                            created_at
                            updated_at
                        }
                        ... on AttackPattern {
                            name
                        }
                        ... on Campaign {
                            name
                        }
                        ... on CourseOfAction {
                            name
                        }
                        ... on Individual {
                            name
                        }
                        ... on Organization {
                            name
                        }
                        ... on Sector {
                            name
                        }
                        ... on System {
                            name
                        }
                        ... on Indicator {
                            name
                        }
                        ... on Infrastructure {
                            name
                        }
                        ... on IntrusionSet {
                            name
                        }
                        ... on Position {
                            name
                        }
                        ... on City {
                            name
                        }
                        ... on Country {
                            name
                        }
                        ... on Region {
                            name
                        }
                        ... on Malware {
                            name
                        }
                        ... on ThreatActor {
                            name
                        }
                        ... on Tool {
                            name
                        }
                        ... on Vulnerability {
                            name
                        }
                        ... on Incident {
                            name
                        }
                        ... on StixCoreRelationship {
                            standard_id
                            spec_version
                            created_at
                            updated_at
                            relationship_type
                        }
                       ... on StixSightingRelationship {
                            standard_id
                            spec_version
                            created_at
                            updated_at
                        }
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
    def generate_id(name, published):
        name = name.lower().strip()
        if isinstance(published, datetime.datetime):
            published = published.isoformat()
        data = {"name": name, "published": published}
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
        return "report--" + id

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
        first = kwargs.get("first", 100)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        custom_attributes = kwargs.get("customAttributes", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)
        if get_all:
            first = 100

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
        if get_all:
            final_data = []
            data = self.opencti.process_multiple(result["data"]["reports"])
            final_data = final_data + data
            while result["data"]["reports"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["reports"]["pageInfo"]["endCursor"]
                self.opencti.log("info", "Listing Reports after " + after)
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
                data = self.opencti.process_multiple(result["data"]["reports"])
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["reports"], with_pagination
            )

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
        :param stix_id: the STIX ID of the Stix-Domain-Entity
        :param name: the name of the Stix-Domain-Entity
        :return Stix-Domain-Entity object
    """

    def get_by_stix_id_or_name(self, **kwargs):
        stix_id = kwargs.get("stix_id", None)
        name = kwargs.get("name", None)
        published = kwargs.get("published", None)
        custom_attributes = kwargs.get("customAttributes", None)
        object_result = None
        if stix_id is not None:
            object_result = self.read(id=stix_id, customAttributes=custom_attributes)
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
        Check if a report already contains a thing (Stix Object or Stix Relationship)

        :param id: the id of the Report
        :param stixObjectOrStixRelationshipId: the id of the Stix-Entity
        :return Boolean
    """

    def contains_stix_object_or_stix_relationship(self, **kwargs):
        id = kwargs.get("id", None)
        stix_object_or_stix_relationship_id = kwargs.get(
            "stixObjectOrStixRelationshipId", None
        )
        if id is not None and stix_object_or_stix_relationship_id is not None:
            self.opencti.log(
                "info",
                "Checking StixObjectOrStixRelationship {"
                + stix_object_or_stix_relationship_id
                + "} in Report {"
                + id
                + "}",
            )
            query = """
                query ReportContainsStixObjectOrStixRelationship($id: String!, $stixObjectOrStixRelationshipId: String!) {
                    reportContainsStixObjectOrStixRelationship(id: $id, stixObjectOrStixRelationshipId: $stixObjectOrStixRelationshipId)
                }
            """
            result = self.opencti.query(
                query,
                {
                    "id": id,
                    "stixObjectOrStixRelationshipId": stix_object_or_stix_relationship_id,
                },
            )
            return result["data"]["reportContainsStixObjectOrStixRelationship"]
        else:
            self.opencti.log(
                "error",
                "[opencti_report] Missing parameters: id or stixObjectOrStixRelationshipId",
            )

    """
        Create a Report object

        :param name: the name of the Report
        :return Report object
    """

    def create(self, **kwargs):
        stix_id = kwargs.get("stix_id", None)
        created_by = kwargs.get("createdBy", None)
        objects = kwargs.get("objects", None)
        object_marking = kwargs.get("objectMarking", None)
        object_label = kwargs.get("objectLabel", None)
        external_references = kwargs.get("externalReferences", None)
        revoked = kwargs.get("revoked", None)
        confidence = kwargs.get("confidence", None)
        lang = kwargs.get("lang", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        name = kwargs.get("name", None)
        description = kwargs.get("description", "")
        report_types = kwargs.get("report_types", None)
        published = kwargs.get("published", None)
        x_opencti_stix_ids = kwargs.get("x_opencti_stix_ids", None)
        update = kwargs.get("update", False)

        if name is not None and description is not None and published is not None:
            self.opencti.log("info", "Creating Report {" + name + "}.")
            query = """
                mutation ReportAdd($input: ReportAddInput) {
                    reportAdd(input: $input) {
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
                        "objects": objects,
                        "externalReferences": external_references,
                        "revoked": revoked,
                        "confidence": confidence,
                        "lang": lang,
                        "created": created,
                        "modified": modified,
                        "name": name,
                        "description": description,
                        "report_types": report_types,
                        "published": published,
                        "x_opencti_stix_ids": x_opencti_stix_ids,
                        "update": update,
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
        Add a Stix-Entity object to Report object (object_refs)

        :param id: the id of the Report
        :param stixObjectOrStixRelationshipId: the id of the Stix-Entity
        :return Boolean
    """

    def add_stix_object_or_stix_relationship(self, **kwargs):
        id = kwargs.get("id", None)
        stix_object_or_stix_relationship_id = kwargs.get(
            "stixObjectOrStixRelationshipId", None
        )
        if id is not None and stix_object_or_stix_relationship_id is not None:
            self.opencti.log(
                "info",
                "Adding StixObjectOrStixRelationship {"
                + stix_object_or_stix_relationship_id
                + "} to Report {"
                + id
                + "}",
            )
            query = """
               mutation ReportEditRelationAdd($id: ID!, $input: StixMetaRelationshipAddInput) {
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
                        "toId": stix_object_or_stix_relationship_id,
                        "relationship_type": "object",
                    },
                },
            )
            return True
        else:
            self.opencti.log(
                "error",
                "[opencti_report] Missing parameters: id and stixObjectOrStixRelationshipId",
            )
            return False

    """
        Remove a Stix-Entity object to Report object (object_refs)

        :param id: the id of the Report
        :param stixObjectOrStixRelationshipId: the id of the Stix-Entity
        :return Boolean
    """

    def remove_stix_object_or_stix_relationship(self, **kwargs):
        id = kwargs.get("id", None)
        stix_object_or_stix_relationship_id = kwargs.get(
            "stixObjectOrStixRelationshipId", None
        )
        if id is not None and stix_object_or_stix_relationship_id is not None:
            self.opencti.log(
                "info",
                "Removing StixObjectOrStixRelationship {"
                + stix_object_or_stix_relationship_id
                + "} to Report {"
                + id
                + "}",
            )
            query = """
               mutation ReportEditRelationDelete($id: ID!, $toId: StixRef!, $relationship_type: String!) {
                   reportEdit(id: $id) {
                        relationDelete(toId: $toId, relationship_type: $relationship_type) {
                            id
                        }
                   }
               }
            """
            self.opencti.query(
                query,
                {
                    "id": id,
                    "toId": stix_object_or_stix_relationship_id,
                    "relationship_type": "object",
                },
            )
            return True
        else:
            self.opencti.log(
                "error",
                "[opencti_report] Missing parameters: id and stixObjectOrStixRelationshipId",
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

            # Search in extensions
            if "x_opencti_stix_ids" not in stix_object:
                stix_object[
                    "x_opencti_stix_ids"
                ] = self.opencti.get_attribute_in_extension("stix_ids", stix_object)

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
                objects=extras["object_ids"] if "object_ids" in extras else [],
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
                report_types=stix_object["report_types"]
                if "report_types" in stix_object
                else None,
                published=stix_object["published"]
                if "published" in stix_object
                else None,
                x_opencti_stix_ids=stix_object["x_opencti_stix_ids"]
                if "x_opencti_stix_ids" in stix_object
                else None,
                update=update,
            )
        else:
            self.opencti.log("error", "[opencti_report] Missing parameters: stixObject")
