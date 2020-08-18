# coding: utf-8

import dateutil.parser
import datetime


class StixSightingRelationship:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            entity_type
            parent_types
            spec_version
            created_at
            updated_at
            standard_id
            description
            first_seen
            last_seen
            attribute_count
            x_opencti_negative
            created
            modified
            confidence
            createdBy {
                ... on Identity {
                    id
                    standard_id
                    entity_type
                    parent_types
                    name
                    aliases
                    description
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
                    }
                }
            }
            from {
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
                ... on XOpenCTIIncident {
                    name
                }           
                ... on StixCyberObservable {
                    observable_value
                }                     
                ... on StixCoreRelationship {
                    standard_id
                    spec_version
                    created_at
                    updated_at
                }
            }
            to {
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
                ... on XOpenCTIIncident {
                    name
                }
                ... on StixCyberObservable {
                    observable_value
                }
                ... on StixCoreRelationship {
                    standard_id
                    spec_version
                    created_at
                    updated_at
                }
            }
        """

    """
        List stix_sightings objects

        :param fromId: the id of the source entity of the relation
        :param toId: the id of the target entity of the relation
        :param firstSeenStart: the first_seen date start filter
        :param firstSeenStop: the first_seen date stop filter
        :param lastSeenStart: the last_seen date start filter
        :param lastSeenStop: the last_seen date stop filter
        :param inferred: includes inferred relations
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of stix_sighting objects
    """

    def list(self, **kwargs):
        from_id = kwargs.get("fromId", None)
        from_types = kwargs.get("fromTypes", None)
        to_id = kwargs.get("toId", None)
        to_types = kwargs.get("toTypes", None)
        first_seen_start = kwargs.get("firstSeenStart", None)
        first_seen_stop = kwargs.get("firstSeenStop", None)
        last_seen_start = kwargs.get("lastSeenStart", None)
        last_seen_stop = kwargs.get("lastSeenStop", None)
        filters = kwargs.get("filters", [])
        inferred = kwargs.get("inferred", None)
        first = kwargs.get("first", 500)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)
        if get_all:
            first = 500

        self.opencti.log(
            "info",
            "Listing stix_sighting with {type: stix_sighting, from_id: "
            + str(from_id)
            + ", to_id: "
            + str(to_id)
            + "}",
        )
        query = (
            """
                query StixSightingRelationships($fromId: String, $fromTypes: [String], $toId: String, $toTypes: [String], $firstSeenStart: DateTime, $firstSeenStop: DateTime, $lastSeenStart: DateTime, $lastSeenStop: DateTime, $inferred: Boolean, $filters: [StixSightingRelationshipsFiltering], $first: Int, $after: ID, $orderBy: StixSightingRelationshipsOrdering, $orderMode: OrderingMode) {
                    stixSightingRelationships(fromId: $fromId, fromTypes: $fromTypes, toId: $toId, toTypes: $toTypes, firstSeenStart: $firstSeenStart, firstSeenStop: $firstSeenStop, lastSeenStart: $lastSeenStart, lastSeenStop: $lastSeenStop, inferred: $inferred, filters: $filters, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
                "fromId": from_id,
                "fromTypes": from_types,
                "toId": to_id,
                "toTypes": to_types,
                "firstSeenStart": first_seen_start,
                "firstSeenStop": first_seen_stop,
                "lastSeenStart": last_seen_start,
                "lastSeenStop": last_seen_stop,
                "filters": filters,
                "inferred": inferred,
                "first": first,
                "after": after,
                "orderBy": order_by,
                "orderMode": order_mode,
            },
        )
        return self.opencti.process_multiple(
            result["data"]["stixSightingRelationships"], with_pagination
        )

    """
        Read a stix_sighting object

        :param id: the id of the stix_sighting
        :param fromId: the id of the source entity of the relation
        :param toId: the id of the target entity of the relation
        :param firstSeenStart: the first_seen date start filter
        :param firstSeenStop: the first_seen date stop filter
        :param lastSeenStart: the last_seen date start filter
        :param lastSeenStop: the last_seen date stop filter
        :param inferred: includes inferred relations
        :return stix_sighting object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        from_id = kwargs.get("fromId", None)
        to_id = kwargs.get("toId", None)
        first_seen_start = kwargs.get("firstSeenStart", None)
        first_seen_stop = kwargs.get("firstSeenStop", None)
        last_seen_start = kwargs.get("lastSeenStart", None)
        last_seen_stop = kwargs.get("lastSeenStop", None)
        inferred = kwargs.get("inferred", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.log("info", "Reading stix_sighting {" + id + "}.")
            query = (
                """
                    query StixSightingRelationship($id: String!) {
                        stixSightingRelationship(id: $id) {
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
                result["data"]["stixSightingRelationship"]
            )
        elif from_id is not None and to_id is not None:
            result = self.list(
                fromId=from_id,
                toId=to_id,
                firstSeenStart=first_seen_start,
                firstSeenStop=first_seen_stop,
                lastSeenStart=last_seen_start,
                lastSeenStop=last_seen_stop,
                inferred=inferred,
            )
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.log("error", "Missing parameters: id or from_id and to_id")
            return None

    """
        Create a stix_sighting object

        :param name: the name of the Attack Pattern
        :return stix_sighting object
    """

    def create_raw(self, **kwargs):
        from_id = kwargs.get("fromId", None)
        to_id = kwargs.get("toId", None)
        stix_id = kwargs.get("stix_id", None)
        description = kwargs.get("description", None)
        first_seen = kwargs.get("first_seen", None)
        last_seen = kwargs.get("last_seen", None)
        count = kwargs.get("count", None)
        x_opencti_negative = kwargs.get("x_opencti_negative", False)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        confidence = kwargs.get("confidence", None)
        created_by = kwargs.get("createdBy", None)
        object_marking = kwargs.get("objectMarking", None)
        object_label = kwargs.get("objectLabel", None)
        external_references = kwargs.get("externalReferences", None)

        self.opencti.log(
            "info", "Creating stix_sighting {" + from_id + ", " + str(to_id) + "}.",
        )
        query = """
                mutation StixSightingRelationshipAdd($input: StixSightingRelationshipAddInput!) {
                    stixSightingRelationshipAdd(input: $input) {
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
                    "fromId": from_id,
                    "toId": to_id,
                    "stix_id": stix_id,
                    "description": description,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "attribute_count": count,
                    "x_opencti_negative": x_opencti_negative,
                    "created": created,
                    "modified": modified,
                    "confidence": confidence,
                    "createdBy": created_by,
                    "objectMarking": object_marking,
                    "objectLabel": object_label,
                    "externalReferences": external_references,
                }
            },
        )
        return self.opencti.process_multiple_fields(
            result["data"]["stixSightingRelationshipAdd"]
        )

    """
        Create a stix_sighting object only if it not exists, update it on request

        :param name: the name of the stix_sighting
        :return stix_sighting object
    """

    def create(self, **kwargs):
        from_id = kwargs.get("fromId", None)
        to_id = kwargs.get("toId", None)
        stix_id = kwargs.get("stix_id", None)
        description = kwargs.get("description", None)
        first_seen = kwargs.get("first_seen", None)
        last_seen = kwargs.get("last_seen", None)
        count = kwargs.get("count", None)
        x_opencti_negative = kwargs.get("x_opencti_negative", False)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        confidence = kwargs.get("confidence", None)
        created_by = kwargs.get("createdBy", None)
        object_marking = kwargs.get("objectMarking", None)
        object_label = kwargs.get("objectLabel", None)
        external_references = kwargs.get("externalReferences", None)
        update = kwargs.get("update", False)
        ignore_dates = kwargs.get("ignore_dates", False)
        custom_attributes = """
            id
            standard_id
            entity_type
            parent_types
            first_seen
            last_seen
            x_opencti_negative
            attribute_count
            confidence
            createdBy {
                ... on Identity {
                    id
                }
            }       
        """
        stix_sighting_result = self.read(id=stix_id, customAttributes=custom_attributes)
        if stix_sighting_result is None and to_id is not None:
            if (
                ignore_dates is False
                and first_seen is not None
                and last_seen is not None
            ):
                first_seen_parsed = dateutil.parser.parse(first_seen)
                first_seen_start = (
                    first_seen_parsed + datetime.timedelta(days=-1)
                ).strftime("%Y-%m-%dT%H:%M:%S+00:00")
                first_seen_stop = (
                    first_seen_parsed + datetime.timedelta(days=1)
                ).strftime("%Y-%m-%dT%H:%M:%S+00:00")
                last_seen_parsed = dateutil.parser.parse(last_seen)
                last_seen_start = (
                    last_seen_parsed + datetime.timedelta(days=-1)
                ).strftime("%Y-%m-%dT%H:%M:%S+00:00")
                last_seen_stop = (
                    last_seen_parsed + datetime.timedelta(days=1)
                ).strftime("%Y-%m-%dT%H:%M:%S+00:00")
            else:
                first_seen_start = None
                first_seen_stop = None
                last_seen_start = None
                last_seen_stop = None
            stix_sighting_result = self.read(
                fromId=from_id,
                toId=to_id,
                firstSeenStart=first_seen_start,
                firstSeenStop=first_seen_stop,
                lastSeenStart=last_seen_start,
                lastSeenStop=last_seen_stop,
                customAttributes=custom_attributes,
            )
        if stix_sighting_result is not None:
            if update or stix_sighting_result["createdBy"] == created_by:
                if (
                    description is not None
                    and stix_sighting_result["description"] != description
                ):
                    self.update_field(
                        id=stix_sighting_result["id"],
                        key="description",
                        value=description,
                    )
                    stix_sighting_result["description"] = description
                if (
                    confidence is not None
                    and stix_sighting_result["confidence"] != confidence
                ):
                    self.update_field(
                        id=stix_sighting_result["id"],
                        key="confidence",
                        value=str(confidence),
                    )
                    stix_sighting_result["confidence"] = confidence
                if (
                    x_opencti_negative is not None
                    and stix_sighting_result["x_opencti_negative"] != x_opencti_negative
                ):
                    self.update_field(
                        id=stix_sighting_result["id"],
                        key="x_opencti_negative",
                        value=str(x_opencti_negative).lower(),
                    )
                    stix_sighting_result["x_opencti_negative"] = x_opencti_negative
                if (
                    count is not None
                    and stix_sighting_result["attribute_count"] != count
                ):
                    self.update_field(
                        id=stix_sighting_result["id"],
                        key="attribute_count",
                        value=str(count),
                    )
                    stix_sighting_result["attribute_count"] = count
                if first_seen is not None:
                    new_first_seen = dateutil.parser.parse(first_seen)
                    old_first_seen = dateutil.parser.parse(
                        stix_sighting_result["first_seen"]
                    )
                    if new_first_seen < old_first_seen:
                        self.update_field(
                            id=stix_sighting_result["id"],
                            key="first_seen",
                            value=first_seen,
                        )
                        stix_sighting_result["first_seen"] = first_seen
                if last_seen is not None:
                    new_last_seen = dateutil.parser.parse(last_seen)
                    old_last_seen = dateutil.parser.parse(
                        stix_sighting_result["last_seen"]
                    )
                    if new_last_seen > old_last_seen:
                        self.update_field(
                            id=stix_sighting_result["id"],
                            key="last_seen",
                            value=last_seen,
                        )
                        stix_sighting_result["last_seen"] = last_seen
            return stix_sighting_result
        else:
            return self.create_raw(
                fromId=from_id,
                toId=to_id,
                stix_id=stix_id,
                description=description,
                first_seen=first_seen,
                last_seen=last_seen,
                count=count,
                x_opencti_negative=x_opencti_negative,
                created=created,
                modified=modified,
                confidence=confidence,
                createdBy=created_by,
                objectMarking=object_marking,
                objectLabel=object_label,
                externalReferences=external_references,
            )

    """
        Update a stix_sighting object field

        :param id: the stix_sighting id
        :param key: the key of the field
        :param value: the value of the field
        :return The updated stix_sighting object
    """

    def update_field(self, **kwargs):
        id = kwargs.get("id", None)
        key = kwargs.get("key", None)
        value = kwargs.get("value", None)
        if id is not None and key is not None and value is not None:
            self.opencti.log(
                "info", "Updating stix_sighting {" + id + "} field {" + key + "}."
            )
            query = """
                    mutation StixSightingRelationshipEdit($id: ID!, $input: EditInput!) {
                        stixSightingRelationshipEdit(id: $id) {
                            fieldPatch(input: $input) {
                                id
                            }
                        }
                    }
                """
            result = self.opencti.query(
                query, {"id": id, "input": {"key": key, "value": value}}
            )
            return self.opencti.process_multiple_fields(
                result["data"]["stixSightingRelationshipEdit"]["fieldPatch"]
            )
        else:
            self.opencti.log(
                "error",
                "[opencti_stix_sighting] Missing parameters: id and key and value",
            )
            return None

    """
        Delete a stix_sighting

        :param id: the stix_sighting id
        :return void
    """

    def delete(self, **kwargs):
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.log("info", "Deleting stix_sighting {" + id + "}.")
            query = """
                mutation StixSightingRelationshipEdit($id: ID!) {
                    stixSightingRelationshipEdit(id: $id) {
                        delete
                    }
                }
            """
            self.opencti.query(query, {"id": id})
        else:
            self.opencti.log("error", "[opencti_stix_sighting] Missing parameters: id")
            return None
