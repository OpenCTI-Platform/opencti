# coding: utf-8

import dateutil.parser
import datetime
from pycti.utils.constants import CustomProperties
from pycti.utils.opencti_stix2 import SPEC_VERSION


class StixSighting:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            stix_id_key
            entity_type
            relationship_type
            description
            confidence
            number
            negative
            first_seen
            last_seen
            created
            modified
            created_at
            updated_at
            fromRole
            from {
                id
                stix_id_key
                entity_type
                ...on StixDomainEntity {
                    name
                    description
                }
            }
            toRole
            to {
                id
                stix_id_key
                entity_type
                ...on StixDomainEntity {
                    name
                    description
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
        force_natural = kwargs.get("forceNatural", False)
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
                query StixSightings($fromId: String, $fromTypes: [String], $toId: String, $toTypes: [String], $firstSeenStart: DateTime, $firstSeenStop: DateTime, $lastSeenStart: DateTime, $lastSeenStop: DateTime, $inferred: Boolean, $filters: [StixSightingsFiltering], $first: Int, $after: ID, $orderBy: StixSightingsOrdering, $orderMode: OrderingMode, $forceNatural: Boolean) {
                    stixSightings(fromId: $fromId, fromTypes: $fromTypes, toId: $toId, toTypes: $toTypes, firstSeenStart: $firstSeenStart, firstSeenStop: $firstSeenStop, lastSeenStart: $lastSeenStart, lastSeenStop: $lastSeenStop, inferred: $inferred, filters: $filters, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode, forceNatural: $forceNatural) {
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
                "forceNatural": force_natural,
            },
        )
        return self.opencti.process_multiple(
            result["data"]["stixSightings"], with_pagination
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
                    query StixSighting($id: String!) {
                        stixSighting(id: $id) {
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
            return self.opencti.process_multiple_fields(result["data"]["stixSighting"])
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
        description = kwargs.get("description", None)
        first_seen = kwargs.get("first_seen", None)
        last_seen = kwargs.get("last_seen", None)
        confidence = kwargs.get("confidence", 15)
        number = kwargs.get("number", 1)
        negative = kwargs.get("negative", False)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by_ref = kwargs.get("createdByRef", None)
        marking_definitions = kwargs.get("markingDefinitions", None)

        self.opencti.log(
            "info", "Creating stix_sighting {" + from_id + ", " + str(to_id) + "}.",
        )
        query = """
                mutation StixSightingAdd($input: StixSightingAddInput!) {
                    stixSightingAdd(input: $input) {
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
                    "fromId": from_id,
                    "toId": to_id,
                    "description": description,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "confidence": confidence,
                    "number": number,
                    "negative": negative,
                    "internal_id_key": id,
                    "stix_id_key": stix_id_key,
                    "created": created,
                    "modified": modified,
                    "createdByRef": created_by_ref,
                    "markingDefinitions": marking_definitions,
                }
            },
        )
        return self.opencti.process_multiple_fields(result["data"]["stixSightingAdd"])

    """
        Create a stix_sighting object only if it not exists, update it on request

        :param name: the name of the stix_sighting
        :return stix_sighting object
    """

    def create(self, **kwargs):
        from_id = kwargs.get("fromId", None)
        to_id = kwargs.get("toId", None)
        description = kwargs.get("description", None)
        first_seen = kwargs.get("first_seen", None)
        last_seen = kwargs.get("last_seen", None)
        number = kwargs.get("number", 1)
        confidence = kwargs.get("confidence", 15)
        negative = kwargs.get("negative", False)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by_ref = kwargs.get("createdByRef", None)
        marking_definitions = kwargs.get("markingDefinitions", None)
        update = kwargs.get("update", False)
        ignore_dates = kwargs.get("ignore_dates", False)
        custom_attributes = """
            id
            entity_type
            name
            description
            confidence
            number
            negative
            first_seen
            last_seen
            createdByRef {
                node {
                    id
                }
            }
        """
        stix_sighting_result = None
        if id is not None:
            stix_sighting_result = self.read(id=id, customAttributes=custom_attributes)
        if stix_sighting_result is None and stix_id_key is not None:
            stix_sighting_result = self.read(
                id=stix_id_key, customAttributes=custom_attributes
            )
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
            if update or stix_sighting_result["createdByRef"] == created_by_ref:
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
                    negative is not None
                    and stix_sighting_result["negative"] != negative
                ):
                    self.update_field(
                        id=stix_sighting_result["id"],
                        key="negative",
                        value=str(negative).lower(),
                    )
                    stix_sighting_result["negative"] = negative
                if number is not None and stix_sighting_result["number"] != number:
                    self.update_field(
                        id=stix_sighting_result["id"], key="number", value=str(number),
                    )
                    stix_sighting_result["number"] = number
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
                description=description,
                first_seen=first_seen,
                last_seen=last_seen,
                confidence=confidence,
                number=number,
                negative=negative,
                id=id,
                stix_id_key=stix_id_key,
                created=created,
                modified=modified,
                createdByRef=created_by_ref,
                markingDefinitions=marking_definitions,
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
                    mutation StixSightingEdit($id: ID!, $input: EditInput!) {
                        stixSightingEdit(id: $id) {
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
                result["data"]["stixSightingEdit"]["fieldPatch"]
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
                mutation StixSightingEdit($id: ID!) {
                    stixSightingEdit(id: $id) {
                        delete
                    }
                }
            """
            self.opencti.query(query, {"id": id})
        else:
            self.opencti.log("error", "[opencti_stix_sighting] Missing parameters: id")
            return None

    """
        Export an stix_sighting object in STIX2

        :param id: the id of the stix_sighting
        :return stix_sighting object
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
            stix_sighting = dict()
            stix_sighting["id"] = entity["stix_id_key"]
            stix_sighting["type"] = "sighting"
            stix_sighting["spec_version"] = SPEC_VERSION
            stix_sighting["sighting_of_ref"] = entity["from"]["stix_id_key"]
            stix_sighting["where_sighted_refs"] = entity["to"]["stix_id_key"]
            if self.opencti.not_empty(entity["description"]):
                stix_sighting["description"] = entity["description"]
            stix_sighting["created"] = self.opencti.stix2.format_date(entity["created"])
            stix_sighting["modified"] = self.opencti.stix2.format_date(
                entity["modified"]
            )
            if self.opencti.not_empty(entity["first_seen"]):
                stix_sighting["first_seen"] = self.opencti.stix2.format_date(
                    entity["first_seen"]
                )
            if self.opencti.not_empty(entity["last_seen"]):
                stix_sighting["last_seen"] = self.opencti.stix2.format_date(
                    entity["last_seen"]
                )
            if self.opencti.not_empty(entity["confidence"]):
                stix_sighting["confidence"] = entity["confidence"]
            stix_sighting[CustomProperties.ID] = entity["id"]
            return self.opencti.stix2.prepare_export(
                entity, stix_sighting, mode, max_marking_definition_entity
            )
        else:
            self.opencti.log(
                "error", "[opencti_stix_sighting] Missing parameters: id or entity"
            )
