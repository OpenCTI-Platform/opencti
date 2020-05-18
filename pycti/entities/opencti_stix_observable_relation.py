# coding: utf-8

import dateutil.parser
import datetime


class StixObservableRelation:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            id
            stix_id_key
            entity_type
            relationship_type
            description
            weight
            role_played
            first_seen
            last_seen
            created
            modified
            created_at
            updated_at
            from {
                id
                stix_id_key
                entity_type
                observable_value
            }
            to {
                id
                stix_id_key
                entity_type
                observable_value
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
        List stix_observable_relation objects

        :param fromId: the id of the source entity of the relation
        :param toId: the id of the target entity of the relation
        :param relationType: the relation type
        :param firstSeenStart: the first_seen date start filter
        :param firstSeenStop: the first_seen date stop filter
        :param lastSeenStart: the last_seen date start filter
        :param lastSeenStop: the last_seen date stop filter
        :param inferred: includes inferred relations
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of stix_observable_relation objects
    """

    def list(self, **kwargs):
        from_id = kwargs.get("fromId", None)
        from_types = kwargs.get("fromTypes", None)
        to_id = kwargs.get("toId", None)
        to_types = kwargs.get("toTypes", None)
        relation_type = kwargs.get("relationType", None)
        first_seen_start = kwargs.get("firstSeenStart", None)
        first_seen_stop = kwargs.get("firstSeenStop", None)
        last_seen_start = kwargs.get("lastSeenStart", None)
        last_seen_stop = kwargs.get("lastSeenStop", None)
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
            "Listing stix_observable_relations with {type: "
            + str(relation_type)
            + ", from_id: "
            + str(from_id)
            + ", to_id: "
            + str(to_id)
            + "}",
        )
        query = (
            """
            query StixObservableRelations($fromId: String, $fromTypes: [String], $toId: String, $toTypes: [String], $relationType: String, $firstSeenStart: DateTime, $firstSeenStop: DateTime, $lastSeenStart: DateTime, $lastSeenStop: DateTime, $inferred: Boolean, $first: Int, $after: ID, $orderBy: StixObservableRelationsOrdering, $orderMode: OrderingMode, $forceNatural: Boolean) {
                stixObservableRelations(fromId: $fromId, fromTypes: $fromTypes, toId: $toId, toTypes: $toTypes, relationType: $relationType, firstSeenStart: $firstSeenStart, firstSeenStop: $firstSeenStop, lastSeenStart: $lastSeenStart, lastSeenStop: $lastSeenStop, inferred: $inferred, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode, forceNatural: $forceNatural) {
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
                "relationType": relation_type,
                "firstSeenStart": first_seen_start,
                "firstSeenStop": first_seen_stop,
                "lastSeenStart": last_seen_start,
                "lastSeenStop": last_seen_stop,
                "inferred": inferred,
                "first": first,
                "after": after,
                "orderBy": order_by,
                "orderMode": order_mode,
                "forceNatural": force_natural,
            },
        )
        return self.opencti.process_multiple(
            result["data"]["stixObservableRelations"], with_pagination
        )

    """
        Read a stix_observable_relation object

        :param id: the id of the stix_observable_relation
        :param stix_id_key: the STIX id of the stix_observable_relation
        :param fromId: the id of the source entity of the relation
        :param toId: the id of the target entity of the relation
        :param relationType: the relation type
        :param firstSeenStart: the first_seen date start filter
        :param firstSeenStop: the first_seen date stop filter
        :param lastSeenStart: the last_seen date start filter
        :param lastSeenStop: the last_seen date stop filter
        :param inferred: includes inferred relations
        :return stix_observable_relation object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        from_id = kwargs.get("fromId", None)
        to_id = kwargs.get("toId", None)
        relation_type = kwargs.get("relationType", None)
        first_seen_start = kwargs.get("firstSeenStart", None)
        first_seen_stop = kwargs.get("firstSeenStop", None)
        last_seen_start = kwargs.get("lastSeenStart", None)
        last_seen_stop = kwargs.get("lastSeenStop", None)
        inferred = kwargs.get("inferred", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.log("info", "Reading stix_observable_relation {" + id + "}.")
            query = (
                """
                query StixObservableRelation($id: String!) {
                    stixObservableRelation(id: $id) {
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
                result["data"]["stixObservableRelation"]
            )
        else:
            result = self.list(
                fromId=from_id,
                toId=to_id,
                relationType=relation_type,
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

    """
        Create a stix_observable_relation object

        :param from_id: id of the source entity
        :return stix_observable_relation object
    """

    def create_raw(self, **kwargs):
        from_id = kwargs.get("fromId", None)
        from_role = kwargs.get("fromRole", None)
        to_id = kwargs.get("toId", None)
        to_role = kwargs.get("toRole", None)
        relationship_type = kwargs.get("relationship_type", None)
        description = kwargs.get("description", None)
        role_played = kwargs.get("role_played", None)
        first_seen = kwargs.get("first_seen", None)
        last_seen = kwargs.get("last_seen", None)
        weight = kwargs.get("weight", None)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by_ref = kwargs.get("createdByRef", None)
        marking_definitions = kwargs.get("markingDefinitions", None)

        self.opencti.log(
            "info",
            "Creating stix_observable_relation {"
            + from_role
            + ": "
            + from_id
            + ", "
            + to_role
            + ": "
            + to_id
            + "}.",
        )
        query = """
                mutation StixObservableRelationAdd($input: StixObservableRelationAddInput!) {
                    stixObservableRelationAdd(input: $input) {
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
                    "fromRole": from_role,
                    "toId": to_id,
                    "toRole": to_role,
                    "relationship_type": relationship_type,
                    "description": description,
                    "role_played": role_played,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "weight": weight,
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
            result["data"]["stixObservableRelationAdd"]
        )

    """
        Create a stix_observable_relation object only if it not exists, update it on request

        :param name: the name of the stix_observable_relation
        :return stix_observable_relation object
    """

    def create(self, **kwargs):
        from_id = kwargs.get("fromId", None)
        from_type = kwargs.get("fromType", None)
        to_type = kwargs.get("toType", None)
        to_id = kwargs.get("toId", None)
        relationship_type = kwargs.get("relationship_type", None)
        description = kwargs.get("description", None)
        role_played = kwargs.get("role_played", None)
        first_seen = kwargs.get("first_seen", None)
        last_seen = kwargs.get("last_seen", None)
        weight = kwargs.get("weight", None)
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
            weight
            first_seen
            last_seen
        """
        stix_relation_result = None
        if stix_id_key is not None:
            stix_relation_result = self.read(
                id=stix_id_key, customAttributes=custom_attributes
            )
        if stix_relation_result is None:
            if (
                ignore_dates is False
                and first_seen is not None
                and last_seen is not None
            ):
                first_seen = dateutil.parser.parse(first_seen)
                first_seen_start = (first_seen + datetime.timedelta(days=-1)).strftime(
                    "%Y-%m-%dT%H:%M:%S+00:00"
                )
                first_seen_stop = (first_seen + datetime.timedelta(days=1)).strftime(
                    "%Y-%m-%dT%H:%M:%S+00:00"
                )
                last_seen = dateutil.parser.parse(last_seen)
                last_seen_start = (last_seen + datetime.timedelta(days=-1)).strftime(
                    "%Y-%m-%dT%H:%M:%S+00:00"
                )
                last_seen_stop = (last_seen + datetime.timedelta(days=1)).strftime(
                    "%Y-%m-%dT%H:%M:%S+00:00"
                )
            else:
                first_seen_start = None
                first_seen_stop = None
                last_seen_start = None
                last_seen_stop = None
            stix_relation_result = self.read(
                fromId=from_id,
                toId=to_id,
                relationType=relationship_type,
                firstSeenStart=first_seen_start,
                firstSeenStop=first_seen_stop,
                lastSeenStart=last_seen_start,
                lastSeenStop=last_seen_stop,
                customAttributes=custom_attributes,
            )
        if stix_relation_result is not None:
            if update:
                if description is not None:
                    self.update_field(
                        id=stix_relation_result["id"],
                        key="description",
                        value=description,
                    )
                    stix_relation_result["description"] = description
                if weight is not None:
                    self.update_field(
                        id=stix_relation_result["id"], key="weight", value=str(weight)
                    )
                    stix_relation_result["weight"] = weight
                if first_seen is not None:
                    new_first_seen = dateutil.parser.parse(first_seen)
                    old_first_seen = dateutil.parser.parse(
                        stix_relation_result["first_seen"]
                    )
                    if new_first_seen < old_first_seen:
                        self.update_field(
                            id=stix_relation_result["id"],
                            key="first_seen",
                            value=first_seen,
                        )
                        stix_relation_result["first_seen"] = first_seen
                if last_seen is not None:
                    new_last_seen = dateutil.parser.parse(last_seen)
                    old_last_seen = dateutil.parser.parse(
                        stix_relation_result["last_seen"]
                    )
                    if new_last_seen > old_last_seen:
                        self.update_field(
                            id=stix_relation_result["id"],
                            key="last_seen",
                            value=last_seen,
                        )
                        stix_relation_result["last_seen"] = last_seen
            return stix_relation_result
        else:
            roles = self.opencti.resolve_role(relationship_type, from_type, to_type)
            if roles is not None:
                final_from_id = from_id
                final_to_id = to_id
            else:
                roles = self.opencti.resolve_role(relationship_type, to_type, from_type)
                if roles is not None:
                    final_from_id = to_id
                    final_to_id = from_id
                else:
                    self.opencti.log(
                        "error",
                        "Relation creation failed, cannot resolve roles: {"
                        + relationship_type
                        + ": "
                        + from_type
                        + ", "
                        + to_type
                        + "}",
                    )
                    return None

            return self.create_raw(
                fromId=final_from_id,
                fromRole=roles["from_role"],
                toId=final_to_id,
                toRole=roles["to_role"],
                relationship_type=relationship_type,
                description=description,
                first_seen=first_seen,
                last_seen=last_seen,
                weight=weight,
                role_played=role_played,
                id=id,
                stix_id_key=stix_id_key,
                created=created,
                modified=modified,
                createdByRef=created_by_ref,
                markingDefinitions=marking_definitions,
            )

    """
        Update a stix_observable_relation object field

        :param id: the stix_observable_relation id
        :param key: the key of the field
        :param value: the value of the field
        :return The updated stix_observable_relation object
    """

    def update_field(self, **kwargs):
        id = kwargs.get("id", None)
        key = kwargs.get("key", None)
        value = kwargs.get("value", None)
        if id is not None and key is not None and value is not None:
            self.opencti.log(
                "info",
                "Updating stix_observable_relation {" + id + "} field {" + key + "}.",
            )
            query = (
                """
                mutation StixObservableRelationEdit($id: ID!, $input: EditInput!) {
                    stixObservableRelationEdit(id: $id) {
                        fieldPatch(input: $input) {
                            """
                + self.properties
                + """
                        }
                    }
                }
            """
            )
            result = self.opencti.query(
                query, {"id": id, "input": {"key": key, "value": value}}
            )
            return self.opencti.process_multiple_fields(
                result["data"]["stixObservableRelationEdit"]["fieldPatch"]
            )
        else:
            self.opencti.log("error", "Missing parameters: id and key and value")
            return None
