# coding: utf-8

import json
from pycti.utils.constants import CustomProperties
from pycti.utils.opencti_stix2 import SPEC_VERSION


class Indicator:
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
            indicator_pattern
            pattern_type
            detection
            confidence
            valid_from
            valid_until
            score
            created
            modified            
            created_at
            updated_at
            killChainPhases {
                edges {
                    node {
                        id
                        entity_type
                        stix_id_key
                        kill_chain_name
                        phase_name
                        phase_order
                        created
                        modified
                    }
                    relation {
                        id
                    }
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
        List Indicator objects

        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Indicator objects
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
            "info", "Listing Indicators with filters " + json.dumps(filters) + "."
        )
        query = (
            """
            query Indicators($filters: [IndicatorsFiltering], $search: String, $first: Int, $after: ID, $orderBy: IndicatorsOrdering, $orderMode: OrderingMode) {
                indicators(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
            data = self.opencti.process_multiple(result["data"]["indicators"])
            final_data = final_data + data
            while result["data"]["indicators"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["indicators"]["pageInfo"]["endCursor"]
                self.opencti.log("info", "Listing Indicators after " + after)
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
                data = self.opencti.process_multiple(result["data"]["indicators"])
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["indicators"], with_pagination
            )

    """
        Read a Indicator object
        
        :param id: the id of the Indicator
        :param filters: the filters to apply if no id provided
        :return Indicator object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.log("info", "Reading Indicator {" + id + "}.")
            query = (
                """
                query Indicator($id: String!) {
                    indicator(id: $id) {
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
            return self.opencti.process_multiple_fields(result["data"]["indicator"])
        elif filters is not None:
            result = self.list(filters=filters, customAttributes=custom_attributes)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.log(
                "error", "[opencti_indicator] Missing parameters: id or filters"
            )
            return None

    """
        Create a Indicator object

        :param name: the name of the Indicator
        :return Indicator object
    """

    def create_raw(self, **kwargs):
        name = kwargs.get("name", None)
        description = kwargs.get("description", None)
        indicator_pattern = kwargs.get("indicator_pattern", None)
        main_observable_type = kwargs.get("main_observable_type", None)
        pattern_type = kwargs.get("pattern_type", None)
        valid_from = kwargs.get("valid_from", None)
        valid_until = kwargs.get("valid_until", None)
        score = kwargs.get("score", None)
        confidence = kwargs.get("confidence", 50)
        detection = kwargs.get("detection", False)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by_ref = kwargs.get("createdByRef", None)
        marking_definitions = kwargs.get("markingDefinitions", None)
        tags = kwargs.get("tags", None)
        kill_chain_phases = kwargs.get("killChainPhases", None)

        if (
            name is not None
            and indicator_pattern is not None
            and main_observable_type is not None
        ):
            self.opencti.log("info", "Creating Indicator {" + name + "}.")
            query = """
                mutation IndicatorAdd($input: IndicatorAddInput) {
                    indicatorAdd(input: $input) {
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
            if pattern_type is None:
                pattern_type = "stix2"
            result = self.opencti.query(
                query,
                {
                    "input": {
                        "name": name,
                        "description": description,
                        "indicator_pattern": indicator_pattern,
                        "main_observable_type": main_observable_type,
                        "pattern_type": pattern_type,
                        "valid_from": valid_from,
                        "valid_until": valid_until,
                        "score": score,
                        "detection": detection,
                        "confidence": confidence,
                        "internal_id_key": id,
                        "stix_id_key": stix_id_key,
                        "created": created,
                        "modified": modified,
                        "createdByRef": created_by_ref,
                        "markingDefinitions": marking_definitions,
                        "tags": tags,
                        "killChainPhases": kill_chain_phases,
                    }
                },
            )
            return self.opencti.process_multiple_fields(result["data"]["indicatorAdd"])
        else:
            self.opencti.log(
                "error",
                "[opencti_indicator] Missing parameters: name and indicator_pattern and main_observable_type",
            )

    """
        Create a Indicator object only if it not exists, update it on request

        :param name: the name of the Indicator
        :return Indicator object
    """

    def create(self, **kwargs):
        name = kwargs.get("name", None)
        description = kwargs.get("description", None)
        indicator_pattern = kwargs.get("indicator_pattern", None)
        main_observable_type = kwargs.get("main_observable_type", None)
        pattern_type = kwargs.get("pattern_type", None)
        valid_from = kwargs.get("valid_from", None)
        valid_until = kwargs.get("valid_until", None)
        score = kwargs.get("score", None)
        confidence = kwargs.get("confidence", 50)
        detection = kwargs.get("detection", False)
        id = kwargs.get("id", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by_ref = kwargs.get("createdByRef", None)
        marking_definitions = kwargs.get("markingDefinitions", None)
        tags = kwargs.get("tags", None)
        kill_chain_phases = kwargs.get("killChainPhases", None)
        update = kwargs.get("update", False)
        custom_attributes = """
            id
            entity_type
            name
            description
            score
            confidence
            detection
            createdByRef {
                node {
                    id
                }
            }
            ... on Indicator {
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
        """
        object_result = None
        if stix_id_key is not None:
            object_result = self.read(
                id=stix_id_key, customAttributes=custom_attributes
            )
        if object_result is None:
            object_result = self.read(
                filters=[
                    {
                        "key": "indicator_pattern",
                        "values": [indicator_pattern],
                        "operator": "match" if len(indicator_pattern) > 500 else "eq",
                    }
                ],
                customAttributes=custom_attributes,
            )
        if object_result is not None:
            if update or object_result["createdByRefId"] == created_by_ref:
                # name
                if name is not None and object_result["name"] != name:
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
                # score
                if score is not None and object_result["score"] != score:
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"], key="score", value=str(score)
                    )
                    object_result["score"] = score
                # confidence
                if confidence is not None and object_result["confidence"] != confidence:
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"], key="confidence", value=str(confidence)
                    )
                    object_result["confidence"] = confidence
                # detection
                if detection is not None and object_result["detection"] != detection:
                    self.opencti.stix_domain_entity.update_field(
                        id=object_result["id"],
                        key="detection",
                        value=str(detection).lower(),
                    )
                    object_result["detection"] = detection
            return object_result
        else:
            return self.create_raw(
                name=name,
                description=description,
                indicator_pattern=indicator_pattern,
                main_observable_type=main_observable_type,
                pattern_type=pattern_type,
                valid_from=valid_from,
                valid_until=valid_until,
                score=score,
                detection=detection,
                confidence=confidence,
                id=id,
                stix_id_key=stix_id_key,
                created=created,
                modified=modified,
                createdByRef=created_by_ref,
                markingDefinitions=marking_definitions,
                tags=tags,
                killChainPhases=kill_chain_phases,
            )

    """
        Add a Stix-Observable object to Indicator object (observable_refs)

        :param id: the id of the Indicator
        :param entity_id: the id of the Stix-Observable
        :return Boolean
    """

    def add_stix_observable(self, **kwargs):
        id = kwargs.get("id", None)
        indicator = kwargs.get("indicator", None)
        stix_observable_id = kwargs.get("stix_observable_id", None)
        if id is not None and stix_observable_id is not None:
            if indicator is None:
                indicator = self.read(id=id)
            if indicator is None:
                self.opencti.log(
                    "error",
                    "[opencti_indicator] Cannot add Object Ref, indicator not found",
                )
                return False
            if stix_observable_id in indicator["observableRefsIds"]:
                return True
            else:
                self.opencti.log(
                    "info",
                    "Adding Stix-Observable {"
                    + stix_observable_id
                    + "} to Indicator {"
                    + id
                    + "}",
                )
                query = """
                   mutation IndicatorEdit($id: ID!, $input: RelationAddInput) {
                       indicatorEdit(id: $id) {
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
                "[opencti_indicator] Missing parameters: id and stix_observable_id",
            )
            return False

    """
        Import an Indicator object from a STIX2 object

        :param stixObject: the Stix-Object Indicator
        :return Indicator object
    """

    def import_from_stix2(self, **kwargs):
        stix_object = kwargs.get("stixObject", None)
        extras = kwargs.get("extras", {})
        update = kwargs.get("update", False)
        if stix_object is not None:
            pattern_type = "stix"
            if CustomProperties.PATTERN_TYPE in stix_object:
                pattern_type = stix_object[CustomProperties.PATTERN_TYPE]
            elif "pattern_type" in stix_object:
                pattern_type = stix_object["pattern_type"]
            return self.create(
                name=stix_object["name"] if "name" in stix_object else "",
                description=self.opencti.stix2.convert_markdown(
                    stix_object["description"]
                )
                if "description" in stix_object
                else "",
                indicator_pattern=stix_object[CustomProperties.INDICATOR_PATTERN]
                if CustomProperties.INDICATOR_PATTERN in stix_object
                else stix_object["pattern"],
                main_observable_type=stix_object[CustomProperties.OBSERVABLE_TYPE]
                if CustomProperties.OBSERVABLE_TYPE in stix_object
                else "Unknown",
                pattern_type=pattern_type,
                valid_from=stix_object["valid_from"]
                if "valid_from" in stix_object
                else None,
                valid_until=stix_object["valid_until"]
                if "valid_until" in stix_object
                else None,
                score=stix_object[CustomProperties.SCORE]
                if CustomProperties.SCORE in stix_object
                else None,
                confidence=stix_object["confidence"]
                if "confidence" in stix_object
                else 50,
                detection=stix_object[CustomProperties.DETECTION]
                if CustomProperties.DETECTION in stix_object
                else None,
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
                else None,
                tags=extras["tags_ids"] if "tags_ids" in extras else [],
                killChainPhases=extras["kill_chain_phases_ids"]
                if "kill_chain_phases_ids" in extras
                else [],
                update=update,
            )
        else:
            self.opencti.log(
                "error", "[opencti_attack_pattern] Missing parameters: stixObject"
            )

    """
        Export an Indicator object in STIX2
    
        :param id: the id of the Indicator
        :return Indicator object
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
            indicator = dict()
            indicator["id"] = entity["stix_id_key"]
            indicator["type"] = "indicator"
            indicator["spec_version"] = SPEC_VERSION
            indicator["name"] = entity["name"]
            if self.opencti.not_empty(entity["stix_label"]):
                indicator["labels"] = entity["stix_label"]
            else:
                indicator["labels"] = ["indicator"]
            if self.opencti.not_empty(entity["description"]):
                indicator["description"] = entity["description"]
            indicator["pattern"] = entity["indicator_pattern"]
            indicator["valid_from"] = self.opencti.stix2.format_date(
                entity["valid_from"]
            )
            indicator["valid_until"] = self.opencti.stix2.format_date(
                entity["valid_until"]
            )
            if self.opencti.not_empty(entity["pattern_type"]):
                indicator["pattern_type"] = entity["pattern_type"]
            else:
                indicator["pattern_type"] = "stix"
            indicator["created"] = self.opencti.stix2.format_date(entity["created"])
            indicator["modified"] = self.opencti.stix2.format_date(entity["modified"])
            if self.opencti.not_empty(entity["alias"]):
                indicator[CustomProperties.ALIASES] = entity["alias"]
            if self.opencti.not_empty(entity["score"]):
                indicator[CustomProperties.SCORE] = entity["score"]
            indicator[CustomProperties.ID] = entity["id"]
            return self.opencti.stix2.prepare_export(
                entity, indicator, mode, max_marking_definition_entity
            )
        else:
            self.opencti.log("error", "Missing parameters: id or entity")
