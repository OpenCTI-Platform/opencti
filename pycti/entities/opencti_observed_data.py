# coding: utf-8

import json


class ObservedData:
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
                    }
                }
            }
            revoked
            confidence
            created
            modified
            first_observed
            last_observed
            number_observed
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
                        ... on StixCoreRelationship {
                            standard_id
                            spec_version
                            created_at
                            updated_at
                        }
                    }
                }
            }
        """

    """
        List ObservedData objects

        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of ObservedData objects
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
            "info", "Listing ObservedDatas with filters " + json.dumps(filters) + "."
        )
        query = (
            """
            query ObservedDatas($filters: [ObservedDatasFiltering], $search: String, $first: Int, $after: ID, $orderBy: ObservedDatasOrdering, $orderMode: OrderingMode) {
                observedDatas(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
            result["data"]["observedDatas"], with_pagination
        )

    """
        Read a ObservedData object

        :param id: the id of the ObservedData
        :param filters: the filters to apply if no id provided
        :return ObservedData object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.log("info", "Reading ObservedData {" + id + "}.")
            query = (
                """
                query ObservedData($id: String!) {
                    observedData(id: $id) {
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
            return self.opencti.process_multiple_fields(result["data"]["observedData"])
        elif filters is not None:
            result = self.list(filters=filters)
            if len(result) > 0:
                return result[0]
            else:
                return None

    """
        Check if a observedData already contains a STIX entity
        
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
                + "} in ObservedData {"
                + id
                + "}",
            )
            query = """
                query ObservedDataContainsStixObjectOrStixRelationship($id: String!, $stixObjectOrStixRelationshipId: String!) {
                    observedDataContainsStixObjectOrStixRelationship(id: $id, stixObjectOrStixRelationshipId: $stixObjectOrStixRelationshipId)
                }
            """
            result = self.opencti.query(
                query,
                {
                    "id": id,
                    "stixObjectOrStixRelationshipId": stix_object_or_stix_relationship_id,
                },
            )
            return result["data"]["observedDataContainsStixObjectOrStixRelationship"]
        else:
            self.opencti.log(
                "error",
                "[opencti_observedData] Missing parameters: id or entity_id",
            )

    """
        Create a ObservedData object

        :param name: the name of the ObservedData
        :return ObservedData object
    """

    def create(self, **kwargs):
        stix_id = kwargs.get("stix_id", None)
        created_by = kwargs.get("createdBy", None)
        object_marking = kwargs.get("objectMarking", None)
        object_label = kwargs.get("objectLabel", None)
        external_references = kwargs.get("externalReferences", None)
        revoked = kwargs.get("revoked", None)
        confidence = kwargs.get("confidence", None)
        lang = kwargs.get("lang", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        first_observed = kwargs.get("first_observed", None)
        last_observed = kwargs.get("last_observed", None)
        number_observed = kwargs.get("number_observed", None)
        update = kwargs.get("update", False)

        if first_observed is not None and last_observed is not None:
            self.opencti.log("info", "Creating ObservedData.")
            query = """
                mutation ObservedDataAdd($input: ObservedDataAddInput) {
                    observedDataAdd(input: $input) {
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
                        "externalReferences": external_references,
                        "revoked": revoked,
                        "confidence": confidence,
                        "lang": lang,
                        "created": created,
                        "modified": modified,
                        "first_observed": first_observed,
                        "last_observed": last_observed,
                        "number_observed": number_observed,
                        "update": update,
                    }
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["observedDataAdd"]
            )
        else:
            self.opencti.log(
                "error",
                "[opencti_observedData] Missing parameters: first_observed or last_observed",
            )

    """
        Add a Stix-Core-Object or stix_relationship to ObservedData object (object)

        :param id: the id of the ObservedData
        :param entity_id: the id of the Stix-Core-Object or stix_relationship
        :return Boolean
    """

    def add_stix_object_or_stix_relationship(self, **kwargs):
        id = kwargs.get("id", None)
        stix_object_or_stix_relationship_id = kwargs.get(
            "stixObjectOrStixRelationshipId", None
        )
        if id is not None and stix_object_or_stix_relationship_id is not None:
            if self.contains_stix_object_or_stix_relationship(
                id=id,
                stixObjectOrStixRelationshipId=stix_object_or_stix_relationship_id,
            ):
                return True
            self.opencti.log(
                "info",
                "Adding StixObjectOrStixRelationship {"
                + stix_object_or_stix_relationship_id
                + "} to ObservedData {"
                + id
                + "}",
            )
            query = """
               mutation ObservedDataEdit($id: ID!, $input: StixMetaRelationshipAddInput) {
                   observedDataEdit(id: $id) {
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
                "[opencti_observedData] Missing parameters: id and stix_object_or_stix_relationship_id",
            )
            return False

    """
        Remove a Stix-Core-Object or stix_relationship to Observed-Data object (object_refs)

        :param id: the id of the Observed-Data
        :param entity_id: the id of the Stix-Core-Object or stix_relationship
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
                + "} to Observed-Data {"
                + id
                + "}",
            )
            query = """
               mutation ObservedDataEditRelationDelete($id: ID!, $toId: String!, $relationship_type: String!) {
                   observedDataEdit(id: $id) {
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
                "error", "[opencti_observed_data] Missing parameters: id and entity_id"
            )
            return False

    """
        Import a ObservedData object from a STIX2 object

        :param stixObject: the Stix-Object ObservedData
        :return ObservedData object
    """

    def import_from_stix2(self, **kwargs):
        stix_object = kwargs.get("stixObject", None)
        extras = kwargs.get("extras", {})
        update = kwargs.get("update", False)
        if stix_object is not None:
            observed_data_result = self.create(
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
                first_observed=stix_object["first_observed"]
                if "first_observed" in stix_object
                else None,
                last_observed=stix_object["last_observed"]
                if "last_observed" in stix_object
                else None,
                number_observed=stix_object["number_observed"]
                if "number_observed" in stix_object
                else None,
                update=update,
            )
            if "objects" in stix_object:
                for key, observable_item in stix_object["objects"].items():
                    stix_observable_result = self.opencti.stix_cyber_observable.create(
                        observableData=observable_item,
                        createdBy=extras["created_by_id"]
                        if "created_by_id" in extras
                        else None,
                        objectMarking=extras["object_marking_ids"]
                        if "object_marking_ids" in extras
                        else None,
                        objectLabel=extras["object_label_ids"]
                        if "object_label_ids" in extras
                        else [],
                    )
                    if stix_observable_result is not None:
                        self.add_stix_object_or_stix_relationship(
                            id=observed_data_result["id"],
                            stixObjectOrStixRelationshipId=stix_observable_result["id"],
                        )
                        self.opencti.stix2.mapping_cache[
                            stix_observable_result["id"]
                        ] = {
                            "id": stix_observable_result["id"],
                            "type": stix_observable_result["entity_type"],
                        }
            return observed_data_result
        else:
            self.opencti.log(
                "error", "[opencti_attack_pattern] Missing parameters: stixObject"
            )
