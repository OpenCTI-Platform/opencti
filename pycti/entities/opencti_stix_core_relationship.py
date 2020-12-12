# coding: utf-8


class StixCoreRelationship:
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
            relationship_type
            description
            start_time
            stop_time
            revoked
            confidence
            lang
            created
            modified
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
        List stix_core_relationship objects

        :param fromId: the id of the source entity of the relation
        :param toId: the id of the target entity of the relation
        :param relationship_type: the relation type
        :param startTimeStart: the start_time date start filter
        :param startTimeStop: the start_time date stop filter
        :param stopTimeStart: the stop_time date start filter
        :param stopTimeStop: the stop_time date stop filter
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of stix_core_relationship objects
    """

    def list(self, **kwargs):
        from_id = kwargs.get("fromId", None)
        from_types = kwargs.get("fromTypes", None)
        to_id = kwargs.get("toId", None)
        to_types = kwargs.get("toTypes", None)
        relationship_type = kwargs.get("relationship_type", None)
        start_time_start = kwargs.get("startTimeStart", None)
        start_time_stop = kwargs.get("startTimeStop", None)
        stop_time_start = kwargs.get("stopTimeStart", None)
        stop_time_stop = kwargs.get("stopTimeStop", None)
        filters = kwargs.get("filters", [])
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
            "Listing stix_core_relationships with {type: "
            + str(relationship_type)
            + ", from_id: "
            + str(from_id)
            + ", to_id: "
            + str(to_id)
            + "}",
        )
        query = (
            """
                query StixCoreRelationships($fromId: String, $fromTypes: [String], $toId: String, $toTypes: [String], $relationship_type: String, $startTimeStart: DateTime, $startTimeStop: DateTime, $stopTimeStart: DateTime, $stopTimeStop: DateTime, $filters: [StixCoreRelationshipsFiltering], $first: Int, $after: ID, $orderBy: StixCoreRelationshipsOrdering, $orderMode: OrderingMode) {
                    stixCoreRelationships(fromId: $fromId, fromTypes: $fromTypes, toId: $toId, toTypes: $toTypes, relationship_type: $relationship_type, startTimeStart: $startTimeStart, startTimeStop: $startTimeStop, stopTimeStart: $stopTimeStart, stopTimeStop: $stopTimeStop, filters: $filters, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
                "relationship_type": relationship_type,
                "startTimeStart": start_time_start,
                "startTimeStop": start_time_stop,
                "stopTimeStart": stop_time_start,
                "stopTimeStop": stop_time_stop,
                "filters": filters,
                "first": first,
                "after": after,
                "orderBy": order_by,
                "orderMode": order_mode,
            },
        )
        return self.opencti.process_multiple(
            result["data"]["stixCoreRelationships"], with_pagination
        )

    """
        Read a stix_core_relationship object

        :param id: the id of the stix_core_relationship
        :param fromId: the id of the source entity of the relation
        :param toId: the id of the target entity of the relation
        :param relationship_type: the relation type
        :param startTimeStart: the start_time date start filter
        :param startTimeStop: the start_time date stop filter
        :param stopTimeStart: the stop_time date start filter
        :param stopTimeStop: the stop_time date stop filter
        :return stix_core_relationship object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        from_id = kwargs.get("fromId", None)
        to_id = kwargs.get("toId", None)
        relationship_type = kwargs.get("relationship_type", None)
        start_time_start = kwargs.get("startTimeStart", None)
        start_time_stop = kwargs.get("startTimeStop", None)
        stop_time_start = kwargs.get("stopTimeStart", None)
        stop_time_stop = kwargs.get("stopTimeStop", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.log("info", "Reading stix_core_relationship {" + id + "}.")
            query = (
                """
                    query StixCoreRelationship($id: String!) {
                        stixCoreRelationship(id: $id) {
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
                result["data"]["stixCoreRelationship"]
            )
        elif from_id is not None and to_id is not None:
            result = self.list(
                fromId=from_id,
                toId=to_id,
                relationship_type=relationship_type,
                startTimeStart=start_time_start,
                startTimeStop=start_time_stop,
                stopTimeStart=stop_time_start,
                stopTimeStop=stop_time_stop,
            )
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.log("error", "Missing parameters: id or from_id and to_id")
            return None

    """
        Create a stix_core_relationship object

        :param name: the name of the Attack Pattern
        :return stix_core_relationship object
    """

    def create(self, **kwargs):
        from_id = kwargs.get("fromId", None)
        to_id = kwargs.get("toId", None)
        stix_id = kwargs.get("stix_id", None)
        relationship_type = kwargs.get("relationship_type", None)
        description = kwargs.get("description", None)
        start_time = kwargs.get("start_time", None)
        stop_time = kwargs.get("stop_time", None)
        revoked = kwargs.get("revoked", None)
        confidence = kwargs.get("confidence", None)
        lang = kwargs.get("lang", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by = kwargs.get("createdBy", None)
        object_marking = kwargs.get("objectMarking", None)
        object_label = kwargs.get("objectLabel", None)
        external_references = kwargs.get("externalReferences", None)
        kill_chain_phases = kwargs.get("killChainPhases", None)
        update = kwargs.get("update", False)

        self.opencti.log(
            "info",
            "Creating stix_core_relationship {" + from_id + ", " + to_id + "}.",
        )
        query = """
                mutation StixCoreRelationshipAdd($input: StixCoreRelationshipAddInput!) {
                    stixCoreRelationshipAdd(input: $input) {
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
                    "relationship_type": relationship_type,
                    "description": description,
                    "start_time": start_time,
                    "stop_time": stop_time,
                    "revoked": revoked,
                    "confidence": confidence,
                    "lang": lang,
                    "created": created,
                    "modified": modified,
                    "createdBy": created_by,
                    "objectMarking": object_marking,
                    "objectLabel": object_label,
                    "externalReferences": external_references,
                    "killChainPhases": kill_chain_phases,
                    "update": update,
                }
            },
        )
        return self.opencti.process_multiple_fields(
            result["data"]["stixCoreRelationshipAdd"]
        )

    """
        Update a stix_core_relationship object field

        :param id: the stix_core_relationship id
        :param key: the key of the field
        :param value: the value of the field
        :return The updated stix_core_relationship object
    """

    def update_field(self, **kwargs):
        id = kwargs.get("id", None)
        key = kwargs.get("key", None)
        value = kwargs.get("value", None)
        if id is not None and key is not None and value is not None:
            self.opencti.log(
                "info",
                "Updating stix_core_relationship {" + id + "} field {" + key + "}.",
            )
            query = """
                    mutation StixCoreRelationshipEdit($id: ID!, $input: EditInput!) {
                        stixCoreRelationshipEdit(id: $id) {
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
                result["data"]["stixCoreRelationshipEdit"]["fieldPatch"]
            )
        else:
            self.opencti.log(
                "error",
                "[opencti_stix_core_relationship] Missing parameters: id and key and value",
            )
            return None

    """
        Delete a stix_core_relationship

        :param id: the stix_core_relationship id
        :return void
    """

    def delete(self, **kwargs):
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.log("info", "Deleting stix_core_relationship {" + id + "}.")
            query = """
                mutation StixCoreRelationshipEdit($id: ID!) {
                    stixCoreRelationshipEdit(id: $id) {
                        delete
                    }
                }
            """
            self.opencti.query(query, {"id": id})
        else:
            self.opencti.log(
                "error", "[opencti_stix_core_relationship] Missing parameters: id"
            )
            return None

    """
        Add a Marking-Definition object to stix_core_relationship object (object_marking_refs)

        :param id: the id of the stix_core_relationship
        :param marking_definition_id: the id of the Marking-Definition
        :return Boolean
    """

    def add_marking_definition(self, **kwargs):
        id = kwargs.get("id", None)
        marking_definition_id = kwargs.get("marking_definition_id", None)
        if id is not None and marking_definition_id is not None:
            custom_attributes = """
                id
                objectMarking {
                    edges {
                        node {
                            id
                            standard_id
                            entity_type
                            definition_type
                            definition
                            x_opencti_order
                            x_opencti_color
                            created
                            modified
                        }
                    }
                }
            """
            stix_core_relationship = self.read(
                id=id, customAttributes=custom_attributes
            )
            if stix_core_relationship is None:
                self.opencti.log(
                    "error", "Cannot add Marking-Definition, entity not found"
                )
                return False
            if marking_definition_id in stix_core_relationship["markingDefinitionsIds"]:
                return True
            else:
                self.opencti.log(
                    "info",
                    "Adding Marking-Definition {"
                    + marking_definition_id
                    + "} to Stix-Domain-Object {"
                    + id
                    + "}",
                )
                query = """
                   mutation StixCoreRelationshipAddRelation($id: ID!, $input: StixMetaRelationshipAddInput) {
                       stixCoreRelationshipEdit(id: $id) {
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
                            "toId": marking_definition_id,
                            "relationship_type": "object-marking",
                        },
                    },
                )
                return True
        else:
            self.opencti.log(
                "error", "Missing parameters: id and marking_definition_id"
            )
            return False

    """
        Remove a Marking-Definition object to stix_core_relationship

        :param id: the id of the stix_core_relationship
        :param marking_definition_id: the id of the Marking-Definition
        :return Boolean
    """

    def remove_marking_definition(self, **kwargs):
        id = kwargs.get("id", None)
        marking_definition_id = kwargs.get("marking_definition_id", None)
        if id is not None and marking_definition_id is not None:
            self.opencti.log(
                "info",
                "Removing Marking-Definition {"
                + marking_definition_id
                + "} from stix_core_relationship {"
                + id
                + "}",
            )
            query = """
               mutation StixCoreRelationshipRemoveRelation($id: ID!, $toId: String!, $relationship_type: String!) {
                   stixCoreRelationshipEdit(id: $id) {
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
                    "toId": marking_definition_id,
                    "relationship_type": "object-marking",
                },
            )
            return True
        else:
            self.opencti.log("error", "Missing parameters: id and label_id")
            return False

    """
        Add a Label object to stix_core_relationship(labelging)

        :param id: the id of the stix_core_relationship
        :param label_id: the id of the Label
        :return Boolean
    """

    def add_label(self, **kwargs):
        id = kwargs.get("id", None)
        label_id = kwargs.get("label_id", None)
        label_name = kwargs.get("label_name", None)
        if label_name is not None:
            label = self.opencti.label.read(
                filters=[{"key": "value", "values": [label_name]}]
            )
            if label:
                label_id = label["id"]
            else:
                label = self.opencti.label.create(value=label_name)
                label_id = label["id"]
        if id is not None and label_id is not None:
            self.opencti.log(
                "info",
                "Adding label {"
                + label_id
                + "} to stix-core-relationship {"
                + id
                + "}",
            )
            query = """
               mutation StixCoreRelationshipAddRelation($id: ID!, $input: StixMetaRelationshipAddInput) {
                   stixCoreRelationshipEdit(id: $id) {
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
                        "toId": label_id,
                        "relationship_type": "object-label",
                    },
                },
            )
            return True
        else:
            self.opencti.log("error", "Missing parameters: id and label_id")
            return False

    """
        Add a External-Reference object to stix_core_relationship (external-reference)

        :param id: the id of the stix_core_relationship
        :param marking_definition_id: the id of the Marking-Definition
        :return Boolean
    """

    def add_external_reference(self, **kwargs):
        id = kwargs.get("id", None)
        external_reference_id = kwargs.get("external_reference_id", None)
        if id is not None and external_reference_id is not None:
            self.opencti.log(
                "info",
                "Adding External-Reference {"
                + external_reference_id
                + "} to stix-core-relationship {"
                + id
                + "}",
            )
            query = """
               mutation StixCoreRelationshipEditRelationAdd($id: ID!, $input: StixMetaRelationshipAddInput) {
                   stixCoreRelationshipEdit(id: $id) {
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
                        "toId": external_reference_id,
                        "relationship_type": "external-reference",
                    },
                },
            )
            return True
        else:
            self.opencti.log(
                "error", "Missing parameters: id and external_reference_id"
            )
            return False

    """
        Remove a External-Reference object to stix_core_relationship object

        :param id: the id of the stix_core_relationship
        :param external_reference_id: the id of the External-Reference
        :return Boolean
    """

    def remove_external_reference(self, **kwargs):
        id = kwargs.get("id", None)
        external_reference_id = kwargs.get("external_reference_id", None)
        if id is not None and external_reference_id is not None:
            self.opencti.log(
                "info",
                "Removing External-Reference {"
                + external_reference_id
                + "} from stix_core_relationship {"
                + id
                + "}",
            )
            query = """
               mutation StixCoreRelationshipRemoveRelation($id: ID!, $toId: String!, $relationship_type: String!) {
                   stixCoreRelationshipEdit(id: $id) {
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
                    "toId": external_reference_id,
                    "relationship_type": "external-reference",
                },
            )
            return True
        else:
            self.opencti.log("error", "Missing parameters: id and label_id")
            return False

    """
        Add a Kill-Chain-Phase object to stix_core_relationship object (kill_chain_phases)

        :param id: the id of the stix_core_relationship
        :param kill_chain_phase_id: the id of the Kill-Chain-Phase
        :return Boolean
    """

    def add_kill_chain_phase(self, **kwargs):
        id = kwargs.get("id", None)
        kill_chain_phase_id = kwargs.get("kill_chain_phase_id", None)
        if id is not None and kill_chain_phase_id is not None:
            self.opencti.log(
                "info",
                "Adding Kill-Chain-Phase {"
                + kill_chain_phase_id
                + "} to stix-core-relationship {"
                + id
                + "}",
            )
            query = """
               mutation StixCoreRelationshipAddRelation($id: ID!, $input: StixMetaRelationshipAddInput) {
                   stixCoreRelationshipEdit(id: $id) {
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
                        "toId": kill_chain_phase_id,
                        "relationship_type": "kill-chain-phase",
                    },
                },
            )
            return True
        else:
            self.opencti.log(
                "error",
                "[opencti_stix_core_relationship] Missing parameters: id and kill_chain_phase_id",
            )
            return False

    """
        Remove a Kill-Chain-Phase object to stix_core_relationship object

        :param id: the id of the stix_core_relationship
        :param kill_chain_phase_id: the id of the Kill-Chain-Phase
        :return Boolean
    """

    def remove_kill_chain_phase(self, **kwargs):
        id = kwargs.get("id", None)
        kill_chain_phase_id = kwargs.get("kill_chain_phase_id", None)
        if id is not None and kill_chain_phase_id is not None:
            self.opencti.log(
                "info",
                "Removing Kill-Chain-Phase {"
                + kill_chain_phase_id
                + "} from stix_core_relationship {"
                + id
                + "}",
            )
            query = """
               mutation StixCoreRelationshipRemoveRelation($id: ID!, $toId: String!, $relationship_type: String!) {
                   stixCoreRelationshipEdit(id: $id) {
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
                    "toId": kill_chain_phase_id,
                    "relationship_type": "kill-chain-phase",
                },
            )
            return True
        else:
            self.opencti.log(
                "error",
                "[stix_core_relationship] Missing parameters: id and kill_chain_phase_id",
            )
            return False

    """
        Update the Identity author of a stix_core_relationship object (created_by)

        :param id: the id of the stix_core_relationship
        :param identity_id: the id of the Identity
        :return Boolean
    """

    def update_created_by(self, **kwargs):
        id = kwargs.get("id", None)
        identity_id = kwargs.get("identity_id", None)
        if id is not None:
            self.opencti.log(
                "info",
                "Updating author of stix_core_relationship {"
                + id
                + "} with Identity {"
                + str(identity_id)
                + "}",
            )
            custom_attributes = """
                id
                createdBy {
                    ... on Identity {
                        id
                        standard_id
                        entity_type
                        parent_types
                        name
                        x_opencti_aliases
                        description
                        created
                        modified
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
            """
            stix_domain_object = self.read(id=id, customAttributes=custom_attributes)
            if stix_domain_object["createdBy"] is not None:
                query = """
                    mutation StixCoreRelationshipEdit($id: ID!, $toId: String! $relationship_type: String!) {
                        stixCoreRelationshipEdit(id: $id) {
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
                        "toId": stix_domain_object["createdBy"]["id"],
                        "relationship_type": "created-by",
                    },
                )
            if identity_id is not None:
                # Add the new relation
                query = """
                    mutation StixCoreRelationshipEdit($id: ID!, $input: StixMetaRelationshipAddInput) {
                        stixCoreRelationshipEdit(id: $id) {
                            relationAdd(input: $input) {
                                id
                            }
                        }
                    }
               """
                variables = {
                    "id": id,
                    "input": {
                        "toId": identity_id,
                        "relationship_type": "created-by",
                    },
                }
                self.opencti.query(query, variables)
        else:
            self.opencti.log("error", "Missing parameters: id")
            return False

    """
        Import an Indicator object from a STIX2 object

        :param stixObject: the Stix-Object Indicator
        :return Indicator object
    """

    def import_from_stix2(self, **kwargs):
        stix_relation = kwargs.get("stixRelation", None)
        extras = kwargs.get("extras", {})
        update = kwargs.get("update", False)
        default_date = kwargs.get("defaultDate", False)
        if stix_relation is not None:

            # TODO: Compatibility with OpenCTI 3.X to be REMOVED
            if "confidence" not in stix_relation:
                stix_relation["confidence"] = (
                    stix_relation["x_opencti_weight"]
                    if "x_opencti_weight" in stix_relation
                    else 0
                )
            if "start_time" not in stix_relation:
                stix_relation["start_time"] = (
                    stix_relation["x_opencti_first_seen"]
                    if "x_opencti_first_seen" in stix_relation
                    else None
                )
            if "stop_time" not in stix_relation:
                stix_relation["stop_time"] = (
                    stix_relation["x_opencti_last_seen"]
                    if "x_opencti_last_seen" in stix_relation
                    else None
                )
            if stix_relation["relationship_type"] == "gathering":
                stix_relation["relationship_type"] = "part-of"
            elif stix_relation["relationship_type"] == "localization":
                stix_relation["relationship_type"] = "located-at"

            return self.create(
                fromId=stix_relation["source_ref"],
                toId=stix_relation["target_ref"],
                stix_id=stix_relation["id"],
                relationship_type=stix_relation["relationship_type"],
                description=self.opencti.stix2.convert_markdown(
                    stix_relation["description"]
                )
                if "description" in stix_relation
                else "",
                start_time=stix_relation["start_time"]
                if "start_time" in stix_relation
                else default_date,
                stop_time=stix_relation["stop_time"]
                if "stop_time" in stix_relation
                else default_date,
                revoked=stix_relation["revoked"]
                if "revoked" in stix_relation
                else None,
                confidence=stix_relation["confidence"]
                if "confidence" in stix_relation
                else None,
                lang=stix_relation["lang"] if "lang" in stix_relation else None,
                created=stix_relation["created"]
                if "created" in stix_relation
                else None,
                modified=stix_relation["modified"]
                if "modified" in stix_relation
                else None,
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
                killChainPhases=extras["kill_chain_phases_ids"]
                if "kill_chain_phases_ids" in extras
                else None,
                update=update,
            )
        else:
            self.opencti.log(
                "error", "[opencti_attack_pattern] Missing parameters: stixObject"
            )
