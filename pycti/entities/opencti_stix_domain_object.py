# coding: utf-8

import json
import os
import magic


class StixDomainObject:
    def __init__(self, opencti, file):
        self.opencti = opencti
        self.file = file
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
            ... on AttackPattern {
                name
                description
                aliases
                x_mitre_platforms
                x_mitre_permissions_required
                x_mitre_detection
                x_mitre_id
                killChainPhases {
                    edges {
                        node {
                            id
                            standard_id                            
                            entity_type
                            kill_chain_name
                            phase_name
                            x_opencti_order
                            created
                            modified
                        }
                    }
                }
            }
            ... on Campaign {
                name
                description
                aliases
                first_seen
                last_seen
                objective
            }
            ... on Note {
                attribute_abstract
                content
                authors
                objects {
                    edges {
                        node {
                            ... on BasicObject {
                                id
                            }
                            ... on BasicRelationship {
                                id
                            } 
                        }
                    }
                }                
            }
            ... on ObservedData {
                first_observed
                last_observed
                number_observed
                objects {
                    edges {
                        node {
                            ... on BasicObject {
                                id
                            }
                            ... on BasicRelationship {
                                id
                            } 
                        }
                    }
                }                
            }
            ... on Opinion {
                explanation
                authors
                opinion
                objects {
                    edges {
                        node {
                            ... on BasicObject {
                                id
                            }
                            ... on BasicRelationship {
                                id
                            } 
                        }
                    }
                }                
            }
            ... on Report {
                name
                description
                report_types
                published
                x_opencti_report_status
                objects {
                    edges {
                        node {
                            ... on BasicObject {
                                id
                            }
                            ... on BasicRelationship {
                                id
                            } 
                        }
                    }
                }
            }
            ... on CourseOfAction {
                name
                description
                x_opencti_aliases
            }
            ... on Individual {
                name
                description
                x_opencti_aliases
                contact_information
                x_opencti_firstname
                x_opencti_lastname
            }
            ... on Organization {
                name
                description
                x_opencti_aliases
                contact_information
                x_opencti_organization_type
                x_opencti_reliability
            }
            ... on Sector {
                name
                description
                x_opencti_aliases
                contact_information
            }
            ... on Indicator {
                pattern_type
                pattern_version
                pattern
                name
                description
                indicator_types
                valid_from
                valid_until
                x_opencti_score
                x_opencti_detection
                x_opencti_main_observable_type
            }
            ... on Infrastructure {
                name
                description
                aliases
                infrastructure_types
                first_seen
                last_seen
            }
            ... on IntrusionSet {
                name
                description
                aliases
                first_seen
                last_seen
                goals
                resource_level
                primary_motivation
                secondary_motivations
            }
            ... on City {
                name
                description
                latitude
                longitude
                precision
                x_opencti_aliases
            }
            ... on Country {
                name
                description
                latitude
                longitude
                precision
                x_opencti_aliases
            }
            ... on Region {
                name
                description
                latitude
                longitude
                precision
                x_opencti_aliases
            }
            ... on Position {
                name
                description
                latitude
                longitude
                precision
                x_opencti_aliases
                street_address
                postal_code
            }
            ... on Malware {
                name
                description
                aliases
                malware_types
                is_family
                first_seen
                last_seen
                architecture_execution_envs
                implementation_languages
                capabilities
                killChainPhases {
                    edges {
                        node {
                            id
                            standard_id                            
                            entity_type
                            kill_chain_name
                            phase_name
                            x_opencti_order
                            created
                            modified
                        }
                    }
                }
            }
            ... on ThreatActor {
                name
                description
                aliases
                threat_actor_types
                first_seen
                last_seen
                roles
                goals
                sophistication
                resource_level
                primary_motivation
                secondary_motivations
                personal_motivations
            }
            ... on Tool {
                name
                description
                aliases
                tool_types
                tool_version
                killChainPhases {
                    edges {
                        node {
                            id
                            standard_id
                            entity_type
                            kill_chain_name
                            phase_name
                            x_opencti_order
                            created
                            modified
                        }
                    }
                }
            }
            ... on Vulnerability {
                name
                description
                x_opencti_base_score
                x_opencti_base_severity
                x_opencti_attack_vector
                x_opencti_integrity_impact
                x_opencti_availability_impact
            }
            ... on XOpenCTIIncident {
                name
                description
                aliases
                first_seen
                last_seen
                objective
            }
            importFiles {
                edges {
                    node {
                        id
                        name
                        size
                    }
                }
            }
        """

    """
        List Stix-Domain-Object objects

        :param types: the list of types
        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Stix-Domain-Object objects
    """

    def list(self, **kwargs):
        types = kwargs.get("types", None)
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
            "Listing Stix-Domain-Objects with filters " + json.dumps(filters) + ".",
        )
        query = (
            """
                query StixDomainObjects($types: [String], $filters: [StixDomainObjectsFiltering], $search: String, $first: Int, $after: ID, $orderBy: StixDomainObjectsOrdering, $orderMode: OrderingMode) {
                    stixDomainObjects(types: $types, filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
                "types": types,
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
            data = self.opencti.process_multiple(result["data"]["stixDomainObjects"])
            final_data = final_data + data
            while result["data"]["stixDomainObjects"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["stixDomainObjects"]["pageInfo"]["endCursor"]
                self.opencti.log("info", "Listing Stix-Domain-Entities after " + after)
                result = self.opencti.query(
                    query,
                    {
                        "types": types,
                        "filters": filters,
                        "search": search,
                        "first": first,
                        "after": after,
                        "orderBy": order_by,
                        "orderMode": order_mode,
                    },
                )
                data = self.opencti.process_multiple(
                    result["data"]["stixDomainObjects"]
                )
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["stixDomainObjects"], with_pagination
            )

    """
        Read a Stix-Domain-Object object
        
        :param id: the id of the Stix-Domain-Object
        :param types: list of Stix Domain Entity types
        :param filters: the filters to apply if no id provided
        :return Stix-Domain-Object object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        types = kwargs.get("types", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.log("info", "Reading Stix-Domain-Object {" + id + "}.")
            query = (
                """
                    query StixDomainObject($id: String!) {
                        stixDomainObject(id: $id) {
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
                result["data"]["stixDomainObject"]
            )
        elif filters is not None:
            result = self.list(
                types=types, filters=filters, customAttributes=custom_attributes
            )
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.log(
                "error",
                "[opencti_stix_domain_object] Missing parameters: id or filters",
            )
            return None

    """
        Get a Stix-Domain-Object object by stix_id or name

        :param types: a list of Stix-Domain-Object types
        :param stix_id: the STIX ID of the Stix-Domain-Object
        :param name: the name of the Stix-Domain-Object
        :return Stix-Domain-Object object
    """

    def get_by_stix_id_or_name(self, **kwargs):
        types = kwargs.get("types", None)
        stix_id = kwargs.get("stix_id", None)
        name = kwargs.get("name", None)
        aliases = kwargs.get("aliases", [])
        field_name = kwargs.get("fieldName", "aliases")
        custom_attributes = kwargs.get("customAttributes", None)
        object_result = None
        if stix_id is not None:
            object_result = self.read(id=stix_id, customAttributes=custom_attributes)
        if object_result is None and name is not None:
            # TODO: Change this logic and move it to the API.
            object_result = self.read(
                types=types,
                filters=[{"key": "name", "values": [name]}],
                customAttributes=custom_attributes,
            )
            if object_result is None:
                object_result = self.read(
                    types=types,
                    filters=[{"key": field_name, "values": [name]}],
                    customAttributes=custom_attributes,
                )
                if object_result is None:
                    for alias in aliases:
                        object_result = self.read(
                            types=types,
                            filters=[{"key": field_name, "values": [alias]}],
                            customAttributes=custom_attributes,
                        )
        return object_result

    """
        Update a Stix-Domain-Object object field

        :param id: the Stix-Domain-Object id
        :param key: the key of the field
        :param value: the value of the field
        :return The updated Stix-Domain-Object object
    """

    def update_field(self, **kwargs):
        id = kwargs.get("id", None)
        key = kwargs.get("key", None)
        value = kwargs.get("value", None)
        operation = kwargs.get("operation", "replace")

        if id is not None and key is not None and value is not None:
            self.opencti.log(
                "info", "Updating Stix-Domain-Object {" + id + "} field {" + key + "}."
            )
            query = """
                    mutation StixDomainObjectEdit($id: ID!, $input: EditInput!, $operation: EditOperation) {
                        stixDomainObjectEdit(id: $id) {
                            fieldPatch(input: $input, operation: $operation) {
                                id
                            }
                        }
                    }
                """
            result = self.opencti.query(
                query,
                {
                    "id": id,
                    "input": {"key": key, "value": value},
                    "operation": operation,
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["stixDomainObjectEdit"]["fieldPatch"]
            )
        else:
            self.opencti.log(
                "error",
                "[opencti_stix_domain_object] Missing parameters: id and key and value",
            )
            return None

    """
        Delete a Stix-Domain-Object

        :param id: the Stix-Domain-Object id
        :return void
    """

    def delete(self, **kwargs):
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.log("info", "Deleting Stix-Domain-Object {" + id + "}.")
            query = """
                 mutation StixDomainObjectEdit($id: ID!) {
                     stixDomainObjectEdit(id: $id) {
                         delete
                     }
                 }
             """
            self.opencti.query(query, {"id": id})
        else:
            self.opencti.log(
                "error", "[opencti_stix_domain_object] Missing parameters: id"
            )
            return None

    """
        Upload a file in this Stix-Domain-Object 

        :param id: the Stix-Domain-Object id
        :param file_name
        :param data
        :return void
    """

    def add_file(self, **kwargs):
        id = kwargs.get("id", None)
        file_name = kwargs.get("file_name", None)
        data = kwargs.get("data", None)
        mime_type = kwargs.get("mime_type", "text/plain")
        if id is not None and file_name is not None:
            stix_domain_object = self.read(id=id)
            if stix_domain_object is None:
                self.opencti.log("error", "Cannot add File, entity not found")
                return False
            final_file_name = os.path.basename(file_name)
            current_files = {}
            for file in stix_domain_object["importFiles"]:
                current_files[file["name"]] = file
            if final_file_name in current_files:
                return current_files[final_file_name]
            else:
                self.opencti.log(
                    "info", "Uploading a file in Stix-Domain-Object {" + id + "}."
                )
                query = """
                    mutation StixDomainObjectEdit($id: ID!, $file: Upload!) {
                        stixDomainObjectEdit(id: $id) {
                            importPush(file: $file) {
                                id
                                name
                            }
                        }
                    }
                 """
                if data is None:
                    data = open(file_name, "rb")
                    if file_name.endswith(".json"):
                        mime_type = "application/json"
                    else:
                        mime_type = magic.from_file(file_name, mime=True)

                return self.opencti.query(
                    query,
                    {"id": id, "file": (self.file(final_file_name, data, mime_type))},
                )
        else:
            self.opencti.log(
                "error",
                "[opencti_stix_domain_object] Missing parameters: id or file_name",
            )
            return None

    def push_list_export(self, entity_type, file_name, data, list_filters=""):
        query = """
            mutation StixDomainObjectsExportPush($type: String!, $file: Upload!, $listFilters: String) {
                stixDomainObjectsExportPush(type: $type, file: $file, listFilters: $listFilters)
            } 
        """
        self.opencti.query(
            query,
            {
                "type": entity_type,
                "file": (self.file(file_name, data)),
                "listFilters": list_filters,
            },
        )

    def push_entity_export(self, entity_id, file_name, data):
        query = """
            mutation StixDomainObjectEdit($id: ID!, $file: Upload!) {
                stixDomainObjectEdit(id: $id) {
                    exportPush(file: $file)
                }
            } 
        """
        self.opencti.query(
            query, {"id": entity_id, "file": (self.file(file_name, data))}
        )

    """
        Update the Identity author of a Stix-Domain-Object object (created_by)

        :param id: the id of the Stix-Domain-Object
        :param identity_id: the id of the Identity
        :return Boolean
    """

    def update_created_by(self, **kwargs):
        id = kwargs.get("id", None)
        identity_id = kwargs.get("identity_id", None)
        if id is not None:
            self.opencti.log(
                "info",
                "Updating author of Stix-Domain-Object {"
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
                    mutation StixDomainObjectEdit($id: ID!, $toId: String! $relationship_type: String!) {
                        stixDomainObjectEdit(id: $id) {
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
                    mutation StixDomainObjectEdit($id: ID!, $input: StixMetaRelationshipAddInput) {
                        stixDomainObjectEdit(id: $id) {
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
        Add a Marking-Definition object to Stix-Domain-Object object (object_marking_refs)

        :param id: the id of the Stix-Domain-Object
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
            stix_domain_object = self.read(id=id, customAttributes=custom_attributes)
            if stix_domain_object is None:
                self.opencti.log(
                    "error", "Cannot add Marking-Definition, entity not found"
                )
                return False
            if marking_definition_id in stix_domain_object["markingDefinitionsIds"]:
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
                   mutation StixDomainObjectAddRelation($id: ID!, $input: StixMetaRelationshipAddInput) {
                       stixDomainObjectEdit(id: $id) {
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
        Remove a Marking-Definition object to Stix-Domain-Object object

        :param id: the id of the Stix-Domain-Object
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
                + "} from Stix-Domain-Object {"
                + id
                + "}",
            )
            query = """
               mutation StixDomainObjectRemoveRelation($id: ID!, $toId: String!, $relationship_type: String!) {
                   stixDomainObjectEdit(id: $id) {
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
        Add a Label object to Stix-Domain-Object object

        :param id: the id of the Stix-Domain-Object
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
                "Adding label {" + label_id + "} to Stix-Domain-Object {" + id + "}",
            )
            query = """
               mutation StixDomainObjectAddRelation($id: ID!, $input: StixMetaRelationshipAddInput) {
                   stixDomainObjectEdit(id: $id) {
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
        Remove a Label object to Stix-Domain-Object object

        :param id: the id of the Stix-Domain-Object
        :param label_id: the id of the Label
        :return Boolean
    """

    def remove_label(self, **kwargs):
        id = kwargs.get("id", None)
        label_id = kwargs.get("label_id", None)
        label_name = kwargs.get("label_name", None)
        if label_name is not None:
            label = self.opencti.label.read(
                filters=[{"key": "value", "values": [label_name]}]
            )
            if label:
                label_id = label["id"]
        if id is not None and label_id is not None:
            self.opencti.log(
                "info",
                "Removing label {" + label_id + "} to Stix-Domain-Object {" + id + "}",
            )
            query = """
               mutation StixDomainObjectRemoveRelation($id: ID!, $toId: String!, $relationship_type: String!) {
                   stixDomainObjectEdit(id: $id) {
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
                    "toId": label_id,
                    "relationship_type": "object-label",
                },
            )
            return True
        else:
            self.opencti.log("error", "Missing parameters: id and label_id")
            return False

    """
        Add a External-Reference object to Stix-Domain-Object object (object_marking_refs)

        :param id: the id of the Stix-Domain-Object
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
                + "} to Stix-Domain-Object {"
                + id
                + "}",
            )
            query = """
               mutation StixDomainObjectEditRelationAdd($id: ID!, $input: StixMetaRelationshipAddInput) {
                   stixDomainObjectEdit(id: $id) {
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
        Remove a Label object to Stix-Domain-Object object

        :param id: the id of the Stix-Domain-Object
        :param label_id: the id of the Label
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
                + "} to Stix-Domain-Object {"
                + id
                + "}",
            )
            query = """
               mutation StixDomainObjectRemoveRelation($id: ID!, $toId: String!, $relationship_type: String!) {
                   stixDomainObjectEdit(id: $id) {
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
        Add a Kill-Chain-Phase object to Stix-Domain-Object object (kill_chain_phases)

        :param id: the id of the Stix-Domain-Object
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
                + "} to Stix-Domain-Object {"
                + id
                + "}",
            )
            query = """
               mutation StixDomainObjectAddRelation($id: ID!, $input: StixMetaRelationshipAddInput) {
                   stixDomainObjectEdit(id: $id) {
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
            self.opencti.log("error", "Missing parameters: id and kill_chain_phase_id")
            return False

    """
        Remove a Kill-Chain-Phase object to Stix-Domain-Object object

        :param id: the id of the Stix-Domain-Object
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
                + "} from Stix-Domain-Object {"
                + id
                + "}",
            )
            query = """
               mutation StixDomainObjectRemoveRelation($id: ID!, $toId: String!, $relationship_type: String!) {
                   stixDomainObjectEdit(id: $id) {
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
                "[stix_domain_object] Missing parameters: id and kill_chain_phase_id",
            )
            return False

    """
        Get the reports about a Stix-Domain-Object object

        :param id: the id of the Stix-Domain-Object
        :return Stix-Domain-Object object
    """

    def reports(self, **kwargs):
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.log(
                "info",
                "Getting reports of the Stix-Domain-Object {" + id + "}.",
            )
            query = """
                query StixDomainObject($id: String!) {
                    stixDomainObject(id: $id) {
                        reports {
                            edges {
                                node {
                                    id
                                    standard_id
                                    entity_type
                                    spec_version
                                    
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
                                    createdBy {
                                        node {
                                            id
                                            entity_type
                                            stix_id
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
                                                stix_id
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
                                    labels {
                                        edges {
                                            node {
                                                id
                                                label_type
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
                                                stix_id
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
                                                stix_id
                                                entity_type
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
                                                stix_id
                                                entity_type
                                                observable_value
                                            }
                                            relation {
                                                id
                                            }
                                        }
                                    }
                                    relationRefs {
                                        edges {
                                            node {
                                                id
                                                stix_id
                                            }
                                            relation {
                                                id
                                            }
                                        }
                                    }
                                }
                                relation {
                                    id
                                }
                            }
                        }
                    }
                }
             """
            result = self.opencti.query(query, {"id": id})
            processed_result = self.opencti.process_multiple_fields(
                result["data"]["Stix-Domain-Object"]
            )
            if processed_result:
                return processed_result["reports"]
            else:
                return []
        else:
            self.opencti.log("error", "Missing parameters: id")
            return None

    """
        Get the notes about a Stix-Domain-Object object

        :param id: the id of the Stix-Domain-Object
        :return Stix-Domain-Object object
    """

    def notes(self, **kwargs):
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.log(
                "info",
                "Getting notes of the Stix-Domain-Object {" + id + "}.",
            )
            query = """
                query StixDomainObject($id: String!) {
                    stixDomainObject(id: $id) {
                        notes {
                            edges {
                                node {
                                    id
                                    stix_id
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
                                    createdBy {
                                        node {
                                            id
                                            entity_type
                                            stix_id
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
                                                stix_id
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
                                    labels {
                                        edges {
                                            node {
                                                id
                                                label_type
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
                                                stix_id
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
                                                stix_id
                                                entity_type
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
                                                stix_id
                                                entity_type
                                                observable_value
                                            }
                                            relation {
                                                id
                                            }
                                        }
                                    }
                                    relationRefs {
                                        edges {
                                            node {
                                                id
                                                stix_id
                                            }
                                            relation {
                                                id
                                            }
                                        }
                                    }
                                }
                                relation {
                                    id
                                }
                            }
                        }
                    }
                }
             """
            result = self.opencti.query(query, {"id": id})
            processed_result = self.opencti.process_multiple_fields(
                result["data"]["Stix-Domain-Object"]
            )
            if processed_result:
                return processed_result["notes"]
            else:
                return []
        else:
            self.opencti.log("error", "Missing parameters: id")
            return None
