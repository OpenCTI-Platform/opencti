# coding: utf-8

import json
import os
import magic


class StixDomainEntity:
    def __init__(self, opencti, file):
        self.opencti = opencti
        self.file = file
        self.properties = """
            id
            stix_id_key
            entity_type
            parent_types
            name
            alias
            description
            graph_data        
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
            importFiles {
                edges {
                    node {
                        id
                        name
                        size
                    }
                }
            }
            ... on AttackPattern {
                platform
                required_permission
                external_id
            }
            ... on ThreatActor {
                goal
                sophistication
                resource_level
                primary_motivation
                secondary_motivation
                personal_motivation
            }
            ... on IntrusionSet {
                first_seen
                last_seen
                goal
                sophistication
                resource_level
                primary_motivation
                secondary_motivation
            }
            ... on Campaign {
                objective
                first_seen
                last_seen
            }
            ... on Incident {
                objective
                first_seen
                last_seen
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
            ... on Malware {
                is_family
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
            }
            ... on Tool {
                tool_version
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
            }
            ... on Vulnerability {
                base_score
                base_severity
                attack_vector
                integrity_impact
                availability_impact
            }
            ... on Organization {
                organization_class
            }
            ... on Indicator {
                indicator_pattern
                pattern_type
                observableRefs {
                    edges {
                        node {
                            id
                            stix_id_key
                            entity_type
                            observable_value
                        }
                        relation {
                            id
                        }
                    }
                }
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
            }
            ... on Report {
                report_class
                published
                object_status
                source_confidence_level
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
            }
        """

    """
        List Stix-Domain-Entity objects

        :param types: the list of types
        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row for pagination
        :return List of Stix-Domain-Entity objects
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
            "Listing Stix-Domain-Entities with filters " + json.dumps(filters) + ".",
        )
        query = (
            """
                query StixDomainEntities($types: [String], $filters: [StixDomainEntitiesFiltering], $search: String, $first: Int, $after: ID, $orderBy: StixDomainEntitiesOrdering, $orderMode: OrderingMode) {
                    stixDomainEntities(types: $types, filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
            data = self.opencti.process_multiple(result["data"]["stixDomainEntities"])
            final_data = final_data + data
            while result["data"]["stixDomainEntities"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["stixDomainEntities"]["pageInfo"]["endCursor"]
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
                    result["data"]["stixDomainEntities"]
                )
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["stixDomainEntities"], with_pagination
            )

    """
        Read a Stix-Domain-Entity object
        
        :param id: the id of the Stix-Domain-Entity
        :param types: list of Stix Domain Entity types
        :param filters: the filters to apply if no id provided
        :return Stix-Domain-Entity object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        types = kwargs.get("types", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.log("info", "Reading Stix-Domain-Entity {" + id + "}.")
            query = (
                """
                    query StixDomainEntity($id: String!) {
                        stixDomainEntity(id: $id) {
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
                result["data"]["stixDomainEntity"]
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
                "[opencti_stix_domain_entity] Missing parameters: id or filters",
            )
            return None

    """
        Get a Stix-Domain-Entity object by stix_id or name

        :param types: a list of Stix-Domain-Entity types
        :param stix_id_key: the STIX ID of the Stix-Domain-Entity
        :param name: the name of the Stix-Domain-Entity
        :return Stix-Domain-Entity object
    """

    def get_by_stix_id_or_name(self, **kwargs):
        types = kwargs.get("types", None)
        stix_id_key = kwargs.get("stix_id_key", None)
        name = kwargs.get("name", None)
        custom_attributes = kwargs.get("customAttributes", None)
        object_result = None
        if stix_id_key is not None:
            object_result = self.read(
                id=stix_id_key, customAttributes=custom_attributes
            )
        if object_result is None and name is not None:
            object_result = self.read(
                types=types,
                filters=[{"key": "name", "values": [name]}],
                customAttributes=custom_attributes,
            )
            if object_result is None:
                object_result = self.read(
                    types=types,
                    filters=[{"key": "alias", "values": [name]}],
                    customAttributes=custom_attributes,
                )
        return object_result

    """
        Update a Stix-Domain-Entity object field

        :param id: the Stix-Domain-Entity id
        :param key: the key of the field
        :param value: the value of the field
        :return The updated Stix-Domain-Entity object
    """

    def update_field(self, **kwargs):
        id = kwargs.get("id", None)
        key = kwargs.get("key", None)
        value = kwargs.get("value", None)
        if id is not None and key is not None and value is not None:
            self.opencti.log(
                "info", "Updating Stix-Domain-Entity {" + id + "} field {" + key + "}."
            )
            query = """
                    mutation StixDomainEntityEdit($id: ID!, $input: EditInput!) {
                        stixDomainEntityEdit(id: $id) {
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
                result["data"]["stixDomainEntityEdit"]["fieldPatch"]
            )
        else:
            self.opencti.log(
                "error",
                "[opencti_stix_domain_entity] Missing parameters: id and key and value",
            )
            return None

    """
        Delete a Stix-Domain-Entity

        :param id: the Stix-Domain-Entity id
        :return void
    """

    def delete(self, **kwargs):
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.log("info", "Deleting Stix-Domain-Entity {" + id + "}.")
            query = """
                 mutation StixDomainEntityEdit($id: ID!) {
                     stixDomainEntityEdit(id: $id) {
                         delete
                     }
                 }
             """
            self.opencti.query(query, {"id": id})
        else:
            self.opencti.log(
                "error", "[opencti_stix_domain_entity] Missing parameters: id"
            )
            return None

    """
        Upload a file in this Stix-Domain-Entity 

        :param id: the Stix-Domain-Entity id
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
            stix_domain_entity = self.read(id=id)
            if stix_domain_entity is None:
                self.opencti.log("error", "Cannot add File, entity not found")
                return False
            final_file_name = os.path.basename(file_name)
            current_files = {}
            for file in stix_domain_entity["importFiles"]:
                current_files[file["name"]] = file
            if final_file_name in current_files:
                return current_files[final_file_name]
            else:
                self.opencti.log(
                    "info", "Uploading a file in Stix-Domain-Entity {" + id + "}."
                )
                query = """
                    mutation StixDomainEntityEdit($id: ID!, $file: Upload!) {
                        stixDomainEntityEdit(id: $id) {
                            importPush(file: $file) {
                                id
                                name
                            }
                        }
                    }
                 """
                if data is None:
                    data = open(file_name, "rb")
                    mime_type = magic.from_file(file_name, mime=True)

                return self.opencti.query(
                    query,
                    {"id": id, "file": (self.file(final_file_name, data, mime_type))},
                )
        else:
            self.opencti.log(
                "error",
                "[opencti_stix_domain_entity] Missing parameters: id or file_name",
            )
            return None

    def push_list_export(self, entity_type, file_name, data, context="", list_args=""):
        query = """
            mutation StixDomainEntitiesExportPush($type: String!, $file: Upload!, $context: String, $listArgs: String) {
                stixDomainEntitiesExportPush(type: $type, file: $file, context: $context, listArgs: $listArgs)
            } 
        """
        self.opencti.query(
            query,
            {
                "type": entity_type,
                "file": (self.file(file_name, data)),
                "context": context,
                "listArgs": list_args,
            },
        )

    def push_entity_export(self, entity_id, file_name, data):
        query = """
            mutation StixDomainEntityEdit($id: ID!, $file: Upload!) {
                stixDomainEntityEdit(id: $id) {
                    exportPush(file: $file)
                }
            } 
        """
        self.opencti.query(
            query, {"id": entity_id, "file": (self.file(file_name, data))}
        )
