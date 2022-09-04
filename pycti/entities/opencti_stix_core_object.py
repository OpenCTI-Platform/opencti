# coding: utf-8
import json


class StixCoreObject:
    def __init__(self, opencti, file):
        self.opencti = opencti
        self.file = file

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
            ... on StixDomainObject {
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
                        }
                    }
                }
                revoked
                confidence
                created
                modified
            }
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
            }
            ... on ObservedData {
                first_observed
                last_observed
                number_observed
            }
            ... on Opinion {
                explanation
                authors
                opinion
            }
            ... on Report {
                name
                description
                report_types
                published
            }
            ... on CourseOfAction {
                name
                description
                x_opencti_aliases
            }
            ... on Individual {
                name
                description
                contact_information
                x_opencti_aliases
                x_opencti_firstname
                x_opencti_lastname
            }
            ... on Organization {
                name
                description
                contact_information
                x_opencti_aliases
                x_opencti_organization_type
                x_opencti_reliability
            }
            ... on Sector {
                name
                description
                contact_information
                x_opencti_aliases
            }
            ... on System {
                name
                description
                contact_information
                x_opencti_aliases
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
            ... on  Region {
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
            ... on Incident {
                name
                description
                aliases
                first_seen
                last_seen
                objective
            }
            ... on Event {
                name
                description
            }
            ... on Channel {
                name
                description
            }
            ... on Narrative {
                name
                description
            }
            ... on Language {
                name
            }
            ... on StixCyberObservable {
                observable_value
            }
        """

    """
        List Stix-Core-Object objects

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
            "info",
            "Listing Stix-Core-Objects with filters " + json.dumps(filters) + ".",
        )
        query = (
            """
                    query StixCoreObjects($types: [String], $filters: [StixCoreObjectsFiltering], $search: String, $first: Int, $after: ID, $orderBy: StixCoreObjectsOrdering, $orderMode: OrderingMode) {
                        stixCoreObjects(types: $types, filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
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
            data = self.opencti.process_multiple(result["data"]["stixCoreObjects"])
            final_data = final_data + data
            while result["data"]["stixCoreObjects"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["stixCoreObjects"]["pageInfo"]["endCursor"]
                self.opencti.log("info", "Listing Stix-Core-Objects after " + after)
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
                data = self.opencti.process_multiple(result["data"]["stixCoreObjects"])
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["stixCoreObjects"], with_pagination
            )

    """
        Update a Stix-Domain-Object object field

        :param id: the Stix-Domain-Object id
        :param key: the key of the field
        :param value: the value of the field
        :return The updated Stix-Domain-Object object
    """

    def merge(self, **kwargs):
        id = kwargs.get("id", None)
        stix_core_objects_ids = kwargs.get("object_ids", None)
        if id is not None and stix_core_objects_ids is not None:
            self.opencti.log(
                "info",
                "Merging Core object {"
                + id
                + "} with {"
                + ",".join(stix_core_objects_ids)
                + "}.",
            )
            query = """
                    mutation StixCoreObjectEdit($id: ID!, $stixCoreObjectsIds: [String]!) {
                        stixCoreObjectEdit(id: $id) {
                            merge(stixCoreObjectsIds: $stixCoreObjectsIds) {
                                id
                                standard_id
                                entity_type
                            }
                        }
                    }
                """
            result = self.opencti.query(
                query,
                {
                    "id": id,
                    "stixCoreObjectsIds": stix_core_objects_ids,
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["stixCoreObjectEdit"]["merge"]
            )
        else:
            self.opencti.log(
                "error",
                "[opencti_stix_core_object] Missing parameters: id and object_ids",
            )
            return None

    def list_files(self, **kwargs):
        id = kwargs.get("id", None)
        self.opencti.log(
            "info",
            "Listing files of Stix-Core-Object { " + id + " }",
        )
        query = """
                    query StixCoreObject($id: String!) {
                        stixCoreObject(id: $id) {
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
                """
        result = self.opencti.query(query, {"id": id})
        entity = self.opencti.process_multiple_fields(result["data"]["stixCoreObject"])
        return entity["importFiles"]

    """
        Get the reports about a Stix-Core-Object object

        :param id: the id of the Stix-Core-Object
        :return List of reports
    """

    def reports(self, **kwargs):
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.log(
                "info",
                "Getting reports of the Stix-Core-Object {" + id + "}.",
            )
            query = """
                query StixCoreObject($id: String!) {
                    stixCoreObject(id: $id) {
                        reports {
                            edges {
                                node {
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
                                }
                            }
                        }
                    }
                }
             """
            result = self.opencti.query(query, {"id": id})
            processed_result = self.opencti.process_multiple_fields(
                result["data"]["stixCoreObject"]
            )
            if processed_result:
                return processed_result["reports"]
            else:
                return []
        else:
            self.opencti.log("error", "Missing parameters: id")
            return None
