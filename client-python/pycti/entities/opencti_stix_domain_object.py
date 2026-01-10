# coding: utf-8

import json
import os

import magic


class StixDomainObject:
    """Main StixDomainObject class for OpenCTI

    Manages STIX Domain Objects in the OpenCTI platform.

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type opencti: OpenCTIApiClient
    """

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
            objectOrganization {
                id
                standard_id
                name
            }
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
                        id
                        value
                        color
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
            objectLabel {
                id
                value
                color
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
                note_types
                likelihood
                objects {
                    edges {
                        node {
                            ... on BasicObject {
                                id
                                parent_types
                                entity_type
                                standard_id
                            }
                            ... on BasicRelationship {
                                id
                                parent_types
                                entity_type
                                standard_id
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
                                parent_types
                                entity_type
                                standard_id
                            }
                            ... on BasicRelationship {
                                id
                                parent_types
                                entity_type
                                standard_id
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
                                parent_types
                                entity_type
                                standard_id
                            }
                            ... on BasicRelationship {
                                id
                                parent_types
                                entity_type
                                standard_id
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
                objects {
                    edges {
                        node {
                            ... on BasicObject {
                                id
                                parent_types
                                entity_type
                                standard_id
                            }
                            ... on BasicRelationship {
                                id
                                parent_types
                                entity_type
                                standard_id
                            }
                        }
                    }
                }
            }
            ... on Grouping {
                name
                description
                context
                objects {
                    edges {
                        node {
                            ... on BasicObject {
                                id
                                parent_types
                                entity_type
                                standard_id
                            }
                            ... on BasicRelationship {
                                id
                                parent_types
                                entity_type
                                standard_id
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
            ... on DataComponent {
                name
                description
                dataSource {
                    id
                    standard_id
                    entity_type
                    parent_types
                    spec_version
                    created_at
                    updated_at
                    revoked
                    confidence
                    created
                    modified
                    name
                    description
                    x_mitre_platforms
                    collection_layers
                }
            }
            ... on DataSource {
                name
                description
                x_mitre_platforms
                collection_layers
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
            ... on System {
                name
                description
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
            ... on MalwareAnalysis {
                product
                version
                configuration_version
                modules
                analysis_engine_version
                analysis_definition_version
                submitted
                analysis_started
                analysis_ended
                result_name
                result
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
            ... on Event {
                name
                description
                aliases
                event_types
            }
            ... on Channel {
                name
                description
                aliases
                channel_types
            }
            ... on Narrative {
                name
                description
                aliases
                narrative_types
            }
            ... on DataComponent {
                name
                description
            }
            ... on DataSource {
                name
                description
            }
            ... on Case {
                name
                description
                objects {
                    edges {
                        node {
                            ... on BasicObject {
                                id
                                parent_types
                                entity_type
                                standard_id
                            }
                            ... on BasicRelationship {
                                id
                                parent_types
                                entity_type
                                standard_id
                            }
                        }
                    }
                }
            }
            ... on Vulnerability {
                name
                description
                x_opencti_aliases
                x_opencti_cvss_vector_string
                x_opencti_cvss_base_score
                x_opencti_cvss_base_severity
                x_opencti_cvss_attack_vector
                x_opencti_cvss_attack_complexity
                x_opencti_cvss_privileges_required
                x_opencti_cvss_user_interaction
                x_opencti_cvss_scope
                x_opencti_cvss_confidentiality_impact
                x_opencti_cvss_integrity_impact
                x_opencti_cvss_availability_impact
                x_opencti_cvss_exploit_code_maturity
                x_opencti_cvss_remediation_level
                x_opencti_cvss_report_confidence
                x_opencti_cvss_temporal_score
                x_opencti_cvss_v2_vector_string
                x_opencti_cvss_v2_base_score
                x_opencti_cvss_v2_access_vector
                x_opencti_cvss_v2_access_complexity
                x_opencti_cvss_v2_authentication
                x_opencti_cvss_v2_confidentiality_impact
                x_opencti_cvss_v2_integrity_impact
                x_opencti_cvss_v2_availability_impact
                x_opencti_cvss_v2_exploitability
                x_opencti_cvss_v2_remediation_level
                x_opencti_cvss_v2_report_confidence
                x_opencti_cvss_v2_temporal_score
                x_opencti_cvss_v4_vector_string
                x_opencti_cvss_v4_base_score
                x_opencti_cvss_v4_base_severity
                x_opencti_cvss_v4_attack_vector
                x_opencti_cvss_v4_attack_complexity
                x_opencti_cvss_v4_attack_requirements
                x_opencti_cvss_v4_privileges_required
                x_opencti_cvss_v4_user_interaction
                x_opencti_cvss_v4_confidentiality_impact_v
                x_opencti_cvss_v4_confidentiality_impact_s
                x_opencti_cvss_v4_integrity_impact_v
                x_opencti_cvss_v4_integrity_impact_s
                x_opencti_cvss_v4_availability_impact_v
                x_opencti_cvss_v4_availability_impact_s
                x_opencti_cvss_v4_exploit_maturity
                x_opencti_cwe
                x_opencti_cisa_kev
                x_opencti_epss_score
                x_opencti_epss_percentile
                x_opencti_score
            }
            ... on Incident {
                name
                description
                aliases
                first_seen
                last_seen
                objective
            }
        """
        self.properties_with_files = """
            id
            standard_id
            entity_type
            parent_types
            spec_version
            created_at
            updated_at
            objectOrganization {
                id
                standard_id
                name
            }
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
                        id
                        value
                        color
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
            objectLabel {
                id
                value
                color
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
            ... on AttackPattern {
                name
                description
                aliases
                x_mitre_platforms
                x_mitre_permissions_required
                x_mitre_detection
                x_mitre_id
                killChainPhases {
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
                note_types
                likelihood
                objects {
                    edges {
                        node {
                            ... on BasicObject {
                                id
                                parent_types
                                entity_type
                                standard_id
                            }
                            ... on BasicRelationship {
                                id
                                parent_types
                                entity_type
                                standard_id
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
                                parent_types
                                entity_type
                                standard_id
                            }
                            ... on BasicRelationship {
                                id
                                parent_types
                                entity_type
                                standard_id
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
                                parent_types
                                entity_type
                                standard_id
                            }
                            ... on BasicRelationship {
                                id
                                parent_types
                                entity_type
                                standard_id
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
                objects {
                    edges {
                        node {
                            ... on BasicObject {
                                id
                                parent_types
                                entity_type
                                standard_id
                            }
                            ... on BasicRelationship {
                                id
                                parent_types
                                entity_type
                                standard_id
                            }
                        }
                    }
                }
            }
            ... on Grouping {
                name
                description
                context
                objects {
                    edges {
                        node {
                            ... on BasicObject {
                                id
                                parent_types
                                entity_type
                                standard_id
                            }
                            ... on BasicRelationship {
                                id
                                parent_types
                                entity_type
                                standard_id
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
            ... on DataComponent {
                name
                description
                dataSource {
                    id
                    standard_id
                    entity_type
                    parent_types
                    spec_version
                    created_at
                    updated_at
                    revoked
                    confidence
                    created
                    modified
                    name
                    description
                    x_mitre_platforms
                    collection_layers
                }
            }
            ... on DataSource {
                name
                description
                x_mitre_platforms
                collection_layers
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
            ... on System {
                name
                description
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
            ... on MalwareAnalysis {
                product
                version
                configuration_version
                modules
                analysis_engine_version
                analysis_definition_version
                submitted
                analysis_started
                analysis_ended
                result_name
                result
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
            ... on Event {
                name
                description
                aliases
                event_types
            }
            ... on Channel {
                name
                description
                aliases
                channel_types
            }
            ... on Narrative {
                name
                description
                aliases
                narrative_types
            }
            ... on DataComponent {
                name
                description
            }
            ... on DataSource {
                name
                description
            }
            ... on Case {
                name
                description
                objects {
                    edges {
                        node {
                            ... on BasicObject {
                                id
                                parent_types
                                entity_type
                                standard_id
                            }
                            ... on BasicRelationship {
                                id
                                parent_types
                                entity_type
                                standard_id
                            }
                        }
                    }
                }
            }
            ... on Vulnerability {
                name
                description
                x_opencti_aliases
                x_opencti_cvss_vector_string
                x_opencti_cvss_base_score
                x_opencti_cvss_base_severity
                x_opencti_cvss_attack_vector
                x_opencti_cvss_attack_complexity
                x_opencti_cvss_privileges_required
                x_opencti_cvss_user_interaction
                x_opencti_cvss_scope
                x_opencti_cvss_confidentiality_impact
                x_opencti_cvss_integrity_impact
                x_opencti_cvss_availability_impact
                x_opencti_cvss_exploit_code_maturity
                x_opencti_cvss_remediation_level
                x_opencti_cvss_report_confidence
                x_opencti_cvss_temporal_score
                x_opencti_cvss_v2_vector_string
                x_opencti_cvss_v2_base_score
                x_opencti_cvss_v2_access_vector
                x_opencti_cvss_v2_access_complexity
                x_opencti_cvss_v2_authentication
                x_opencti_cvss_v2_confidentiality_impact
                x_opencti_cvss_v2_integrity_impact
                x_opencti_cvss_v2_availability_impact
                x_opencti_cvss_v2_exploitability
                x_opencti_cvss_v2_remediation_level
                x_opencti_cvss_v2_report_confidence
                x_opencti_cvss_v2_temporal_score
                x_opencti_cvss_v4_vector_string
                x_opencti_cvss_v4_base_score
                x_opencti_cvss_v4_base_severity
                x_opencti_cvss_v4_attack_vector
                x_opencti_cvss_v4_attack_complexity
                x_opencti_cvss_v4_attack_requirements
                x_opencti_cvss_v4_privileges_required
                x_opencti_cvss_v4_user_interaction
                x_opencti_cvss_v4_confidentiality_impact_v
                x_opencti_cvss_v4_confidentiality_impact_s
                x_opencti_cvss_v4_integrity_impact_v
                x_opencti_cvss_v4_integrity_impact_s
                x_opencti_cvss_v4_availability_impact_v
                x_opencti_cvss_v4_availability_impact_s
                x_opencti_cvss_v4_exploit_maturity
                x_opencti_cwe
                x_opencti_cisa_kev
                x_opencti_epss_score
                x_opencti_epss_percentile
                x_opencti_score
            }
            ... on Incident {
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
                        metaData {
                            mimetype
                            version
                        }
                    }
                }
            }
        """

    def list(self, **kwargs):
        """List Stix-Domain-Object objects.

        :param types: the list of types
        :type types: list
        :param filters: the filters to apply
        :type filters: dict
        :param search: the search keyword
        :type search: str
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :type first: int
        :param after: ID of the first row for pagination
        :type after: str
        :param orderBy: field to order results by
        :type orderBy: str
        :param orderMode: ordering mode (asc/desc)
        :type orderMode: str
        :param customAttributes: custom attributes to return
        :type customAttributes: str
        :param getAll: whether to retrieve all results
        :type getAll: bool
        :param withPagination: whether to include pagination info
        :type withPagination: bool
        :param withFiles: whether to include files
        :type withFiles: bool
        :return: List of Stix-Domain-Object objects
        :rtype: list
        """
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
        with_files = kwargs.get("withFiles", False)

        self.opencti.app_logger.info(
            "Listing Stix-Domain-Objects with filters", {"filters": json.dumps(filters)}
        )
        query = (
            """
                query StixDomainObjects($types: [String], $filters: FilterGroup, $search: String, $first: Int, $after: ID, $orderBy: StixDomainObjectsOrdering, $orderMode: OrderingMode) {
                    stixDomainObjects(types: $types, filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
                        edges {
                            node {
                                """
            + (
                custom_attributes
                if custom_attributes is not None
                else (self.properties_with_files if with_files else self.properties)
            )
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
                self.opencti.app_logger.info(
                    "Listing Stix-Domain-Objects", {"after": after}
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
                data = self.opencti.process_multiple(
                    result["data"]["stixDomainObjects"]
                )
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["stixDomainObjects"], with_pagination
            )

    def read(self, **kwargs):
        """Read a Stix-Domain-Object object.

        :param id: the id of the Stix-Domain-Object
        :type id: str
        :param types: list of Stix Domain Entity types
        :type types: list
        :param filters: the filters to apply if no id provided
        :type filters: dict
        :param customAttributes: custom attributes to return
        :type customAttributes: str
        :param withFiles: whether to include files
        :type withFiles: bool
        :return: Stix-Domain-Object object
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        types = kwargs.get("types", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        with_files = kwargs.get("withFiles", False)
        if id is not None:
            self.opencti.app_logger.info("Reading Stix-Domain-Object", {"id": id})
            query = (
                """
                    query StixDomainObject($id: String!) {
                        stixDomainObject(id: $id) {
                            """
                + (
                    custom_attributes
                    if custom_attributes is not None
                    else (self.properties_with_files if with_files else self.properties)
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
            self.opencti.app_logger.error(
                "[opencti_stix_domain_object] Missing parameters: id or filters"
            )
            return None

    def get_by_stix_id_or_name(self, **kwargs):
        """Get a Stix-Domain-Object object by stix_id or name.

        :param types: a list of Stix-Domain-Object types
        :type types: list
        :param stix_id: the STIX ID of the Stix-Domain-Object
        :type stix_id: str
        :param name: the name of the Stix-Domain-Object
        :type name: str
        :param aliases: list of aliases to search
        :type aliases: list
        :param fieldName: the field name to use for alias search
        :type fieldName: str
        :param customAttributes: custom attributes to return
        :type customAttributes: str
        :return: Stix-Domain-Object object
        :rtype: dict or None
        """
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
                filters={
                    "mode": "and",
                    "filters": [{"key": "name", "values": [name]}],
                    "filterGroups": [],
                },
                customAttributes=custom_attributes,
            )
            if object_result is None:
                object_result = self.read(
                    types=types,
                    filters={
                        "mode": "and",
                        "filters": [{"key": field_name, "values": [name]}],
                        "filterGroups": [],
                    },
                    customAttributes=custom_attributes,
                )
                if object_result is None:
                    for alias in aliases:
                        object_result = self.read(
                            types=types,
                            filters={
                                "mode": "and",
                                "filters": [{"key": field_name, "values": [alias]}],
                                "filterGroups": [],
                            },
                            customAttributes=custom_attributes,
                        )
        return object_result

    def update_field(self, **kwargs):
        """Update a Stix-Domain-Object object field.

        :param id: the Stix-Domain-Object id
        :type id: str
        :param input: the input of the field
        :type input: list
        :return: Updated Stix-Domain-Object object
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        input = kwargs.get("input", None)
        if id is not None and input is not None:
            self.opencti.app_logger.info("Updating Stix-Domain-Object", {"id": id})
            query = """
                    mutation StixDomainObjectEdit($id: ID!, $input: [EditInput]!) {
                        stixDomainObjectEdit(id: $id) {
                            fieldPatch(input: $input) {
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
                    "input": input,
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["stixDomainObjectEdit"]["fieldPatch"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_stix_domain_object] Missing parameters: id and input"
            )
            return None

    def delete(self, **kwargs):
        """Delete a Stix-Domain-Object.

        :param id: the Stix-Domain-Object id
        :type id: str
        :return: None
        """
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.app_logger.info("Deleting Stix-Domain-Object", {"id": id})
            query = """
                 mutation StixDomainObjectEdit($id: ID!) {
                     stixDomainObjectEdit(id: $id) {
                         delete
                     }
                 }
             """
            self.opencti.query(query, {"id": id})
        else:
            self.opencti.app_logger.error(
                "[opencti_stix_domain_object] Missing parameters: id"
            )
            return None

    def add_file(self, **kwargs):
        """Upload a file to this Stix-Domain-Object.

        :param id: the Stix-Domain-Object id
        :type id: str
        :param file_name: the file name or path
        :type file_name: str
        :param data: the file data (optional, will read from file_name if not provided)
        :type data: bytes or None
        :param fileMarkings: list of marking definition IDs for the file
        :type fileMarkings: list
        :param version: version datetime
        :type version: str
        :param mime_type: MIME type of the file
        :type mime_type: str
        :param no_trigger_import: whether to skip triggering import
        :type no_trigger_import: bool
        :param embedded: whether the file is embedded
        :type embedded: bool
        :return: File upload result
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        file_name = kwargs.get("file_name", None)
        data = kwargs.get("data", None)
        file_markings = kwargs.get("fileMarkings", None)
        version = kwargs.get("version", None)
        mime_type = kwargs.get("mime_type", "text/plain")
        no_trigger_import = kwargs.get("no_trigger_import", False)
        embedded = kwargs.get("embedded", False)
        if id is not None and file_name is not None:
            final_file_name = os.path.basename(file_name)
            query = """
                mutation StixDomainObjectEdit($id: ID!, $file: Upload!, $fileMarkings: [String], $version: DateTime, $noTriggerImport: Boolean, $embedded: Boolean) {
                    stixDomainObjectEdit(id: $id) {
                        importPush(file: $file, version: $version, fileMarkings: $fileMarkings, noTriggerImport: $noTriggerImport, embedded: $embedded) {
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
            self.opencti.app_logger.info(
                "Uploading a file in Stix-Domain-Object",
                {"file": final_file_name, "id": id},
            )
            return self.opencti.query(
                query,
                {
                    "id": id,
                    "file": (self.opencti.file(final_file_name, data, mime_type)),
                    "fileMarkings": file_markings,
                    "version": version,
                    "noTriggerImport": (
                        no_trigger_import
                        if isinstance(no_trigger_import, bool)
                        else no_trigger_import == "True"
                    ),
                    "embedded": embedded,
                },
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_stix_domain_object] Missing parameters: id or file_name"
            )
            return None

    def push_list_export(
        self,
        entity_id,
        entity_type,
        file_name,
        file_markings,
        data,
        list_filters="",
        mime_type=None,
    ):
        """Push a list export file.

        :param entity_id: the entity id
        :type entity_id: str
        :param entity_type: the entity type
        :type entity_type: str
        :param file_name: the file name
        :type file_name: str
        :param file_markings: list of marking definition IDs
        :type file_markings: list
        :param data: the file data
        :type data: bytes or str
        :param list_filters: filters applied to the list export
        :type list_filters: str
        :param mime_type: MIME type of the file
        :type mime_type: str or None
        :return: None
        """
        query = """
            mutation StixDomainObjectsExportPush($entity_id: String, $entity_type: String!, $file: Upload!, $file_markings: [String]!, $listFilters: String) {
                stixDomainObjectsExportPush(entity_id: $entity_id, entity_type: $entity_type, file: $file,  file_markings: $file_markings, listFilters: $listFilters)
            }
        """
        if mime_type is None:
            file = self.opencti.file(file_name, data)
        else:
            file = self.opencti.file(file_name, data, mime_type)
        self.opencti.query(
            query,
            {
                "entity_id": entity_id,
                "entity_type": entity_type,
                "file": file,
                "file_markings": file_markings,
                "listFilters": list_filters,
            },
        )

    def push_entity_export(
        self, entity_id, file_name, data, file_markings=None, mime_type=None
    ):
        """Push an entity export file.

        :param entity_id: the entity id
        :type entity_id: str
        :param file_name: the file name
        :type file_name: str
        :param data: the file data
        :type data: bytes or str
        :param file_markings: list of marking definition IDs
        :type file_markings: list or None
        :param mime_type: MIME type of the file
        :type mime_type: str or None
        :return: None
        """
        if file_markings is None:
            file_markings = []
        query = """
            mutation StixDomainObjectEdit(
                $id: ID!, $file: Upload!,
                $file_markings: [String]!
            ) {
                stixDomainObjectEdit(id: $id) {
                    exportPush(
                        file: $file,
                        file_markings: $file_markings
                    )
                }
            }
        """
        if mime_type is None:
            file = self.opencti.file(file_name, data)
        else:
            file = self.opencti.file(file_name, data, mime_type)
        self.opencti.query(
            query, {"id": entity_id, "file": file, "file_markings": file_markings}
        )

    def update_created_by(self, **kwargs):
        """Update the Identity author of a Stix-Domain-Object object (created_by).

        :param id: the id of the Stix-Domain-Object
        :type id: str
        :param identity_id: the id of the Identity
        :type identity_id: str
        :return: True if successful, False otherwise
        :rtype: bool
        """
        id = kwargs.get("id", None)
        identity_id = kwargs.get("identity_id", None)
        if id is not None:
            self.opencti.app_logger.info(
                "Updating author of Stix-Domain-Object with Identity",
                {"id": id, "identity_id": identity_id},
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
                    mutation StixDomainObjectEdit($id: ID!, $toId: StixRef! $relationship_type: String!) {
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
                    mutation StixDomainObjectEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
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
            self.opencti.app_logger.error("Missing parameters: id")
            return False

    def add_marking_definition(self, **kwargs):
        """Add a Marking-Definition object to Stix-Domain-Object object (object_marking_refs).

        :param id: the id of the Stix-Domain-Object
        :type id: str
        :param marking_definition_id: the id of the Marking-Definition
        :type marking_definition_id: str
        :return: True if successful, False otherwise
        :rtype: bool
        """
        id = kwargs.get("id", None)
        marking_definition_id = kwargs.get("marking_definition_id", None)
        if id is not None and marking_definition_id is not None:
            custom_attributes = """
                id
                objectMarking {
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
            """
            stix_domain_object = self.read(id=id, customAttributes=custom_attributes)
            if stix_domain_object is None:
                self.opencti.app_logger.error(
                    "Cannot add Marking-Definition, entity not found"
                )
                return False
            if marking_definition_id in stix_domain_object["objectMarkingIds"]:
                return True
            else:
                self.opencti.app_logger.info(
                    "Adding Marking-Definition to Stix-Domain-Object",
                    {"marking_definition_id": marking_definition_id, "id": id},
                )
                query = """
                   mutation StixDomainObjectAddRelation($id: ID!, $input: StixRefRelationshipAddInput!) {
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
            self.opencti.app_logger.error(
                "Missing parameters: id and marking_definition_id"
            )
            return False

    def remove_marking_definition(self, **kwargs):
        """Remove a Marking-Definition object from Stix-Domain-Object object.

        :param id: the id of the Stix-Domain-Object
        :type id: str
        :param marking_definition_id: the id of the Marking-Definition
        :type marking_definition_id: str
        :return: True if successful, False otherwise
        :rtype: bool
        """
        id = kwargs.get("id", None)
        marking_definition_id = kwargs.get("marking_definition_id", None)
        if id is not None and marking_definition_id is not None:
            self.opencti.app_logger.info(
                "Removing Marking-Definition from Stix-Domain-Object",
                {"marking_definition_id": marking_definition_id, "id": id},
            )
            query = """
               mutation StixDomainObjectRemoveRelation($id: ID!, $toId: StixRef!, $relationship_type: String!) {
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
            self.opencti.app_logger.error("Missing parameters: id and marking_definition_id")
            return False

    def add_label(self, **kwargs):
        """Add a Label object to Stix-Domain-Object object.

        :param id: the id of the Stix-Domain-Object
        :type id: str
        :param label_id: the id of the Label
        :type label_id: str
        :param label_name: the name of the Label (alternative to label_id)
        :type label_name: str
        :return: True if successful, False otherwise
        :rtype: bool
        """
        id = kwargs.get("id", None)
        label_id = kwargs.get("label_id", None)
        label_name = kwargs.get("label_name", None)
        if label_name is not None:
            label = self.opencti.label.read(
                filters={
                    "mode": "and",
                    "filters": [{"key": "value", "values": [label_name]}],
                    "filterGroups": [],
                }
            )
            if label:
                label_id = label["id"]
            else:
                label = self.opencti.label.create(value=label_name)
                label_id = label["id"]
        if id is not None and label_id is not None:
            self.opencti.app_logger.info(
                "Adding label to Stix-Domain-Object", {"label_id": label_id, "id": id}
            )
            query = """
               mutation StixDomainObjectAddRelation($id: ID!, $input: StixRefRelationshipAddInput!) {
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
            self.opencti.app_logger.error("Missing parameters: id and label_id")
            return False

    def remove_label(self, **kwargs):
        """Remove a Label object from Stix-Domain-Object object.

        :param id: the id of the Stix-Domain-Object
        :type id: str
        :param label_id: the id of the Label
        :type label_id: str
        :param label_name: the name of the Label (alternative to label_id)
        :type label_name: str
        :return: True if successful, False otherwise
        :rtype: bool
        """
        id = kwargs.get("id", None)
        label_id = kwargs.get("label_id", None)
        label_name = kwargs.get("label_name", None)
        if label_name is not None:
            label = self.opencti.label.read(
                filters={
                    "mode": "and",
                    "filters": [{"key": "value", "values": [label_name]}],
                    "filterGroups": [],
                }
            )
            if label:
                label_id = label["id"]
        if id is not None and label_id is not None:
            self.opencti.app_logger.info(
                "Removing label from Stix-Domain-Object",
                {"label_id": label_id, "id": id},
            )
            query = """
               mutation StixDomainObjectRemoveRelation($id: ID!, $toId: StixRef!, $relationship_type: String!) {
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
            self.opencti.app_logger.error("Missing parameters: id and label_id")
            return False

    def add_external_reference(self, **kwargs):
        """Add an External-Reference object to Stix-Domain-Object object.

        :param id: the id of the Stix-Domain-Object
        :type id: str
        :param external_reference_id: the id of the External-Reference
        :type external_reference_id: str
        :return: True if successful, False otherwise
        :rtype: bool
        """
        id = kwargs.get("id", None)
        external_reference_id = kwargs.get("external_reference_id", None)
        if id is not None and external_reference_id is not None:
            self.opencti.app_logger.info(
                "Adding External-Reference to Stix-Domain-Object",
                {"external_reference_id": external_reference_id, "id": id},
            )
            query = """
               mutation StixDomainObjectEditRelationAdd($id: ID!, $input: StixRefRelationshipAddInput!) {
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
            self.opencti.app_logger.error(
                "Missing parameters: id and external_reference_id"
            )
            return False

    def remove_external_reference(self, **kwargs):
        """Remove an External-Reference object from Stix-Domain-Object object.

        :param id: the id of the Stix-Domain-Object
        :type id: str
        :param external_reference_id: the id of the External-Reference
        :type external_reference_id: str
        :return: True if successful, False otherwise
        :rtype: bool
        """
        id = kwargs.get("id", None)
        external_reference_id = kwargs.get("external_reference_id", None)
        if id is not None and external_reference_id is not None:
            self.opencti.app_logger.info(
                "Removing External-Reference from Stix-Domain-Object",
                {"external_reference_id": external_reference_id, "id": id},
            )
            query = """
               mutation StixDomainObjectRemoveRelation($id: ID!, $toId: StixRef!, $relationship_type: String!) {
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
            self.opencti.app_logger.error("Missing parameters: id and external_reference_id")
            return False

    def add_kill_chain_phase(self, **kwargs):
        """Add a Kill-Chain-Phase object to Stix-Domain-Object object (kill_chain_phases).

        :param id: the id of the Stix-Domain-Object
        :type id: str
        :param kill_chain_phase_id: the id of the Kill-Chain-Phase
        :type kill_chain_phase_id: str
        :return: True if successful, False otherwise
        :rtype: bool
        """
        id = kwargs.get("id", None)
        kill_chain_phase_id = kwargs.get("kill_chain_phase_id", None)
        if id is not None and kill_chain_phase_id is not None:
            self.opencti.app_logger.info(
                "Adding Kill-Chain-Phase to Stix-Domain-Object",
                {"kill_chain_phase_id": kill_chain_phase_id, "id": id},
            )
            query = """
               mutation StixDomainObjectAddRelation($id: ID!, $input: StixRefRelationshipAddInput!) {
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
            self.opencti.app_logger.error(
                "Missing parameters: id and kill_chain_phase_id"
            )
            return False

    def remove_kill_chain_phase(self, **kwargs):
        """Remove a Kill-Chain-Phase object from Stix-Domain-Object object.

        :param id: the id of the Stix-Domain-Object
        :type id: str
        :param kill_chain_phase_id: the id of the Kill-Chain-Phase
        :type kill_chain_phase_id: str
        :return: True if successful, False otherwise
        :rtype: bool
        """
        id = kwargs.get("id", None)
        kill_chain_phase_id = kwargs.get("kill_chain_phase_id", None)
        if id is not None and kill_chain_phase_id is not None:
            self.opencti.app_logger.info(
                "Removing Kill-Chain-Phase from Stix-Domain-Object",
                {"kill_chain_phase_id": kill_chain_phase_id, "id": id},
            )
            query = """
               mutation StixDomainObjectRemoveRelation($id: ID!, $toId: StixRef!, $relationship_type: String!) {
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
            self.opencti.app_logger.error(
                "[stix_domain_object] Missing parameters: id and kill_chain_phase_id"
            )
            return False

    def reports(self, **kwargs):
        """Get the reports about a Stix-Domain-Object object.

        :param id: the id of the Stix-Domain-Object
        :type id: str
        :return: List of reports
        :rtype: list or None
        """
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.app_logger.info(
                "Getting reports of the Stix-Domain-Object", {"id": id}
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
                                                id
                                                value
                                                color
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
                                    objectLabel {
                                        id
                                        value
                                        color
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
                result["data"]["stixDomainObject"]
            )
            if processed_result:
                return processed_result["reports"]
            else:
                return []
        else:
            self.opencti.app_logger.error("Missing parameters: id")
            return None

    def notes(self, **kwargs):
        """Get the notes about a Stix-Domain-Object object.

        :param id: the id of the Stix-Domain-Object
        :type id: str
        :return: List of notes
        :rtype: list or None
        """
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.app_logger.info(
                "Getting notes of the Stix-Domain-Object", {"id": id}
            )
            query = """
                query StixDomainObject($id: String!) {
                    stixDomainObject(id: $id) {
                        notes {
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
                                                id
                                                value
                                                color
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
                                    objectLabel {
                                        id
                                        value
                                        color
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
                                    attribute_abstract
                                    content
                                    authors
                                    note_types
                                    likelihood
                                }
                            }
                        }
                    }
                }
             """
            result = self.opencti.query(query, {"id": id})
            processed_result = self.opencti.process_multiple_fields(
                result["data"]["stixDomainObject"]
            )
            if processed_result:
                return processed_result["notes"]
            else:
                return []
        else:
            self.opencti.app_logger.error("Missing parameters: id")
            return None

    def observed_data(self, **kwargs):
        """Get the observed data of a Stix-Domain-Object object.

        :param id: the id of the Stix-Domain-Object
        :type id: str
        :return: List of observed data
        :rtype: list or None
        """
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.app_logger.info(
                "Getting Observed-Data of the Stix-Domain-Object", {"id": id}
            )
            query = """
                    query StixDomainObject($id: String!) {
                        stixDomainObject(id: $id) {
                            observedData {
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
                                                    id
                                                    value
                                                    color
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
                                        objectLabel {
                                            id
                                            value
                                            color
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
                                        first_observed
                                        last_observed
                                        number_observed
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
                        }
                    }
                 """
            result = self.opencti.query(query, {"id": id})
            processed_result = self.opencti.process_multiple_fields(
                result["data"]["stixDomainObject"]
            )
            if processed_result:
                return processed_result["observedData"]
            else:
                return []
        else:
            self.opencti.app_logger.error("Missing parameters: id")
            return None
