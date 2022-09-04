# coding: utf-8


class StixObjectOrStixRelationship:
    def __init__(self, opencti):
        self.opencti = opencti
        self.properties = """
            ... on StixObject {
                id
                standard_id
                entity_type
                parent_types
                spec_version
                created_at
                updated_at
            }
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
            ... on StixCoreRelationship {
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
                description
                start_time
                stop_time
            }
            ... on StixSightingRelationship {
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
                confidence
                created
                modified
                description
                attribute_count
                x_opencti_negative
                first_seen
                last_seen
            }
        """

    """
        Read a StixObjectOrStixRelationship object

        :param id: the id of the StixObjectOrStixRelationship
        :return StixObjectOrStixRelationship object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.log(
                "info", "Reading StixObjectOrStixRelationship {" + id + "}."
            )
            query = (
                """
                query StixObjectOrStixRelationship($id: String!) {
                    stixObjectOrStixRelationship(id: $id) {
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
                result["data"]["stixObjectOrStixRelationship"]
            )
        else:
            self.opencti.log("error", "Missing parameters: id")
            return None
