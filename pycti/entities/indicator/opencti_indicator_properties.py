INDICATOR_PROPERTIES = """
    id
    standard_id
    entity_type
    parent_types
    spec_version
    created_at
    updated_at
    creators {
        id
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
    objectOrganization {
        id
        standard_id
        name
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
    x_opencti_observable_values {
        type
        value
    }
    x_mitre_platforms
    observables {
        edges {
            node {
                id
                entity_type
                observable_value
            }
        }
    }
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
"""
INDICATOR_PROPERTIES_WITH_FILES = """
    id
    standard_id
    entity_type
    parent_types
    spec_version
    created_at
    updated_at
    creators {
        id
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
    objectOrganization {
        id
        standard_id
        name
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
    x_opencti_observable_values {
        type
        value
    }
    x_mitre_platforms
    observables {
        edges {
            node {
                id
                entity_type
                observable_value
            }
        }
    }
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
