import { graphql } from 'react-relay';

export const knowledgeGraphStixCoreObjectQuery = graphql`
    query KnowledgeGraphQueryStixCoreObjectQuery($id: String!) {
        stixCoreObject(id: $id) {
            id
            entity_type
            parent_types
            created_at
            createdBy {
                ... on Identity {
                    id
                    name
                    entity_type
                }
            }
            objectMarking {
                id
                definition_type
                definition
                x_opencti_order
                x_opencti_color
            }
            ... on StixDomainObject {
                created
            }
            ... on AttackPattern {
                name
                x_mitre_id
            }
            ... on Campaign {
                name
                first_seen
                last_seen
            }
            ... on CourseOfAction {
                name
            }
            ... on Note {
                attribute_abstract
                content
            }
            ... on ObservedData {
                name
                first_observed
                last_observed
            }
            ... on Opinion {
                opinion
            }
            ... on Report {
                name
                published
            }
            ... on Grouping {
                name
                description
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
            ... on System {
                name
            }
            ... on Indicator {
                name
                valid_from
            }
            ... on Infrastructure {
                name
            }
            ... on IntrusionSet {
                name
                first_seen
                last_seen
            }
            ... on Position {
                name
            }
            ... on City {
                name
            }
            ... on AdministrativeArea {
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
                first_seen
                last_seen
            }
            ... on MalwareAnalysis {
                result_name
            }
            ... on ThreatActor {
                name
                entity_type
                first_seen
                last_seen
            }
            ... on Tool {
                name
            }
            ... on Vulnerability {
                name
            }
            ... on Incident {
                name
                first_seen
                last_seen
            }
            ... on StixCyberObservable {
                observable_value
            }
            ... on StixFile {
                observableName: name
            }
            ... on Event {
                name
            }
            ... on Case {
                name
            }
            ... on Narrative {
                name
            }
            ... on DataComponent {
                name
            }
            ... on DataSource {
                name
            }
            ... on Language {
                name
            }
        }
    }
`;

export const knowledgeGraphStixRelationshipQuery = graphql`
    query KnowledgeGraphQueryStixRelationshipQuery($id: String!) {
        stixRelationship(id: $id) {
            id
            entity_type
            parent_types
            ... on StixCoreRelationship {
                relationship_type
                start_time
                stop_time
                confidence
                created
                is_inferred
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
                    ... on StixCoreRelationship {
                        relationship_type
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
                    ... on StixCoreRelationship {
                        relationship_type
                    }
                }
                created_at
                createdBy {
                    ... on Identity {
                        id
                        name
                        entity_type
                    }
                }
                objectMarking {
                    id
                    definition_type
                    definition
                    x_opencti_order
                    x_opencti_color
                }
            }
            ... on StixRefRelationship {
                relationship_type
                start_time
                stop_time
                confidence
                is_inferred
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
                    ... on StixCoreRelationship {
                        relationship_type
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
                    ... on StixCoreRelationship {
                        relationship_type
                    }
                }
                created_at
                datable
                objectMarking {
                    id
                    definition_type
                    definition
                    x_opencti_order
                    x_opencti_color
                }
            }
            ... on StixSightingRelationship {
                relationship_type
                first_seen
                last_seen
                confidence
                created
                is_inferred
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
                    ... on StixCoreRelationship {
                        relationship_type
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
                    ... on StixCoreRelationship {
                        relationship_type
                    }
                }
                created_at
                createdBy {
                    ... on Identity {
                        id
                        name
                        entity_type
                    }
                }
                objectMarking {
                    id
                    definition_type
                    definition
                    x_opencti_order
                    x_opencti_color
                }
            }
        }
    }
`;

export const knowledgeGraphQueryCheckObjectQuery = graphql`
    query KnowledgeGraphQueryCheckObjectQuery($id: String!, $entityTypes: [String!]) {
        stixObjectOrStixRelationship(id: $id) {
            ... on BasicObject {
                id
            }
            ... on StixCoreObject {
                is_inferred
                parent_types
                containers(entityTypes: $entityTypes) {
                    edges {
                        node {
                            id
                        }
                    }
                }
            }
            ... on BasicRelationship {
                id
            }
            ... on StixCoreRelationship {
                is_inferred
                parent_types
                containers(entityTypes: $entityTypes) {
                    edges {
                        node {
                            id
                        }
                    }
                }
            }
            ... on StixRefRelationship {
                is_inferred
                parent_types
                containers(entityTypes: $entityTypes) {
                    edges {
                        node {
                            id
                        }
                    }
                }
            }
            ... on StixSightingRelationship {
                is_inferred
                parent_types
                containers(entityTypes: $entityTypes) {
                    edges {
                        node {
                            id
                        }
                    }
                }
            }
        }
    }
`;

export const knowledgeGraphQueryStixRelationshipDeleteMutation = graphql`
    mutation KnowledgeGraphQueryStixRelationshipDeleteMutation($id: ID!) {
        stixRelationshipEdit(id: $id) {
            delete
        }
    }
`;

export const knowledgeGraphQueryStixObjectDeleteMutation = graphql`
    mutation KnowledgeGraphQueryStixCoreObjectDeleteMutation($id: ID!) {
        stixCoreObjectEdit(id: $id) {
            delete
        }
    }
`;
