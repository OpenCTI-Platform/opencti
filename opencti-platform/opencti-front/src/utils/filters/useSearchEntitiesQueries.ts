import { graphql } from 'react-relay';

export const filtersStixCoreObjectsContainersSearchQuery = graphql`
    query useSearchEntitiesQueriesStixCoreObjectsContainersSearchQuery(
        $search: String
        $filters: FilterGroup
    ) {
        containers(search: $search, filters: $filters) {
            edges {
                node {
                    id
                    entity_type
                    parent_types
                    representative {
                        main
                    }
                }
            }
        }
    }
`;

export const filtersStixCoreObjectsSearchQuery = graphql`
    query useSearchEntitiesQueriesStixCoreObjectsSearchQuery(
        $search: String
        $types: [String]
        $count: Int
        $filters: FilterGroup
    ) {
        stixCoreObjects(
            search: $search
            types: $types
            first: $count
            filters: $filters
        ) {
            edges {
                node {
                    id
                    entity_type
                    parent_types
                    ... on AttackPattern {
                        name
                        description
                        x_mitre_id
                    }
                    ... on Note {
                        attribute_abstract
                        content
                    }
                    ... on ObservedData {
                        first_observed
                        last_observed
                    }
                    ... on Opinion {
                        opinion
                    }
                    ... on Report {
                        name
                    }
                    ... on Grouping {
                        name
                    }
                    ... on Campaign {
                        name
                        description
                    }
                    ... on CourseOfAction {
                        name
                        description
                    }
                    ... on Individual {
                        name
                        description
                    }
                    ... on Organization {
                        name
                        description
                    }
                    ... on Sector {
                        name
                        description
                    }
                    ... on System {
                        name
                        description
                    }
                    ... on Indicator {
                        name
                        description
                    }
                    ... on Infrastructure {
                        name
                        description
                    }
                    ... on IntrusionSet {
                        name
                        description
                    }
                    ... on Position {
                        name
                        description
                    }
                    ... on City {
                        name
                        description
                    }
                    ... on AdministrativeArea {
                        name
                        description
                    }
                    ... on Country {
                        name
                        description
                    }
                    ... on Region {
                        name
                        description
                    }
                    ... on Malware {
                        name
                        description
                    }
                    ... on MalwareAnalysis {
                        product
                        operatingSystem {
                            name
                        }
                    }
                    ... on ThreatActor {
                        name
                        description
                    }
                    ... on Tool {
                        name
                        description
                    }
                    ... on Vulnerability {
                        name
                        description
                    }
                    ... on Incident {
                        name
                        description
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
                    ... on DataComponent {
                        name
                    }
                    ... on DataSource {
                        name
                    }
                    ... on Case {
                        name
                    }
                    ... on Task {
                        name
                    }
                    ... on Language {
                        name
                    }
                    ... on StixCyberObservable {
                        observable_value
                    }
                    createdBy {
                        ... on Identity {
                            id
                            name
                            entity_type
                        }
                    }
                    objectMarking {
                        edges {
                            node {
                                id
                                definition_type
                                definition
                                x_opencti_order
                                x_opencti_color
                            }
                        }
                    }
                }
            }
        }
    }
`;

export const filtersSchemaSCOSearchQuery = graphql`
    query useSearchEntitiesQueriesSchemaSCOSearchQuery {
        schemaSCOs: subTypes(type: "Stix-Cyber-Observable") {
            edges {
                node {
                    id
                    label
                }
            }
        }
    }
`;
