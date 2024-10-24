import { graphql } from 'react-relay';

const stixCoreObjectsAttributesQuery = graphql`
    query StixCoreObjectsAttributesQuery($id: String!) {
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
            representative {
                main
                secondary
            }
            creators {
                id
                name
            }
            objectLabel {
                id
                value
                color
            }
            objectMarking {
                id
                definition_type
                definition
                x_opencti_order
                x_opencti_color
            }
            externalReferences {
                edges {
                    node {
                        id
                        source_name
                        url
                        external_id
                        description
                    }
                }
            }
            reports(first: 10) {
                edges {
                    node {
                        id
                        entity_type
                        name
                        description
                        published
                        report_types
                        createdBy {
                            ... on Identity {
                                id
                                name
                                entity_type
                            }
                        }
                    }
                }
                pageInfo {
                    globalCount
                }
            }
            ... on StixDomainObject {
                modified
                created
                confidence
            }
            ... on AttackPattern {
                name
                x_mitre_id
                description
            }
            ... on Campaign {
                name
                description
                first_seen
                last_seen
            }
            ... on CourseOfAction {
                name
                description
            }
            ... on Note {
                attribute_abstract
                content
            }
            ... on ObservedData {
                name
            }
            ... on Opinion {
                opinion
            }
            ... on Report {
                name
                published
                description
            }
            ... on Grouping {
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
                indicator_types
            }
            ... on Infrastructure {
                name
                description
            }
            ... on IntrusionSet {
                name
                first_seen
                last_seen
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
                first_seen
                last_seen
                description
            }
            ... on MalwareAnalysis {
                result_name
            }
            ... on ThreatActor {
                name
                first_seen
                last_seen
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
                first_seen
                last_seen
                description
            }
            ... on CaseIncident {
                priority
                severity
            }
            ... on StixCyberObservable {
                observable_value
                x_opencti_description
            }
            ... on StixFile {
                observableName: name
                x_opencti_additional_names
                hashes {
                    algorithm
                    hash
                }
            }
            ... on Event {
                name
                description
            }
            ... on Case {
                name
                description
            }
            ... on Task {
                name
                description
                status {
                    template_id
                    id
                }
                due_date
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
                description
            }
            ... on DataSource {
                name
                description
            }
            ... on Language {
                name
            }
        }
    }
`;

export default stixCoreObjectsAttributesQuery;