import { graphql } from 'react-relay';

export const markingDefinitionsLinesSearchQuery = graphql`
    query MarkingDefinitionsQuerySearchQuery($search: String) {
        markingDefinitions(search: $search) {
            edges {
                node {
                    id
                    standard_id
                    definition_type
                    definition
                    x_opencti_order
                    x_opencti_color
                    created
                    modified
                }
            }
        }
    }
`;
