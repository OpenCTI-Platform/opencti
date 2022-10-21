import { graphql } from 'react-relay';

// eslint-disable-next-line import/prefer-default-export
export const statusTemplatesSearchQuery = graphql`
    query StatusTemplatesQuerySearchQuery($search: String) {
        statusTemplates(search: $search) {
            edges {
                node {
                    id
                    name
                    color
                }
            }
        }
    }
`;
