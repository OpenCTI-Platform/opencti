import { graphql } from 'react-relay';

const searchStixCoreObjectsByRepresentativeQuery = graphql`
  query BulkRelationDialogSearchQuery(
    $types: [String]
    $filters: FilterGroup
    $search: String
  ) {
    stixCoreObjects(types: $types, search: $search, filters: $filters) {
      edges {
        node {
          id
          entity_type
          representative {
            main
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          objectLabel {
            id
            value
            color
          }
          creators {
            id
            name
          }
          containersNumber {
            total
          }
        }
      }
    }
  }
`;

export default searchStixCoreObjectsByRepresentativeQuery;
