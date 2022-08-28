import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query subTypes($type: String!) {
    subTypes(type: $type) {
      edges {
        node {
          id
          label
        }
      }
    }
  }
`;

describe('SubType resolver standard behavior', () => {
  it('should list subTypes', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { type: 'Stix-Cyber-Observable' } });
    expect(queryResult.data.subTypes.edges.length).toEqual(28);
  });
});
