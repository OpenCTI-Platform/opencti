import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { isSorted, queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query subTypes($type: String) {
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
  it('should list subTypes with type Stix-Cyber-Observable', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { type: 'Stix-Cyber-Observable' } });
    expect(queryResult.data.subTypes.edges.length).toEqual(29);
    expect(isSorted(queryResult.data.subTypes.edges.map((edge) => edge.node.id))).toEqual(true);
  });
  it('should list default subTypes', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY });
    expect(queryResult.data.subTypes.edges.length).toEqual(33);
    expect(isSorted(queryResult.data.subTypes.edges.map((edge) => edge.node.id))).toEqual(true);
  });
});
