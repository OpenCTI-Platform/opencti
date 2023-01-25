import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { isSorted, queryAsAdmin } from '../../utils/testQuery';
import { ENTITY_TYPE_DATA_COMPONENT } from '../../../src/schema/stixDomainObject';

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

const SUB_TYPE_ATTRIBUTES_QUERY = gql`
  query subType($id: String!) {
    subType(id: $id) {
      mandatoryAttributes {
        name
        builtIn
        mandatory
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
    expect(queryResult.data.subTypes.edges.length).toEqual(34);
    expect(isSorted(queryResult.data.subTypes.edges.map((edge) => edge.node.id))).toEqual(true);
  });
  it('should retrieve mandatory attribute for an entity', async () => {
    const queryResult = await queryAsAdmin({ query: SUB_TYPE_ATTRIBUTES_QUERY, variables: { id: ENTITY_TYPE_DATA_COMPONENT } });
    const attributes = queryResult.data.subType.mandatoryAttributes;
    expect(attributes.map((node) => node.name).includes('name')).toBeTruthy();
  });
});
