import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
import { ENTITY_TYPE_DATA_COMPONENT } from '../../../src/schema/stixDomainObject';

const RUNTIME_ATTRIBUTES_QUERY = gql`
  query runtimeAttributes(
    $first: Int
    $search: String
    $attributeName: String!
  ) {
    runtimeAttributes(
      first: $first
      search: $search
      attributeName: $attributeName
    ) {
      edges {
        node {
          value
        }
      }
    }
  }
`;

const SCHEMA_ATTRIBUTES_QUERY = gql`
  query schemaAttributes($elementType: [String]!) {
    schemaAttributes(elementType: $elementType) {
      edges {
        node {
          value
        }
      }
    }
  }
`;

describe('Attribute resolver standard behavior', () => {
  it('should retrieve runtime attribute for an entity', async () => {
    const queryResult = await queryAsAdmin({ query: RUNTIME_ATTRIBUTES_QUERY, variables: { attributeName: 'priority' } });
    const attributes = queryResult.data.runtimeAttributes.edges;
    expect(attributes.length).toEqual(0);
  });
  it('should retrieve schema attribute for an entity', async () => {
    const queryResult = await queryAsAdmin({ query: SCHEMA_ATTRIBUTES_QUERY, variables: { elementType: ENTITY_TYPE_DATA_COMPONENT } });
    const attributes = queryResult.data.schemaAttributes.edges.map((edgeNode) => edgeNode.node);
    expect(attributes.length).toEqual(10);
    expect(attributes.map((node) => node.value).includes('revoked')).toBeTruthy();
  });
});
