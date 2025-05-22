import gql from 'graphql-tag';
import { describe, expect, it } from 'vitest';
import { queryAsAdmin } from '../../utils/testQuery';
import { FilterMode, FilterOperator } from '../../../src/generated/graphql';
import { RELATION_IN_PIR } from '../../../src/schema/stixRefRelationship';

const LIST_QUERY = gql`
  query pirs(
    $first: Int
    $after: ID
    $filters: FilterGroup
    $search: String
  ) {
    pirs(
      first: $first
      after: $after
      filters: $filters
      search: $search
    ) {
      edges {
        node {
          id
          name
          pir_filters
          pir_criteria {
            weight
            filters
          }
        }
      }
    }
  }
`;

const LIST_RELS_QUERY = gql`
  query stixRefRelationships(
    $filters: FilterGroup
    $relationship_type: [String]
  ) {
    stixRefRelationships(
      filters: $filters
      relationship_type: $relationship_type
    ) {
      edges {
        node {
          id
          relationship_type
          from {
            ... on StixObject {
              x_opencti_stix_ids
            }
          }
          to {
            ... on InternalObject{
              id
            }
          }
          pir_explanations {
            dependency_ids
            criterion {
              filters
              weight
            }
          }
          pir_score
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query pir($id: ID!) {
    pir(id: $id) {
      id
      standard_id
      name
      pir_criteria {
        weight
        filters
      }
      pir_filters
    }
  }
`;

describe('PIR resolver standard behavior', () => {
  let pirInternalId: string = '';
  it('should pir created', async () => {
    const CREATE_QUERY = gql`
      mutation PirAdd($input: PirAddInput!) {
        pirAdd(input: $input) {
          id
          standard_id
          name
        }
      }
    `;
    // Create the pir
    const PIR_TO_CREATE = {
      input: {
        name: 'MyPir',
        pir_filters: {
          mode: FilterMode.And,
          filterGroups: [],
          filters: [
            { key: ['confidence'], values: ['80'], operator: FilterOperator.Gt }
          ]
        },
        pir_criteria: [
          {
            weight: 2,
            filters: {
              mode: FilterMode.And,
              filterGroups: [],
              filters: [
                { key: ['toId'], values: ['24b6365f-dd85-4ee3-a28d-bb4b37e1619c'] }
              ]
            },
          },
          {
            weight: 1,
            filters: {
              mode: FilterMode.And,
              filterGroups: [],
              filters: [
                { key: ['toId'], values: ['d17360d5-0b58-4a21-bebc-84aa5a3f32b4'] }
              ]
            },
          },
        ]
      },
    };
    const pir = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: PIR_TO_CREATE,
    });
    expect(pir).not.toBeNull();
    expect(pir.data?.pirAdd).not.toBeNull();
    expect(pir.data?.pirAdd.name).toEqual('MyPir');
    pirInternalId = pir.data?.pirAdd.id;
  });
  it('should pir loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: pirInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.pir).not.toBeNull();
    expect(queryResult.data?.pir.id).toEqual(pirInternalId);
    expect(queryResult.data?.pir.pir_criteria.length).toEqual(2);
    expect(queryResult.data?.pir.pir_criteria[0].weight).toEqual(2);
    expect(JSON.parse(queryResult.data?.pir.pir_criteria[0].filters).filters[0].key[0]).toEqual('toId');
  });
  it('should list pirs', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data?.pirs.edges.length).toEqual(1);
  });
  it('should flag an element and create a pir meta rel', async () => {
    const FLAG_QUERY = gql`
      mutation pirFlagElement($id: ID!, $input: PirFlagElementInput!) {
        pirFlagElement(id: $id, input: $input)
      }
    `;
    const relationshipId = 'relationship--642f6fca-6c5a-495c-9419-9ee0a4a599ee';
    const sourceId = 'malware-analysis--8fd6fcd4-81a9-4937-92b8-4e1cbe68f263';
    const matchingCriteria = {
      filters: {
        mode: FilterMode.And,
        filterGroups: [],
        filters: [
          { key: ['toId'], values: ['24b6365f-dd85-4ee3-a28d-bb4b37e1619c'] }
        ]
      },
      weight: 2,
    };
    await queryAsAdmin({
      query: FLAG_QUERY,
      variables: { id: pirInternalId, input: { relationshipId, sourceId, matchingCriteria } },
    });
    // Verify the ref has been created
    const queryResult = await queryAsAdmin({
      query: LIST_RELS_QUERY,
      variables: { relationship_type: [RELATION_IN_PIR] },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.stixRefRelationships.edges.length).toEqual(1);
    expect(queryResult.data?.stixRefRelationships.edges[0].node.from.x_opencti_stix_ids[0]).toEqual(sourceId);
    expect(queryResult.data?.stixRefRelationships.edges[0].node.to.id).toEqual(pirInternalId);
    expect(queryResult.data?.stixRefRelationships.edges[0].node.pir_score).toEqual(67);
    expect(queryResult.data?.stixRefRelationships.edges[0].node.pir_explanations[0].dependency_ids[0]).toEqual(relationshipId);
  });
  it('should pir deleted', async () => {
    const DELETE_QUERY = gql`
      mutation pirDelete($id: ID!) {
        pirDelete(id: $id)
      }
    `;
    // Delete the pir
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: pirInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: pirInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.pir).toBeNull();
  });
});
