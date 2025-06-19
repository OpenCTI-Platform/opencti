import gql from 'graphql-tag';
import { describe, expect, it } from 'vitest';
import { queryAsAdmin, testContext } from '../../utils/testQuery';
import { FilterMode, FilterOperator } from '../../../src/generated/graphql';
import { RELATION_IN_PIR } from '../../../src/schema/stixRefRelationship';
import { SYSTEM_USER } from '../../../src/utils/access';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import type { BasicStoreEntity } from '../../../src/types/store';

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
              id
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
  let flaggedElementId: string = '';
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
        pir_rescan_days: 30,
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
    // fetch an element standard id
    const malware = await storeLoadById<BasicStoreEntity>(testContext, SYSTEM_USER, 'malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88', ENTITY_TYPE_MALWARE);
    flaggedElementId = malware.id;
    // flag the element
    const FLAG_QUERY = gql`
      mutation pirFlagElement($id: ID!, $input: PirFlagElementInput!) {
        pirFlagElement(id: $id, input: $input)
      }
    `;
    const relationshipId = 'relationship1';
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
      variables: { id: pirInternalId, input: { relationshipId, sourceId: flaggedElementId, matchingCriteria } },
    });
    // Verify the ref has been created
    const queryResult = await queryAsAdmin({
      query: LIST_RELS_QUERY,
      variables: { relationship_type: [RELATION_IN_PIR] },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.stixRefRelationships.edges.length).toEqual(1);
    expect(queryResult.data?.stixRefRelationships.edges[0].node.from.id).toEqual(flaggedElementId);
    expect(queryResult.data?.stixRefRelationships.edges[0].node.to.id).toEqual(pirInternalId);
    expect(queryResult.data?.stixRefRelationships.edges[0].node.pir_score).toEqual(67);
    expect(queryResult.data?.stixRefRelationships.edges[0].node.pir_explanations.length).toEqual(1);
    expect(queryResult.data?.stixRefRelationships.edges[0].node.pir_explanations[0].dependency_ids[0]).toEqual(relationshipId);
  });
  it('should update a pir meta rel by adding a new explanation', async () => {
    const FLAG_QUERY = gql`
      mutation pirFlagElement($id: ID!, $input: PirFlagElementInput!) {
        pirFlagElement(id: $id, input: $input)
      }
    `;
    const relationshipId = 'relationship2';
    const matchingCriteria = {
      filters: {
        mode: FilterMode.And,
        filterGroups: [],
        filters: [
          { key: ['toId'], values: ['d17360d5-0b58-4a21-bebc-84aa5a3f32b4'] }
        ]
      },
      weight: 1,
    };
    await queryAsAdmin({
      query: FLAG_QUERY,
      variables: { id: pirInternalId, input: { relationshipId, sourceId: flaggedElementId, matchingCriteria } },
    });
    // Verify the ref has been updated
    const queryResult = await queryAsAdmin({
      query: LIST_RELS_QUERY,
      variables: { relationship_type: [RELATION_IN_PIR] },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.stixRefRelationships.edges.length).toEqual(1);
    expect(queryResult.data?.stixRefRelationships.edges[0].node.from.id).toEqual(flaggedElementId);
    expect(queryResult.data?.stixRefRelationships.edges[0].node.to.id).toEqual(pirInternalId);
    expect(queryResult.data?.stixRefRelationships.edges[0].node.pir_score).toEqual(100);
    expect(queryResult.data?.stixRefRelationships.edges[0].node.pir_explanations.length).toEqual(2);
  });
  it('should update a pir meta rel by removing a dependency', async () => {
    const UNFLAG_QUERY = gql`
      mutation pirUnflagElement($id: ID!, $input: PirUnflagElementInput!) {
        pirUnflagElement(id: $id, input: $input)
      }
    `;
    const relationshipId = 'relationship2';
    await queryAsAdmin({
      query: UNFLAG_QUERY,
      variables: { id: pirInternalId, input: { relationshipId, sourceId: flaggedElementId } },
    });
    // Verify the ref has been updated
    const queryResult = await queryAsAdmin({
      query: LIST_RELS_QUERY,
      variables: { relationship_type: [RELATION_IN_PIR] },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.stixRefRelationships.edges.length).toEqual(1);
    expect(queryResult.data?.stixRefRelationships.edges[0].node.from.id).toEqual(flaggedElementId);
    expect(queryResult.data?.stixRefRelationships.edges[0].node.to.id).toEqual(pirInternalId);
    expect(queryResult.data?.stixRefRelationships.edges[0].node.pir_score).toEqual(67);
    expect(queryResult.data?.stixRefRelationships.edges[0].node.pir_explanations.length).toEqual(1);
  });
  it('should unflag an element', async () => {
    const UNFLAG_QUERY = gql`
      mutation pirUnflagElement($id: ID!, $input: PirUnflagElementInput!) {
        pirUnflagElement(id: $id, input: $input)
      }
    `;
    const relationshipId = 'relationship1';
    await queryAsAdmin({
      query: UNFLAG_QUERY,
      variables: { id: pirInternalId, input: { relationshipId, sourceId: flaggedElementId } },
    });
    // Verify the ref has been deleted
    const queryResult = await queryAsAdmin({
      query: LIST_RELS_QUERY,
      variables: { relationship_type: [RELATION_IN_PIR] },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.stixRefRelationships.edges.length).toEqual(0);
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
