import gql from 'graphql-tag';
import { describe, expect, it } from 'vitest';
import { queryAsAdmin } from '../../utils/testQuery';
import { FilterMode, FilterOperator } from '../../../src/generated/graphql';

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

const READ_QUERY = gql`
  query pir($id: String!) {
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

describe('Report resolver standard behavior', () => {
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
    pirInternalId = pir.data?.reportAdd.id;
  });
  it('should pir loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: pirInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.pir).not.toBeNull();
    expect(queryResult.data?.pir.id).toEqual(pirInternalId);
    expect(queryResult.data?.pir.pir_criteria.length).toEqual(2);
    expect(queryResult.data?.pir.pir_criteria[0].weight).toEqual(2);
    expect(JSON.parse(queryResult.data?.pir.pir_criteria[0].filters).filters[0].key).toEqual('toId');
  });
  it('should list pirs', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data?.pirs.edges.length).toEqual(1);
  });
  it('should pir deleted', async () => {
    const DELETE_QUERY = gql`
      mutation pirDelete($id: ID!) {
        pirDelete(id: $id)
      }
    `;
    // Delete the report
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
