import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query stixDomainEntities(
    $first: Int
    $after: ID
    $orderBy: StixDomainEntitiesOrdering
    $orderMode: OrderingMode
    $filters: [StixDomainEntitiesFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    stixDomainEntities(
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      filterMode: $filterMode
      search: $search
    ) {
      edges {
        node {
          id
          name
          description
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query stixDomainEntity($id: String!) {
    stixDomainEntity(id: $id) {
      id
      name
      description
      toStix
    }
  }
`;

describe('StixDomainEntity resolver standard behavior', () => {
  let stixDomainEntityInternalId;
  let stixDomainEntityMarkingDefinitionRelationId;
  const stixDomainEntityStixId = 'report--34c9875d-8206-4f4b-bf17-f58d9cf7ebec';
  it('should stixDomainEntity created', async () => {
    const CREATE_QUERY = gql`
      mutation StixDomainEntityAdd($input: StixDomainEntityAddInput) {
        stixDomainEntityAdd(input: $input) {
          id
          name
          description
          tags {
            edges {
              node {
                id
              }
            }
          }
        }
      }
    `;
    // Create the stixDomainEntity
    const STIX_DOMAIN_ENTITY_TO_CREATE = {
      input: {
        name: 'StixDomainEntity',
        type: 'Report',
        stix_id_key: stixDomainEntityStixId,
        description: 'StixDomainEntity description',
        tags: ['ebd3398f-2189-4597-b994-5d1ab310d4bc', 'd2f32968-7e6a-4a78-b0d7-df4e9e30130c'],
      },
    };
    const stixDomainEntity = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: STIX_DOMAIN_ENTITY_TO_CREATE,
    });
    expect(stixDomainEntity).not.toBeNull();
    expect(stixDomainEntity.data.stixDomainEntityAdd).not.toBeNull();
    expect(stixDomainEntity.data.stixDomainEntityAdd.name).toEqual('StixDomainEntity');
    expect(stixDomainEntity.data.stixDomainEntityAdd.tags.edges.length).toEqual(2);
    stixDomainEntityInternalId = stixDomainEntity.data.stixDomainEntityAdd.id;
  });
  it('should stixDomainEntity loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixDomainEntityInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixDomainEntity).not.toBeNull();
    expect(queryResult.data.stixDomainEntity.id).toEqual(stixDomainEntityInternalId);
    expect(queryResult.data.stixDomainEntity.toStix.length).toBeGreaterThan(5);
  });
  it('should stixDomainEntity loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixDomainEntityStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixDomainEntity).not.toBeNull();
    expect(queryResult.data.stixDomainEntity.id).toEqual(stixDomainEntityInternalId);
  });
  it('should list stixDomainEntities', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.stixDomainEntities.edges.length).toEqual(10);
  });
  it('should stixDomainEntities number to be accurate', async () => {
    const NUMBER_QUERY = gql`
      query stixDomainEntitiesNumber {
        stixDomainEntitiesNumber {
          total
        }
      }
    `;
    const queryResult = await queryAsAdmin({ query: NUMBER_QUERY });
    expect(queryResult.data.stixDomainEntitiesNumber.total).toEqual(69);
  });
  it('should timeseries stixDomainEntities to be accurate', async () => {
    const TIMESERIES_QUERY = gql`
      query stixDomainEntitiesTimeSeries(
        $type: String
        $field: String!
        $operation: StatsOperation!
        $startDate: DateTime!
        $endDate: DateTime!
        $interval: String!
      ) {
        stixDomainEntitiesTimeSeries(
          type: $type
          field: $field
          operation: $operation
          startDate: $startDate
          endDate: $endDate
          interval: $interval
        ) {
          date
          value
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: TIMESERIES_QUERY,
      variables: {
        field: 'created',
        operation: 'count',
        startDate: '2020-01-01T00:00:00+00:00',
        endDate: '2021-01-01T00:00:00+00:00',
        interval: 'month',
      },
    });
    expect(queryResult.data.stixDomainEntitiesTimeSeries.length).toEqual(13);
    expect(queryResult.data.stixDomainEntitiesTimeSeries[1].value).toEqual(12);
    expect(queryResult.data.stixDomainEntitiesTimeSeries[2].value).toEqual(5);
  });
  it('should update stixDomainEntity', async () => {
    const UPDATE_QUERY = gql`
      mutation StixDomainEntityEdit($id: ID!, $input: EditInput!) {
        stixDomainEntityEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: stixDomainEntityInternalId, input: { key: 'name', value: ['StixDomainEntity - test'] } },
    });
    expect(queryResult.data.stixDomainEntityEdit.fieldPatch.name).toEqual('StixDomainEntity - test');
  });
  it('should context patch stixDomainEntity', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation StixDomainEntityEdit($id: ID!, $input: EditContext) {
        stixDomainEntityEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: stixDomainEntityInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.stixDomainEntityEdit.contextPatch.id).toEqual(stixDomainEntityInternalId);
  });
  it('should context clean stixDomainEntity', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation StixDomainEntityEdit($id: ID!) {
        stixDomainEntityEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: stixDomainEntityInternalId },
    });
    expect(queryResult.data.stixDomainEntityEdit.contextClean.id).toEqual(stixDomainEntityInternalId);
  });
  it('should add relation in stixDomainEntity', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation StixDomainEntityEdit($id: ID!, $input: RelationAddInput!) {
        stixDomainEntityEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on StixDomainEntity {
                markingDefinitions {
                  edges {
                    node {
                      id
                    }
                    relation {
                      id
                    }
                  }
                }
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_ADD_QUERY,
      variables: {
        id: stixDomainEntityInternalId,
        input: {
          fromRole: 'so',
          toRole: 'marking',
          toId: '43f586bc-bcbc-43d1-ab46-43e5ab1a2c46',
          through: 'object_marking_refs',
        },
      },
    });
    expect(queryResult.data.stixDomainEntityEdit.relationAdd.from.markingDefinitions.edges.length).toEqual(1);
    stixDomainEntityMarkingDefinitionRelationId =
      queryResult.data.stixDomainEntityEdit.relationAdd.from.markingDefinitions.edges[0].relation.id;
  });
  it('should delete relation in stixDomainEntity', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation StixDomainEntityEdit($id: ID!, $relationId: ID!) {
        stixDomainEntityEdit(id: $id) {
          relationDelete(relationId: $relationId) {
            id
            markingDefinitions {
              edges {
                node {
                  id
                }
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: stixDomainEntityInternalId,
        relationId: stixDomainEntityMarkingDefinitionRelationId,
      },
    });
    expect(queryResult.data.stixDomainEntityEdit.relationDelete.markingDefinitions.edges.length).toEqual(0);
  });
  it('should delete relation with toId in stixDomainEntity', async () => {
    const RELATION_TOID_DELETE_QUERY = gql`
      mutation StixDomainEntityEdit($id: ID!, $toId: String, $relationType: String) {
        stixDomainEntityEdit(id: $id) {
          relationDelete(toId: $toId, relationType: $relationType) {
            id
            tags {
              edges {
                node {
                  id
                }
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_TOID_DELETE_QUERY,
      variables: {
        id: stixDomainEntityInternalId,
        toId: 'ebd3398f-2189-4597-b994-5d1ab310d4bc',
        relationType: 'tagged',
      },
    });
    expect(queryResult.data.stixDomainEntityEdit.relationDelete.tags.edges.length).toEqual(1);
  });
  it('should stixDomainEntity deleted', async () => {
    const DELETE_QUERY = gql`
      mutation stixDomainEntityDelete($id: ID!) {
        stixDomainEntityEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the stixDomainEntity
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: stixDomainEntityInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixDomainEntityStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixDomainEntity).toBeNull();
    // TODO Verify is no relations are linked to the deleted entity
  });
});
