import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
import { now } from '../../../src/database/grakn';

const LIST_QUERY = gql`
  query opinions(
    $first: Int
    $after: ID
    $orderBy: OpinionsOrdering
    $orderMode: OrderingMode
    $filters: [OpinionsFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    opinions(
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
          explanation
        }
      }
    }
  }
`;

const TIMESERIES_QUERY = gql`
  query opinionsTimeSeries(
    $objectId: String
    $authorId: String
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
  ) {
    opinionsTimeSeries(
      objectId: $objectId
      authorId: $authorId
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

const NUMBER_QUERY = gql`
  query opinionsNumber($objectId: String, $endDate: DateTime!) {
    opinionsNumber(objectId: $objectId, endDate: $endDate) {
      total
      count
    }
  }
`;

const DISTRIBUTION_QUERY = gql`
  query opinionsDistribution(
    $objectId: String
    $field: String!
    $operation: StatsOperation!
    $limit: Int
    $order: String
  ) {
    opinionsDistribution(objectId: $objectId, field: $field, operation: $operation, limit: $limit, order: $order) {
      label
      value
    }
  }
`;

const READ_QUERY = gql`
  query opinion($id: String!) {
    opinion(id: $id) {
      id
      name
      description
      explanation
      toStix
    }
  }
`;

describe('Opinion resolver standard behavior', () => {
  let opinionInternalId;
  let opinionMarkingDefinitionRelationId;
  const opinionStixId = 'opinion--a144b39f-05e6-49ca-b761-46a536896026';
  it('should opinion created', async () => {
    const CREATE_QUERY = gql`
      mutation OpinionAdd($input: OpinionAddInput) {
        opinionAdd(input: $input) {
          id
          name
          description
          explanation
        }
      }
    `;
    // Create the opinion
    const OPINION_TO_CREATE = {
      input: {
        name: 'Opinion',
        stix_id_key: opinionStixId,
        description: 'strongly-agree',
        explanation: 'Explanation of the opinion',
      },
    };
    const opinion = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: OPINION_TO_CREATE,
    });
    expect(opinion).not.toBeNull();
    expect(opinion.data.opinionAdd).not.toBeNull();
    expect(opinion.data.opinionAdd.name).toEqual('Opinion');
    opinionInternalId = opinion.data.opinionAdd.id;
  });
  it('should opinion loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: opinionInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.opinion).not.toBeNull();
    expect(queryResult.data.opinion.id).toEqual(opinionInternalId);
    expect(queryResult.data.opinion.toStix.length).toBeGreaterThan(5);
  });
  it('should opinion loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: opinionStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.opinion).not.toBeNull();
    expect(queryResult.data.opinion.id).toEqual(opinionInternalId);
  });
  it('should opinion stix domain entities accurate', async () => {
    const OPINION_STIX_DOMAIN_ENTITIES = gql`
      query opinion($id: String!) {
        opinion(id: $id) {
          id
          objectRefs {
            edges {
              node {
                id
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: OPINION_STIX_DOMAIN_ENTITIES,
      variables: { id: '3391d309-0479-45e8-8fa6-e632d9c89d6d' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.opinion).not.toBeNull();
    expect(queryResult.data.opinion.id).toEqual('3391d309-0479-45e8-8fa6-e632d9c89d6d');
    expect(queryResult.data.opinion.objectRefs.edges.length).toEqual(4);
  });
  it('should opinion contains stix domain entity accurate', async () => {
    const OPINION_CONTAINS_STIX_DOMAIN_ENTITY = gql`
      query opinionContainsStixDomainEntity($id: String!, $objectId: String!) {
        opinionContainsStixDomainEntity(id: $id, objectId: $objectId)
      }
    `;
    const queryResult = await queryAsAdmin({
      query: OPINION_CONTAINS_STIX_DOMAIN_ENTITY,
      variables: { id: '3391d309-0479-45e8-8fa6-e632d9c89d6d', objectId: '82316ffd-a0ec-4519-a454-6566f8f5676c' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.opinionContainsStixDomainEntity).not.toBeNull();
    expect(queryResult.data.opinionContainsStixDomainEntity).toBeTruthy();
  });
  it('should opinion stix relations accurate', async () => {
    const OPINION_STIX_RELATIONS = gql`
      query opinion($id: String!) {
        opinion(id: $id) {
          id
          relationRefs {
            edges {
              node {
                id
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: OPINION_STIX_RELATIONS,
      variables: { id: '3391d309-0479-45e8-8fa6-e632d9c89d6d' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.opinion).not.toBeNull();
    expect(queryResult.data.opinion.id).toEqual('3391d309-0479-45e8-8fa6-e632d9c89d6d');
    expect(queryResult.data.opinion.relationRefs.edges.length).toEqual(1);
  });
  it('should opinion contains stix relation accurate', async () => {
    const OPINION_CONTAINS_STIX_RELATION = gql`
      query opinionContainsStixRelation($id: String!, $objectId: String!) {
        opinionContainsStixRelation(id: $id, objectId: $objectId)
      }
    `;
    const queryResult = await queryAsAdmin({
      query: OPINION_CONTAINS_STIX_RELATION,
      variables: { id: '3391d309-0479-45e8-8fa6-e632d9c89d6d', objectId: '97ebc9b3-8a25-428a-8523-1e87b2701d3d' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.opinionContainsStixRelation).not.toBeNull();
    expect(queryResult.data.opinionContainsStixRelation).toBeTruthy();
  });
  it('should opinion stix observables accurate', async () => {
    const OPINION_STIX_OBSERVABLES = gql`
      query opinion($id: String!) {
        opinion(id: $id) {
          id
          observableRefs {
            edges {
              node {
                id
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: OPINION_STIX_OBSERVABLES,
      variables: { id: '3391d309-0479-45e8-8fa6-e632d9c89d6d' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.opinion).not.toBeNull();
    expect(queryResult.data.opinion.id).toEqual('3391d309-0479-45e8-8fa6-e632d9c89d6d');
    expect(queryResult.data.opinion.observableRefs.edges.length).toEqual(3);
  });
  it('should list opinions', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.opinions.edges.length).toEqual(2);
  });
  it('should timeseries opinions to be accurate', async () => {
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
    expect(queryResult.data.opinionsTimeSeries.length).toEqual(13);
    expect(queryResult.data.opinionsTimeSeries[2].value).toEqual(1);
    expect(queryResult.data.opinionsTimeSeries[3].value).toEqual(0);
  });
  it('should timeseries opinions for entity to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: TIMESERIES_QUERY,
      variables: {
        objectId: 'ab78a62f-4928-4d5a-8740-03f0af9c4330',
        field: 'created',
        operation: 'count',
        startDate: '2020-01-01T00:00:00+00:00',
        endDate: '2021-01-01T00:00:00+00:00',
        interval: 'month',
      },
    });
    expect(queryResult.data.opinionsTimeSeries.length).toEqual(13);
    expect(queryResult.data.opinionsTimeSeries[2].value).toEqual(1);
    expect(queryResult.data.opinionsTimeSeries[3].value).toEqual(0);
  });
  it('should timeseries opinions for author to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: TIMESERIES_QUERY,
      variables: {
        authorId: 'c79e5d9f-4321-4174-b120-7cd9342ec88a',
        field: 'created',
        operation: 'count',
        startDate: '2020-01-01T00:00:00+00:00',
        endDate: '2021-01-01T00:00:00+00:00',
        interval: 'month',
      },
    });
    expect(queryResult.data.opinionsTimeSeries.length).toEqual(13);
    expect(queryResult.data.opinionsTimeSeries[2].value).toEqual(1);
    expect(queryResult.data.opinionsTimeSeries[3].value).toEqual(0);
  });
  it('should opinions number to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: NUMBER_QUERY,
      variables: {
        endDate: now(),
      },
    });
    expect(queryResult.data.opinionsNumber.total).toEqual(2);
    expect(queryResult.data.opinionsNumber.count).toEqual(2);
  });
  it('should opinions number by entity to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: NUMBER_QUERY,
      variables: {
        objectId: 'ab78a62f-4928-4d5a-8740-03f0af9c4330',
        endDate: now(),
      },
    });
    expect(queryResult.data.opinionsNumber.total).toEqual(1);
    expect(queryResult.data.opinionsNumber.count).toEqual(1);
  });
  it('should opinions distribution to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: DISTRIBUTION_QUERY,
      variables: {
        field: 'created_by_ref.name',
        operation: 'count',
      },
    });
    expect(queryResult.data.opinionsDistribution.length).toEqual(0);
  });
  it('should opinions distribution by entity to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: DISTRIBUTION_QUERY,
      variables: {
        objectId: 'ab78a62f-4928-4d5a-8740-03f0af9c4330',
        field: 'created_by_ref.name',
        operation: 'count',
      },
    });
    expect(queryResult.data.opinionsDistribution[0].label).toEqual('ANSSI');
    expect(queryResult.data.opinionsDistribution[0].value).toEqual(1);
  });
  it('should update opinion', async () => {
    const UPDATE_QUERY = gql`
      mutation OpinionEdit($id: ID!, $input: EditInput!) {
        opinionEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: opinionInternalId, input: { key: 'name', value: ['Opinion - test'] } },
    });
    expect(queryResult.data.opinionEdit.fieldPatch.name).toEqual('Opinion - test');
  });
  it('should context patch opinion', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation OpinionEdit($id: ID!, $input: EditContext) {
        opinionEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: opinionInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.opinionEdit.contextPatch.id).toEqual(opinionInternalId);
  });
  it('should context clean opinion', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation OpinionEdit($id: ID!) {
        opinionEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: opinionInternalId },
    });
    expect(queryResult.data.opinionEdit.contextClean.id).toEqual(opinionInternalId);
  });
  it('should add relation in opinion', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation OpinionEdit($id: ID!, $input: RelationAddInput!) {
        opinionEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on Opinion {
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
        id: opinionInternalId,
        input: {
          fromRole: 'so',
          toRole: 'marking',
          toId: '43f586bc-bcbc-43d1-ab46-43e5ab1a2c46',
          through: 'object_marking_refs',
        },
      },
    });
    expect(queryResult.data.opinionEdit.relationAdd.from.markingDefinitions.edges.length).toEqual(1);
    opinionMarkingDefinitionRelationId =
      queryResult.data.opinionEdit.relationAdd.from.markingDefinitions.edges[0].relation.id;
  });
  it('should delete relation in opinion', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation OpinionEdit($id: ID!, $relationId: ID!) {
        opinionEdit(id: $id) {
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
        id: opinionInternalId,
        relationId: opinionMarkingDefinitionRelationId,
      },
    });
    expect(queryResult.data.opinionEdit.relationDelete.markingDefinitions.edges.length).toEqual(0);
  });
  it('should opinion deleted', async () => {
    const DELETE_QUERY = gql`
      mutation opinionDelete($id: ID!) {
        opinionEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the opinion
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: opinionInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: opinionStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.opinion).toBeNull();
  });
});
