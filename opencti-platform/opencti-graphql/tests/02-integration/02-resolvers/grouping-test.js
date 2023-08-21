import { expect, afterAll, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, queryAsAdmin, testContext } from '../../utils/testQuery';
import { now } from '../../../src/utils/format';
import { listAllEntities } from '../../../src/database/middleware-loader';
import { ENTITY_TYPE_WORKSPACE } from '../../../src/modules/workspace/workspace-types';
import { deleteElementById } from '../../../src/database/middleware';

const LIST_QUERY = gql`
  query groupings(
    $first: Int
    $after: ID
    $orderBy: GroupingsOrdering
    $orderMode: OrderingMode
    $filters: [GroupingsFiltering!]
    $filterMode: FilterMode
    $search: String
  ) {
    groupings(
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
          context
        }
      }
    }
  }
`;

const TIMESERIES_QUERY = gql`
  query groupingsTimeSeries(
    $objectId: String
    $authorId: String
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
  ) {
    groupingsTimeSeries(
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
  query groupingsNumber($objectId: String, $endDate: DateTime!) {
    groupingsNumber(objectId: $objectId, endDate: $endDate) {
      total
      count
    }
  }
`;

const READ_QUERY = gql`
  query grouping($id: String!) {
    grouping(id: $id) {
      id
      standard_id
      name
      description
      context
      toStix
    }
  }
`;

describe('Grouping resolver standard behavior', () => {
  let groupingInternalId;
  const groupingStixId = 'grouping--994491f0-f114-4e41-bcf0-3288c0324f53';
  it('should grouping created', async () => {
    await queryAsAdmin({
      query: gql`
        mutation vocabularyAdd($input: VocabularyAddInput!) {
          vocabularyAdd(input: $input) {
            id
          }
        }
      `,
      variables: { input: { name: 'test', category: 'grouping_context_ov' } },
    });

    const CREATE_QUERY = gql`
      mutation GroupingAdd($input: GroupingAddInput!) {
        groupingAdd(input: $input) {
          id
          standard_id
          name
          description
          context
        }
      }
    `;
    // Create the grouping
    const GROUPING_TO_CREATE = {
      input: {
        stix_id: groupingStixId,
        name: 'Grouping',
        description: 'Grouping description',
        context: 'test',
        created: '2020-02-26T00:51:35.000Z',
        objects: [
          'campaign--92d46985-17a6-4610-8be8-cc70c82ed214',
          'relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02',
        ],
      },
    };
    const grouping = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: GROUPING_TO_CREATE,
    });
    expect(grouping).not.toBeNull();
    expect(grouping.data.groupingAdd).not.toBeNull();
    expect(grouping.data.groupingAdd.name).toEqual('Grouping');
    groupingInternalId = grouping.data.groupingAdd.id;
  });
  it('should grouping loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: groupingInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.grouping).not.toBeNull();
    expect(queryResult.data.grouping.id).toEqual(groupingInternalId);
    expect(queryResult.data.grouping.toStix.length).toBeGreaterThan(5);
  });
  it('should grouping loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: groupingStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.grouping).not.toBeNull();
    expect(queryResult.data.grouping.id).toEqual(groupingInternalId);
  });
  it('should grouping stix objects sor stix relationships accurate', async () => {
    const GROUPING_STIX_DOMAIN_ENTITIES = gql`
      query grouping($id: String!) {
        grouping(id: $id) {
          id
          standard_id
          objects {
            edges {
              node {
                ... on BasicObject {
                  id
                  standard_id
                }
                ... on BasicRelationship {
                  id
                  standard_id
                }
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: GROUPING_STIX_DOMAIN_ENTITIES,
      variables: { id: groupingInternalId },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.grouping).not.toBeNull();
    expect(queryResult.data.grouping.objects.edges.length).toEqual(2);
  });
  it('should list groupings', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.groupings.edges.length).toEqual(1);
  });
  it('should timeseries groupings to be accurate', async () => {
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
    expect(queryResult.data.groupingsTimeSeries.length).toEqual(13);
    expect(queryResult.data.groupingsTimeSeries[1].value).toEqual(1);
    expect(queryResult.data.groupingsTimeSeries[2].value).toEqual(0);
  });
  it('should groupings number to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: NUMBER_QUERY,
      variables: {
        endDate: now(),
      },
    });
    expect(queryResult.data.groupingsNumber.total).toEqual(1);
    expect(queryResult.data.groupingsNumber.count).toEqual(1);
  });
  it('should update grouping', async () => {
    const UPDATE_QUERY = gql`
      mutation GroupingEdit($id: ID!, $input: [EditInput]!) {
        groupingFieldPatch(id: $id, input: $input) {
          id
          name
          description
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: groupingInternalId, input: { key: 'name', value: ['Grouping - test'] } },
    });
    expect(queryResult.data.groupingFieldPatch.name).toEqual('Grouping - test');
  });
  it('should context patch grouping', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation GroupingEdit($id: ID!, $input: EditContext) {
        groupingContextPatch(id: $id, input: $input) {
          id
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: groupingInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.groupingContextPatch.id).toEqual(groupingInternalId);
  });
  it('should context clean grouping', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation GroupingEdit($id: ID!) {
        groupingContextClean(id: $id) {
          id
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: groupingInternalId },
    });
    expect(queryResult.data.groupingContextClean.id).toEqual(groupingInternalId);
  });
  it('should add relation in grouping', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation GroupingEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
        groupingRelationAdd(id: $id, input: $input) {
          id
          from {
            ... on Grouping {
              objectMarking {
                edges {
                  node {
                    id
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
        id: groupingInternalId,
        input: {
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.groupingRelationAdd.from.objectMarking.edges.length).toEqual(1);
  });
  describe('startInvestigation', () => {
    afterAll(async () => {
      const investigations = await listAllEntities(
        testContext,
        ADMIN_USER,
        [ENTITY_TYPE_WORKSPACE],
        {
          filters: [{
            key: 'type',
            value: 'investigation'
          }]
        }
      );

      await Promise.all(investigations.map(({ id }) => deleteElementById(testContext, ADMIN_USER, id, ENTITY_TYPE_WORKSPACE)));
    });

    it('can start an investigation', async () => {
      const graphQLResponse = await queryAsAdmin({
        query: gql`
          query StartInvestigationFromGrouping($id: String!) {
            grouping(id: $id) {
              name
              startInvestigation {
                id
                name
              }
            }
          }
        `,
        variables: {
          id: groupingInternalId
        },
      });
      const { grouping } = graphQLResponse.data;

      expect(grouping.startInvestigation.id).toBeDefined();
    });
  });
  it('should delete relation in grouping', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation GroupingEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        groupingRelationDelete(id: $id, toId: $toId, relationship_type: $relationship_type) {
          id
          objectMarking {
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
      query: RELATION_DELETE_QUERY,
      variables: {
        id: groupingInternalId,
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.groupingRelationDelete.objectMarking.edges.length).toEqual(0);
  });
  it('should grouping deleted', async () => {
    const DELETE_QUERY = gql`
      mutation groupingDelete($id: ID!) {
        groupingDelete(id: $id)
      }
    `;
    // Delete the grouping
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: groupingInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: groupingStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.grouping).toBeNull();
  });
});
