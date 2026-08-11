import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQueryHelper';

const LIST_QUERY = gql`
  query intrusionSets(
    $first: Int
    $after: ID
    $orderBy: IntrusionSetsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    intrusionSets(
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      search: $search
    ) {
      edges {
        node {
          id
          name
          description
          x_opencti_score
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query intrusionSet($id: String!) {
    intrusionSet(id: $id) {
      id
      standard_id
      name
      description
      x_opencti_score
      toStix
    }
  }
`;

describe('Intrusion set resolver standard behavior', () => {
  let intrusionSetInternalId;
  let intrusionSetForOrderingAInternalId;
  let intrusionSetForOrderingBInternalId;
  const intrusionSetStixId = 'intrusion-set--952ec932-a8c8-4050-9662-f0771ed7c477';
  const intrusionSetForOrderingAStixId = 'intrusion-set--11111111-a8c8-4050-9662-f0771ed7c477';
  const intrusionSetForOrderingBStixId = 'intrusion-set--22222222-a8c8-4050-9662-f0771ed7c477';
  it('should intrusion set created', async () => {
    const CREATE_QUERY = gql`
      mutation IntrusionSetAdd($input: IntrusionSetAddInput!) {
        intrusionSetAdd(input: $input) {
          id
          name
          description
          x_opencti_score
        }
      }
    `;
    // Create the intrusion set
    const INTRUSION_SET_TO_CREATE = {
      input: {
        name: 'Intrusion set',
        stix_id: intrusionSetStixId,
        description: 'Intrusion set description',
        x_opencti_score: 40,
      },
    };
    const intrusionSet = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: INTRUSION_SET_TO_CREATE,
    });
    expect(intrusionSet).not.toBeNull();
    expect(intrusionSet.data.intrusionSetAdd).not.toBeNull();
    expect(intrusionSet.data.intrusionSetAdd.name).toEqual('Intrusion set');
    expect(intrusionSet.data.intrusionSetAdd.x_opencti_score).toEqual(40);
    intrusionSetInternalId = intrusionSet.data.intrusionSetAdd.id;
  });
  it('should create intrusion sets for score ordering and filtering', async () => {
    const CREATE_QUERY = gql`
      mutation IntrusionSetAdd($input: IntrusionSetAddInput!) {
        intrusionSetAdd(input: $input) {
          id
          name
          x_opencti_score
        }
      }
    `;
    const intrusionSetA = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: {
        input: {
          name: 'Intrusion set score test A',
          stix_id: intrusionSetForOrderingAStixId,
          description: 'Intrusion set score test A description',
          x_opencti_score: 10,
        },
      },
    });
    const intrusionSetB = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: {
        input: {
          name: 'Intrusion set score test B',
          stix_id: intrusionSetForOrderingBStixId,
          description: 'Intrusion set score test B description',
          x_opencti_score: 80,
        },
      },
    });

    expect(intrusionSetA.data.intrusionSetAdd.x_opencti_score).toEqual(10);
    expect(intrusionSetB.data.intrusionSetAdd.x_opencti_score).toEqual(80);

    intrusionSetForOrderingAInternalId = intrusionSetA.data.intrusionSetAdd.id;
    intrusionSetForOrderingBInternalId = intrusionSetB.data.intrusionSetAdd.id;
  });
  it('should intrusion set loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: intrusionSetInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.intrusionSet).not.toBeNull();
    expect(queryResult.data.intrusionSet.id).toEqual(intrusionSetInternalId);
    expect(queryResult.data.intrusionSet.x_opencti_score).toEqual(40);
    expect(queryResult.data.intrusionSet.toStix.length).toBeGreaterThan(5);
  });
  it('should intrusion set loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: intrusionSetStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.intrusionSet).not.toBeNull();
    expect(queryResult.data.intrusionSet.id).toEqual(intrusionSetInternalId);
  });
  it('should list intrusion sets', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 2 } });
    expect(queryResult.data.intrusionSets.edges.length).toEqual(2);
  });
  it('should update intrusion set', async () => {
    const UPDATE_QUERY = gql`
      mutation IntrusionSetEdit($id: ID!, $input: [EditInput]!) {
        intrusionSetEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
            x_opencti_score
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: intrusionSetInternalId, input: { key: 'name', value: ['Intrusion set - test'] } },
    });
    expect(queryResult.data.intrusionSetEdit.fieldPatch.name).toEqual('Intrusion set - test');
  });
  it('should update intrusion set score using field patch', async () => {
    const UPDATE_QUERY = gql`
      mutation IntrusionSetEdit($id: ID!, $input: [EditInput]!) {
        intrusionSetEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            x_opencti_score
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: {
        id: intrusionSetInternalId,
        input: { key: 'x_opencti_score', value: '55' },
      },
    });
    expect(queryResult.data.intrusionSetEdit.fieldPatch.x_opencti_score).toEqual(55);

    const readResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: intrusionSetInternalId } });
    expect(readResult.data.intrusionSet.x_opencti_score).toEqual(55);
  });
  it('should list intrusion sets ordered by score', async () => {
    const queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        orderBy: 'x_opencti_score',
        orderMode: 'desc',
        search: 'Intrusion set score test',
      },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.intrusionSets.edges.length).toBeGreaterThanOrEqual(2);
    expect(queryResult.data.intrusionSets.edges[0].node.x_opencti_score).toEqual(80);
    expect(queryResult.data.intrusionSets.edges[1].node.x_opencti_score).toEqual(10);
  });
  it('should filter intrusion sets by score', async () => {
    const scoreFilter = {
      mode: 'and',
      filters: [{ key: ['x_opencti_score'], values: ['10'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    };
    const queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: scoreFilter,
        search: 'Intrusion set score test',
      },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.intrusionSets.edges.length).toEqual(1);
    expect(queryResult.data.intrusionSets.edges[0].node.id).toEqual(intrusionSetForOrderingAInternalId);
    expect(queryResult.data.intrusionSets.edges[0].node.x_opencti_score).toEqual(10);
  });
  it('should context patch intrusion set', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation IntrusionSetEdit($id: ID!, $input: EditContext) {
        intrusionSetEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: intrusionSetInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.intrusionSetEdit.contextPatch.id).toEqual(intrusionSetInternalId);
  });
  it('should context clean intrusion set', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation IntrusionSetEdit($id: ID!) {
        intrusionSetEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: intrusionSetInternalId },
    });
    expect(queryResult.data.intrusionSetEdit.contextClean.id).toEqual(intrusionSetInternalId);
  });
  it('should add relation in intrusion set', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation IntrusionSetEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
        intrusionSetEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on IntrusionSet {
                objectMarking {
                  id
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
        id: intrusionSetInternalId,
        input: {
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.intrusionSetEdit.relationAdd.from.objectMarking.length).toEqual(1);
  });
  it('should delete relation in intrusion set', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation IntrusionSetEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        intrusionSetEdit(id: $id) {
          relationDelete(toId: $toId, relationship_type: $relationship_type) {
            id
            objectMarking {
              id
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: intrusionSetInternalId,
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.intrusionSetEdit.relationDelete.objectMarking.length).toEqual(0);
  });
  it('should intrusion set deleted', async () => {
    const DELETE_QUERY = gql`
      mutation intrusionSetDelete($id: ID!) {
        intrusionSetEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the intrusion set
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: intrusionSetInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: intrusionSetStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.intrusionSet).toBeNull();
  });
  it('should cleanup intrusion sets used for score ordering and filtering', async () => {
    const DELETE_QUERY = gql`
      mutation intrusionSetDelete($id: ID!) {
        intrusionSetEdit(id: $id) {
          delete
        }
      }
    `;

    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: intrusionSetForOrderingAInternalId },
    });
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: intrusionSetForOrderingBInternalId },
    });

    const queryResultA = await queryAsAdmin({ query: READ_QUERY, variables: { id: intrusionSetForOrderingAStixId } });
    const queryResultB = await queryAsAdmin({ query: READ_QUERY, variables: { id: intrusionSetForOrderingBStixId } });
    expect(queryResultA.data.intrusionSet).toBeNull();
    expect(queryResultB.data.intrusionSet).toBeNull();
  });
});
