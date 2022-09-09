import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query intrusionSets(
    $first: Int
    $after: ID
    $orderBy: IntrusionSetsOrdering
    $orderMode: OrderingMode
    $filters: [IntrusionSetsFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    intrusionSets(
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
  query intrusionSet($id: String!) {
    intrusionSet(id: $id) {
      id
      standard_id
      name
      description
      toStix
    }
  }
`;

describe('Intrusion set resolver standard behavior', () => {
  let intrusionSetInternalId;
  const intrusionSetStixId = 'intrusion-set--952ec932-a8c8-4050-9662-f0771ed7c477';
  it('should intrusion set created', async () => {
    const CREATE_QUERY = gql`
      mutation IntrusionSetAdd($input: IntrusionSetAddInput) {
        intrusionSetAdd(input: $input) {
          id
          name
          description
        }
      }
    `;
    // Create the intrusion set
    const INTRUSION_SET_TO_CREATE = {
      input: {
        name: 'Intrusion set',
        stix_id: intrusionSetStixId,
        description: 'Intrusion set description',
      },
    };
    const intrusionSet = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: INTRUSION_SET_TO_CREATE,
    });
    expect(intrusionSet).not.toBeNull();
    expect(intrusionSet.data.intrusionSetAdd).not.toBeNull();
    expect(intrusionSet.data.intrusionSetAdd.name).toEqual('Intrusion set');
    intrusionSetInternalId = intrusionSet.data.intrusionSetAdd.id;
  });
  it('should intrusion set loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: intrusionSetInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.intrusionSet).not.toBeNull();
    expect(queryResult.data.intrusionSet.id).toEqual(intrusionSetInternalId);
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
      mutation IntrusionSetEdit($id: ID!, $input: StixMetaRelationshipAddInput!) {
        intrusionSetEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on IntrusionSet {
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
    expect(queryResult.data.intrusionSetEdit.relationAdd.from.objectMarking.edges.length).toEqual(1);
  });
  it('should delete relation in intrusion set', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation IntrusionSetEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        intrusionSetEdit(id: $id) {
          relationDelete(toId: $toId, relationship_type: $relationship_type) {
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
    expect(queryResult.data.intrusionSetEdit.relationDelete.objectMarking.edges.length).toEqual(0);
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
});
