import gql from 'graphql-tag';
import { ADMIN_USER, queryAsAdmin } from '../../utils/testQuery';
import { elLoadById } from '../../../src/database/engine';

const LIST_QUERY = gql`
  query individuals(
    $first: Int
    $after: ID
    $orderBy: IndividualsOrdering
    $orderMode: OrderingMode
    $filters: [IndividualsFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    individuals(
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
  query individual($id: String!) {
    individual(id: $id) {
      id
      standard_id
      name
      description
      organizations {
        edges {
          node {
            id
            standard_id
          }
        }
      }
      toStix
    }
  }
`;

describe('Individual resolver standard behavior', () => {
  let individualInternalId;
  const individualStixId = 'identity--a7da7a84-73a0-4f1b-b0c0-35ed56418e82';
  it('should individual created', async () => {
    const CREATE_QUERY = gql`
      mutation IndividualAdd($input: IndividualAddInput) {
        individualAdd(input: $input) {
          id
          name
          description
        }
      }
    `;
    // Create the individual
    const INDIVIDUAL_TO_CREATE = {
      input: {
        name: 'Individual',
        stix_id: individualStixId,
        description: 'Individual description',
      },
    };
    const individual = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: INDIVIDUAL_TO_CREATE,
    });
    expect(individual).not.toBeNull();
    expect(individual.data.individualAdd).not.toBeNull();
    expect(individual.data.individualAdd.name).toEqual('Individual');
    individualInternalId = individual.data.individualAdd.id;
  });
  it('should individual loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: individualInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.individual).not.toBeNull();
    expect(queryResult.data.individual.id).toEqual(individualInternalId);
    expect(queryResult.data.individual.toStix.length).toBeGreaterThan(5);
  });
  it('should individual loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: individualStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.individual).not.toBeNull();
    expect(queryResult.data.individual.id).toEqual(individualInternalId);
  });
  it('should individual organizations to be accurate', async () => {
    const individual = await elLoadById(ADMIN_USER, 'identity--d37acc64-4a6f-4dc2-879a-a4c138d0a27f');
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: individual.internal_id },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.individual).not.toBeNull();
    expect(queryResult.data.individual.organizations.edges.length).toEqual(1);
    expect(queryResult.data.individual.organizations.edges[0].node.standard_id).toEqual(
      'identity--732421a0-8471-52de-8d9f-18c8b260813c'
    );
  });
  it('should list individuals', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.individuals.edges.length).toEqual(2);
  });
  it('should update individual', async () => {
    const UPDATE_QUERY = gql`
      mutation IndividualEdit($id: ID!, $input: [EditInput]!) {
        individualEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: individualInternalId, input: { key: 'name', value: ['Individual - test'] } },
    });
    expect(queryResult.data.individualEdit.fieldPatch.name).toEqual('Individual - test');
  });
  it('should context patch individual', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation IndividualEdit($id: ID!, $input: EditContext) {
        individualEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: individualInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.individualEdit.contextPatch.id).toEqual(individualInternalId);
  });
  it('should context clean individual', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation IndividualEdit($id: ID!) {
        individualEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: individualInternalId },
    });
    expect(queryResult.data.individualEdit.contextClean.id).toEqual(individualInternalId);
  });
  it('should add relation in individual', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation IndividualEdit($id: ID!, $input: StixMetaRelationshipAddInput!) {
        individualEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on Individual {
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
        id: individualInternalId,
        input: {
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.individualEdit.relationAdd.from.objectMarking.edges.length).toEqual(1);
  });
  it('should delete relation in individual', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation IndividualEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        individualEdit(id: $id) {
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
        id: individualInternalId,
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.individualEdit.relationDelete.objectMarking.edges.length).toEqual(0);
  });
  it('should individual deleted', async () => {
    const DELETE_QUERY = gql`
      mutation individualDelete($id: ID!) {
        individualEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the individual
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: individualInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: individualStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.individual).toBeNull();
  });
});
