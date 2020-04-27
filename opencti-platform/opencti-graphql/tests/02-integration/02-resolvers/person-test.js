import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query persons(
    $first: Int
    $after: ID
    $orderBy: UsersOrdering
    $orderMode: OrderingMode
    $filters: [UsersFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    persons(
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
  query person($id: String!) {
    person(id: $id) {
      id
      name
      description
      organizations {
        edges {
          node {
            id
          }
        }
      }
      toStix
    }
  }
`;

describe('Person resolver standard behavior', () => {
  let personInternalId;
  let personMarkingDefinitionRelationId;
  const personStixId = 'identity--a7da7a84-73a0-4f1b-b0c0-35ed56418e82';
  it('should person created', async () => {
    const CREATE_QUERY = gql`
      mutation PersonAdd($input: PersonAddInput) {
        personAdd(input: $input) {
          id
          name
          description
        }
      }
    `;
    // Create the person
    const PERSON_TO_CREATE = {
      input: {
        name: 'Person',
        stix_id_key: personStixId,
        description: 'Person description',
      },
    };
    const person = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: PERSON_TO_CREATE,
    });
    expect(person).not.toBeNull();
    expect(person.data.personAdd).not.toBeNull();
    expect(person.data.personAdd.name).toEqual('Person');
    personInternalId = person.data.personAdd.id;
  });
  it('should person loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: personInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.person).not.toBeNull();
    expect(queryResult.data.person.id).toEqual(personInternalId);
    expect(queryResult.data.person.toStix.length).toBeGreaterThan(5);
  });
  it('should person loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: personStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.person).not.toBeNull();
    expect(queryResult.data.person.id).toEqual(personInternalId);
  });
  it('should person organizations to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: '639331ab-ae8d-4c69-9037-3b7e5c67e5c5' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.person).not.toBeNull();
    expect(queryResult.data.person.organizations.edges.length).toEqual(1);
    expect(queryResult.data.person.organizations.edges[0].node.id).toEqual('9ca2ff43-b765-4f13-a213-10664a2ae8fc');
  });
  it('should list persons', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.persons.edges.length).toEqual(3);
  });
  it('should update person', async () => {
    const UPDATE_QUERY = gql`
      mutation PersonEdit($id: ID!, $input: EditInput!) {
        personEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: personInternalId, input: { key: 'name', value: ['Person - test'] } },
    });
    expect(queryResult.data.personEdit.fieldPatch.name).toEqual('Person - test');
  });
  it('should context patch person', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation PersonEdit($id: ID!, $input: EditContext) {
        personEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: personInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.personEdit.contextPatch.id).toEqual(personInternalId);
  });
  it('should context clean person', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation PersonEdit($id: ID!) {
        personEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: personInternalId },
    });
    expect(queryResult.data.personEdit.contextClean.id).toEqual(personInternalId);
  });
  it('should add relation in person', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation PersonEdit($id: ID!, $input: RelationAddInput!) {
        personEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on User {
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
        id: personInternalId,
        input: {
          fromRole: 'so',
          toRole: 'marking',
          toId: '43f586bc-bcbc-43d1-ab46-43e5ab1a2c46',
          through: 'object_marking_refs',
        },
      },
    });
    expect(queryResult.data.personEdit.relationAdd.from.markingDefinitions.edges.length).toEqual(1);
    personMarkingDefinitionRelationId =
      queryResult.data.personEdit.relationAdd.from.markingDefinitions.edges[0].relation.id;
  });
  it('should delete relation in person', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation PersonEdit($id: ID!, $relationId: ID!) {
        personEdit(id: $id) {
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
        id: personInternalId,
        relationId: personMarkingDefinitionRelationId,
      },
    });
    expect(queryResult.data.personEdit.relationDelete.markingDefinitions.edges.length).toEqual(0);
  });
  it('should person deleted', async () => {
    const DELETE_QUERY = gql`
      mutation personDelete($id: ID!) {
        personEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the person
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: personInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: personStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.person).toBeNull();
  });
});
