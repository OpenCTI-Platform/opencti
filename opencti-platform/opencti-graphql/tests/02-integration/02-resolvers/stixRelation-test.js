import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const READ_QUERY = gql`
  query StixRelation($id: String!) {
    stixRelation(id: $id) {
      id
      description
      toStix
      editContext {
        focusOn
        name
      }
    }
  }
`;

describe('StixRelation resolver standard behavior', () => {
  let stixRelationInternalId;
  let stixRelationMarkingDefinitionRelationId;
  const stixRelationStixId = 'relationship--3d8bb13a-6cad-493d-933a-ae4ff5a203ca';
  it('should stixRelation created', async () => {
    const CREATE_QUERY = gql`
      mutation StixDomainRelationAdd($input: StixRelationAddInput) {
        stixRelationAdd(input: $input) {
          id
          description
        }
      }
    `;
    // Create the stixRelation
    const STIX_RELATION_TO_CREATE = {
      input: {
        fromId: 'fab6fa99-b07f-4278-86b4-b674edf60877',
        fromRole: 'user',
        toId: 'dcbadcd2-9359-48ac-8b86-88e38a092a2b',
        toRole: 'usage',
        relationship_type: 'uses',
        stix_id_key: stixRelationStixId,
        description: 'StixRelation description',
      },
    };
    const stixRelation = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: STIX_RELATION_TO_CREATE,
    });
    expect(stixRelation).not.toBeNull();
    expect(stixRelation.data.stixRelationAdd).not.toBeNull();
    expect(stixRelation.data.stixRelationAdd.description).toEqual('StixRelation description');
    stixRelationInternalId = stixRelation.data.stixRelationAdd.id;
  });
  it('should stixRelation loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixRelationInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixRelation).not.toBeNull();
    expect(queryResult.data.stixRelation.id).toEqual(stixRelationInternalId);
    expect(queryResult.data.stixRelation.toStix.length).toBeGreaterThan(5);
  });
  it('should stixRelation loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixRelationStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixRelation).not.toBeNull();
    expect(queryResult.data.stixRelation.id).toEqual(stixRelationInternalId);
  });
  it('should stixRelation number to be accurate', async () => {
    const NUMBER_QUERY = gql`
      query StixRelationsNumber($type: String) {
        stixRelationsNumber(type: $type) {
          total
        }
      }
    `;
    const queryResult = await queryAsAdmin({ query: NUMBER_QUERY, variables: { type: 'stix_relation' } });
    expect(queryResult.data.stixRelationsNumber.total).toEqual(22);
  });
  it('should update stixRelation', async () => {
    const UPDATE_QUERY = gql`
      mutation StixRelationEdit($id: ID!, $input: EditInput!) {
        stixRelationEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: stixRelationInternalId, input: { key: 'name', value: ['StixRelation - test'] } },
    });
    expect(queryResult.data.stixRelationEdit.fieldPatch.name).toEqual('StixRelation - test');
  });
  it('should context patch stixRelation', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation StixRelationEdit($id: ID!, $input: EditContext) {
        stixRelationEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: stixRelationInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.stixRelationEdit.contextPatch.id).toEqual(stixRelationInternalId);
  });
  it('should stixRelation editContext to be accurate', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixRelationInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixRelation).not.toBeNull();
    expect(queryResult.data.stixRelation.id).toEqual(stixRelationInternalId);
    expect(queryResult.data.stixRelation.editContext[0].focusOn).toEqual('description');
  });
  it('should context clean stixRelation', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation StixRelationEdit($id: ID!) {
        stixRelationEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: stixRelationInternalId },
    });
    expect(queryResult.data.stixRelationEdit.contextClean.id).toEqual(stixRelationInternalId);
  });
  it('should add relation in stixRelation', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation StixRelationEdit($id: ID!, $input: RelationAddInput!) {
        stixRelationEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on StixRelation {
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
        id: stixRelationInternalId,
        input: {
          fromRole: 'so',
          toRole: 'marking',
          toId: '43f586bc-bcbc-43d1-ab46-43e5ab1a2c46',
          through: 'object_marking_refs',
        },
      },
    });
    expect(queryResult.data.stixRelationEdit.relationAdd.from.markingDefinitions.edges.length).toEqual(1);
    stixRelationMarkingDefinitionRelationId =
      queryResult.data.stixRelationEdit.relationAdd.from.markingDefinitions.edges[0].relation.id;
  });
  it('should delete relation in stixRelation', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation StixRelationEdit($id: ID!, $relationId: ID!) {
        stixRelationEdit(id: $id) {
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
        id: stixRelationInternalId,
        relationId: stixRelationMarkingDefinitionRelationId,
      },
    });
    expect(queryResult.data.stixRelationEdit.relationDelete.markingDefinitions.edges.length).toEqual(0);
  });
  it('should stixRelation deleted', async () => {
    const DELETE_QUERY = gql`
      mutation stixRelationDelete($id: ID!) {
        stixRelationEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the stixRelation
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: stixRelationInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixRelationStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixRelation).toBeNull();
    // TODO Verify is no relations are linked to the deleted entity
  });
});
