import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const READ_QUERY = gql`
  query stixSightingRelationship($id: String!) {
    stixSightingRelationship(id: $id) {
      id
      standard_id
      description
      toStix
      editContext {
        focusOn
        name
      }
    }
  }
`;

describe('stixSightingRelationship resolver standard behavior', () => {
  let stixSightingRelationshipInternalId;
  let stixSightingRelationshipStandardId;
  it('should stixSightingRelationship created', async () => {
    const CREATE_QUERY = gql`
      mutation StixDomainRelationAdd($input: StixSightingRelationshipAddInput!) {
        stixSightingRelationshipAdd(input: $input) {
          id
          standard_id
          description
        }
      }
    `;
    // Create the stixSightingRelationship
    const STIX_SIGHTING_TO_CREATE = {
      input: {
        fromId: 'indicator--10e9a46e-7edb-496b-a167-e27ea3ed0079',
        toId: 'location--c3794ffd-0e71-4670-aa4d-978b4cbdc72c',
        description: 'stixSightingRelationship description',
        attribute_count: 1,
        confidence: 15,
        x_opencti_negative: false,
      },
    };
    const stixDomainEntity = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: STIX_SIGHTING_TO_CREATE,
    });
    expect(stixDomainEntity).not.toBeNull();
    expect(stixDomainEntity.data.stixSightingRelationshipAdd).not.toBeNull();
    expect(stixDomainEntity.data.stixSightingRelationshipAdd.description).toEqual(
      'stixSightingRelationship description'
    );
    stixSightingRelationshipInternalId = stixDomainEntity.data.stixSightingRelationshipAdd.id;
    stixSightingRelationshipStandardId = stixDomainEntity.data.stixSightingRelationshipAdd.standard_id;
  });
  it('should stixSightingRelationship loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: stixSightingRelationshipInternalId },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixSightingRelationship).not.toBeNull();
    expect(queryResult.data.stixSightingRelationship.id).toEqual(stixSightingRelationshipInternalId);
    expect(queryResult.data.stixSightingRelationship.toStix.length).toBeGreaterThan(5);
  });
  it('should stixSightingRelationship loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: stixSightingRelationshipStandardId },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixSightingRelationship).not.toBeNull();
    expect(queryResult.data.stixSightingRelationship.id).toEqual(stixSightingRelationshipInternalId);
  });
  it('should stixSightingRelationship number to be accurate', async () => {
    const NUMBER_QUERY = gql`
      query stixSightingRelationshipsNumber {
        stixSightingRelationshipsNumber {
          total
        }
      }
    `;
    const queryResult = await queryAsAdmin({ query: NUMBER_QUERY });
    expect(queryResult.data.stixSightingRelationshipsNumber.total).toEqual(3);
  });
  it('should update stixSightingRelationship', async () => {
    const UPDATE_QUERY = gql`
      mutation stixSightingRelationshipEdit($id: ID!, $input: [EditInput]!) {
        stixSightingRelationshipEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            description
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: {
        id: stixSightingRelationshipInternalId,
        input: { key: 'description', value: ['stixSightingRelationship - test'] },
      },
    });
    expect(queryResult.data.stixSightingRelationshipEdit.fieldPatch.description).toEqual(
      'stixSightingRelationship - test'
    );
  });
  it('should context patch stixSightingRelationship', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation stixSightingRelationshipEdit($id: ID!, $input: EditContext) {
        stixSightingRelationshipEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: stixSightingRelationshipInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.stixSightingRelationshipEdit.contextPatch.id).toEqual(stixSightingRelationshipInternalId);
  });
  it('should stixSightingRelationship editContext to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: stixSightingRelationshipInternalId },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixSightingRelationship).not.toBeNull();
    expect(queryResult.data.stixSightingRelationship.id).toEqual(stixSightingRelationshipInternalId);
    expect(queryResult.data.stixSightingRelationship.editContext[0].focusOn).toEqual('description');
  });
  it('should context clean stixSightingRelationship', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation stixSightingRelationshipEdit($id: ID!) {
        stixSightingRelationshipEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: stixSightingRelationshipInternalId },
    });
    expect(queryResult.data.stixSightingRelationshipEdit.contextClean.id).toEqual(stixSightingRelationshipInternalId);
  });
  it('should add relation in stixSightingRelationship', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation stixSightingRelationshipEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
        stixSightingRelationshipEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on StixSightingRelationship {
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
        id: stixSightingRelationshipInternalId,
        input: {
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.stixSightingRelationshipEdit.relationAdd.from.objectMarking.edges.length).toEqual(1);
  });
  it('should delete relation in stixSightingRelationship', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation stixSightingRelationshipEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        stixSightingRelationshipEdit(id: $id) {
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
        id: stixSightingRelationshipInternalId,
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.stixSightingRelationshipEdit.relationDelete.objectMarking.edges.length).toEqual(0);
  });
  it('should add multiple relation in stixSightingRelationship', async () => {
    const RELATIONS_ADD_QUERY = gql`
      mutation stixSightingRelationshipEdit($id: ID!, $input: StixRefRelationshipsAddInput!) {
        stixSightingRelationshipEdit(id: $id) {
          relationsAdd(input: $input) {
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
      query: RELATIONS_ADD_QUERY,
      variables: {
        id: stixSightingRelationshipInternalId,
        input: {
          toIds: ['marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27'],
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.stixSightingRelationshipEdit.relationsAdd.objectMarking.edges.length).toEqual(1);
  });
  it('should stixSightingRelationship deleted', async () => {
    const DELETE_QUERY = gql`
      mutation stixSightingRelationshipDelete($id: ID!) {
        stixSightingRelationshipEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the stixDomainEntity
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: stixSightingRelationshipInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: stixSightingRelationshipInternalId },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixSightingRelationship).toBeNull();
    // TODO Verify is no relations are linked to the deleted entity
  });
});
