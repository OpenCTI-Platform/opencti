import gql from 'graphql-tag';
import { ADMIN_USER, queryAsAdmin } from '../../utils/testQuery';
import { elLoadById } from '../../../src/database/engine';

const READ_QUERY = gql`
    query StixCoreRelationship($id: String!) {
        stixCoreRelationship(id: $id) {
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

const stixCoreRelationshipStixId = 'relationship--3d8bb13a-6cad-493d-933a-ae4ff5a203ca';
describe('StixCoreRelationship resolver standard behavior', () => {
  let stixCoreRelationshipInternalId;
  it('should stixCoreRelationship created', async () => {
    const CREATE_QUERY = gql`
        mutation StixDomainRelationAdd($input: StixCoreRelationshipAddInput) {
            stixCoreRelationshipAdd(input: $input) {
                id
                description
            }
        }
    `;
    // Create the stixCoreRelationship
    const STIX_RELATION_TO_CREATE = {
      input: {
        stix_id: stixCoreRelationshipStixId,
        fromId: 'campaign--92d46985-17a6-4610-8be8-cc70c82ed214',
        toId: 'attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17',
        relationship_type: 'uses',
        description: 'StixCoreRelationship description',
      },
    };
    const stixCoreRelationship = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: STIX_RELATION_TO_CREATE,
    });
    expect(stixCoreRelationship).not.toBeNull();
    expect(stixCoreRelationship.data.stixCoreRelationshipAdd).not.toBeNull();
    expect(stixCoreRelationship.data.stixCoreRelationshipAdd.description).toEqual('StixCoreRelationship description');
    stixCoreRelationshipInternalId = stixCoreRelationship.data.stixCoreRelationshipAdd.id;
  });
  it('should stixCoreRelationship loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixCoreRelationshipInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixCoreRelationship).not.toBeNull();
    expect(queryResult.data.stixCoreRelationship.id).toEqual(stixCoreRelationshipInternalId);
    expect(queryResult.data.stixCoreRelationship.toStix.length).toBeGreaterThan(5);
  });
  it('should stixCoreRelationship loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixCoreRelationshipStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixCoreRelationship).not.toBeNull();
    expect(queryResult.data.stixCoreRelationship.id).toEqual(stixCoreRelationshipInternalId);
  });
  it('should stixCoreRelationship number to be accurate', async () => {
    const campaign = await elLoadById(ADMIN_USER, 'campaign--92d46985-17a6-4610-8be8-cc70c82ed214');
    const NUMBER_QUERY = gql`
        query StixCoreRelationshipsNumber($type: String, $fromId: StixRef) {
            stixCoreRelationshipsNumber(type: $type, fromId: $fromId) {
                total
            }
        }
    `;
    const queryResult = await queryAsAdmin({
      query: NUMBER_QUERY,
      variables: { type: 'uses', fromId: campaign.internal_id },
    });
    expect(queryResult.data.stixCoreRelationshipsNumber.total).toEqual(1);
    const queryResult2 = await queryAsAdmin({ query: NUMBER_QUERY, variables: { type: 'stix_relation' } });
    expect(queryResult2.data.stixCoreRelationshipsNumber.total).toEqual(22);
  });
  it('should update stixCoreRelationship', async () => {
    const UPDATE_QUERY = gql`
        mutation StixCoreRelationshipEdit($id: ID!, $input: [EditInput]!) {
            stixCoreRelationshipEdit(id: $id) {
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
        id: stixCoreRelationshipInternalId,
        input: { key: 'description', value: ['StixCoreRelationship - test'] },
      },
    });
    expect(queryResult.data.stixCoreRelationshipEdit.fieldPatch.description).toEqual('StixCoreRelationship - test');
  });
  it('should context patch stixCoreRelationship', async () => {
    const CONTEXT_PATCH_QUERY = gql`
        mutation StixCoreRelationshipEdit($id: ID!, $input: EditContext) {
            stixCoreRelationshipEdit(id: $id) {
                contextPatch(input: $input) {
                    id
                }
            }
        }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: stixCoreRelationshipInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.stixCoreRelationshipEdit.contextPatch.id).toEqual(stixCoreRelationshipInternalId);
  });
  it('should stixCoreRelationship editContext to be accurate', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixCoreRelationshipInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixCoreRelationship).not.toBeNull();
    expect(queryResult.data.stixCoreRelationship.id).toEqual(stixCoreRelationshipInternalId);
    expect(queryResult.data.stixCoreRelationship.editContext[0].focusOn).toEqual('description');
  });
  it('should context clean stixCoreRelationship', async () => {
    const CONTEXT_PATCH_QUERY = gql`
        mutation StixCoreRelationshipEdit($id: ID!) {
            stixCoreRelationshipEdit(id: $id) {
                contextClean {
                    id
                }
            }
        }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: stixCoreRelationshipInternalId },
    });
    expect(queryResult.data.stixCoreRelationshipEdit.contextClean.id).toEqual(stixCoreRelationshipInternalId);
  });
  it('should add relation in stixCoreRelationship', async () => {
    const RELATION_ADD_QUERY = gql`
        mutation StixCoreRelationshipEdit($id: ID!, $input: StixMetaRelationshipAddInput!) {
            stixCoreRelationshipEdit(id: $id) {
                relationAdd(input: $input) {
                    id
                    from {
                        ... on StixCoreRelationship {
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
        id: stixCoreRelationshipStixId,
        input: {
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.stixCoreRelationshipEdit.relationAdd.from.objectMarking.edges.length).toEqual(1);
  });
  it('should delete relation in stixCoreRelationship', async () => {
    const RELATION_DELETE_QUERY = gql`
        mutation StixCoreRelationshipEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
            stixCoreRelationshipEdit(id: $id) {
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
        id: stixCoreRelationshipStixId,
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.stixCoreRelationshipEdit.relationDelete.objectMarking.edges.length).toEqual(0);
  });
  it('should stixCoreRelationship deleted', async () => {
    const DELETE_QUERY = gql`
        mutation stixCoreRelationshipDelete($id: ID!) {
            stixCoreRelationshipEdit(id: $id) {
                delete
            }
        }
    `;
    // Delete the stixCoreRelationship
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: stixCoreRelationshipInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixCoreRelationshipStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixCoreRelationship).toBeNull();
    // TODO Verify is no relations are linked to the deleted entity
  });
});
