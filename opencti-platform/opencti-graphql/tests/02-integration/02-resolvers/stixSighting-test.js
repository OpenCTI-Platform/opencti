import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const READ_QUERY = gql`
  query StixSighting($id: String!) {
    stixSighting(id: $id) {
      id
      stix_id_key
      description
      toStix
      editContext {
        focusOn
        name
      }
    }
  }
`;

describe('StixSighting resolver standard behavior', () => {
  let stixSightingInternalId;
  let stixSightingStixId;
  let stixSightingMarkingDefinitionRelationId;
  it('should stixSighting created', async () => {
    const CREATE_QUERY = gql`
      mutation StixDomainRelationAdd($input: StixSightingAddInput) {
        stixSightingAdd(input: $input) {
          id
          stix_id_key
          description
        }
      }
    `;
    // Create the stixSighting
    const STIX_SIGHTING_TO_CREATE = {
      input: {
        fromId: 'e7652cb6-777a-4220-9b64-0543ef36d467',
        toId: 'd1881166-f431-4335-bfed-b1c647e59f89',
        description: 'StixSighting description',
        number: 1,
        confidence: 15,
        negative: false,
      },
    };
    const stixDomainEntity = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: STIX_SIGHTING_TO_CREATE,
    });
    expect(stixDomainEntity).not.toBeNull();
    expect(stixDomainEntity.data.stixSightingAdd).not.toBeNull();
    expect(stixDomainEntity.data.stixSightingAdd.description).toEqual('StixSighting description');
    stixSightingInternalId = stixDomainEntity.data.stixSightingAdd.id;
    stixSightingStixId = stixDomainEntity.data.stixSightingAdd.stix_id_key;
  });
  it('should stixSighting loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixSightingInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixSighting).not.toBeNull();
    expect(queryResult.data.stixSighting.id).toEqual(stixSightingInternalId);
    expect(queryResult.data.stixSighting.toStix.length).toBeGreaterThan(5);
  });
  it('should stixSighting loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixSightingStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixSighting).not.toBeNull();
    expect(queryResult.data.stixSighting.id).toEqual(stixSightingInternalId);
  });
  it('should stixSighting number to be accurate', async () => {
    const NUMBER_QUERY = gql`
      query StixSightingsNumber {
        stixSightingsNumber {
          total
        }
      }
    `;
    const queryResult = await queryAsAdmin({ query: NUMBER_QUERY, variables: { type: 'uses' } });
    expect(queryResult.data.stixSightingsNumber.total).toEqual(6);
  });
  it('should update stixSighting', async () => {
    const UPDATE_QUERY = gql`
      mutation StixSightingEdit($id: ID!, $input: EditInput!) {
        stixSightingEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: stixSightingInternalId, input: { key: 'name', value: ['StixSighting - test'] } },
    });
    expect(queryResult.data.stixSightingEdit.fieldPatch.name).toEqual('StixSighting - test');
  });
  it('should context patch stixSighting', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation StixSightingEdit($id: ID!, $input: EditContext) {
        stixSightingEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: stixSightingInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.stixSightingEdit.contextPatch.id).toEqual(stixSightingInternalId);
  });
  it('should stixSighting editContext to be accurate', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixSightingInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixSighting).not.toBeNull();
    expect(queryResult.data.stixSighting.id).toEqual(stixSightingInternalId);
    expect(queryResult.data.stixSighting.editContext[0].focusOn).toEqual('description');
  });
  it('should context clean stixSighting', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation StixSightingEdit($id: ID!) {
        stixSightingEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: stixSightingInternalId },
    });
    expect(queryResult.data.stixSightingEdit.contextClean.id).toEqual(stixSightingInternalId);
  });
  it('should add relation in stixSighting', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation StixSightingEdit($id: ID!, $input: RelationAddInput!) {
        stixSightingEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on StixSighting {
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
        id: stixSightingInternalId,
        input: {
          toId: '43f586bc-bcbc-43d1-ab46-43e5ab1a2c46',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.stixSightingEdit.relationAdd.from.objectMarking.edges.length).toEqual(1);
    stixSightingMarkingDefinitionRelationId =
      queryResult.data.stixSightingEdit.relationAdd.from.objectMarking.edges[0].relation.id;
  });
  it('should delete relation in stixSighting', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation StixSightingEdit($id: ID!, $relationId: ID!) {
        stixSightingEdit(id: $id) {
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
        id: stixSightingInternalId,
        relationId: stixSightingMarkingDefinitionRelationId,
      },
    });
    expect(queryResult.data.stixSightingEdit.relationDelete.objectMarking.edges.length).toEqual(0);
  });
  it('should stixSighting deleted', async () => {
    const DELETE_QUERY = gql`
      mutation stixSightingDelete($id: ID!) {
        stixSightingEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the stixDomainEntity
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: stixSightingInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixSightingInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixSighting).toBeNull();
    // TODO Verify is no relations are linked to the deleted entity
  });
});
