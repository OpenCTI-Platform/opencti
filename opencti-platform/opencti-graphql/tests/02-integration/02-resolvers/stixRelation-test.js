import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const READ_QUERY = gql`
  query StixRelation($id: String!) {
    stixRelation(id: $id) {
      id
      description
      toStix
    }
  }
`;

describe('StixRelation resolver standard behavior', () => {
  let stixRelationInternalId;
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
    // Create the stixDomainEntity
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
    const stixDomainEntity = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: STIX_RELATION_TO_CREATE,
    });
    expect(stixDomainEntity).not.toBeNull();
    expect(stixDomainEntity.data.stixRelationAdd).not.toBeNull();
    expect(stixDomainEntity.data.stixRelationAdd.description).toEqual('StixRelation description');
    stixRelationInternalId = stixDomainEntity.data.stixRelationAdd.id;
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
  it('should stixDomainEntity deleted', async () => {
    const DELETE_QUERY = gql`
      mutation stixRelationDelete($id: ID!) {
        stixRelationEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the stixDomainEntity
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
