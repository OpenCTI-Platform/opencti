import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const READ_QUERY = gql`
  query StixSighting($id: String!) {
    stixSighting(id: $id) {
      id
      description
      toStix
    }
  }
`;

describe('StixSighting resolver standard behavior', () => {
  let stixSightingInternalId;
  const stixSightingStixId = 'sighting--87ca3780-e278-4f52-8599-e80ff72dbf2d';
  it('should stixSighting created', async () => {
    const CREATE_QUERY = gql`
      mutation StixDomainRelationAdd($input: StixSightingAddInput) {
        stixSightingAdd(input: $input) {
          id
          description
        }
      }
    `;
    // Create the stixSighting
    const STIX_SIGHTING_TO_CREATE = {
      input: {
        fromId: 'e7652cb6-777a-4220-9b64-0543ef36d467',
        toId: 'd1881166-f431-4335-bfed-b1c647e59f89',
        stix_id_key: stixSightingStixId,
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
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixSightingStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixSighting).toBeNull();
    // TODO Verify is no relations are linked to the deleted entity
  });
});
