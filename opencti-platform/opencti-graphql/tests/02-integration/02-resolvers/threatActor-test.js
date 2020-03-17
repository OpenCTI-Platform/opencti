import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const READ_QUERY = gql`
  query threatActor($id: String!) {
    threatActor(id: $id) {
      id
      name
      description
    }
  }
`;

describe('Threat actor resolver standard behavior', () => {
  let threatActorInternalId;
  const threatActorStixId = 'threat-actor--667719d8-2e97-4e9f-914c-52e15870edc5';
  it('should threat actor created', async () => {
    const CREATE_QUERY = gql`
      mutation ThreatActorAdd($input: ThreatActorAddInput) {
        threatActorAdd(input: $input) {
          id
          name
          description
        }
      }
    `;
    // Create the threat actor
    const THREAT_ACTOR_TO_CREATE = {
      input: {
        name: 'Threat actor',
        stix_id_key: threatActorStixId,
        description: 'Threat actor description'
      }
    };
    const threatActor = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: THREAT_ACTOR_TO_CREATE
    });
    expect(threatActor).not.toBeNull();
    expect(threatActor.data.threatActorAdd).not.toBeNull();
    expect(threatActor.data.threatActorAdd.name).toEqual('Threat actor');
    threatActorInternalId = threatActor.data.threatActorAdd.id;
  });
  it('should threat actor loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: threatActorInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.threatActor).not.toBeNull();
    expect(queryResult.data.threatActor.id).toEqual(threatActorInternalId);
  });
  it('should threat actor loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: threatActorStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.threatActor).not.toBeNull();
    expect(queryResult.data.threatActor.id).toEqual(threatActorInternalId);
    // Delete the threat actor
  });
  it('should threat actor deleted', async () => {
    const DELETE_QUERY = gql`
      mutation threatActorDelete($id: ID!) {
        threatActorEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the threat actor
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: threatActorInternalId }
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: threatActorStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.threatActor).toBeNull();
  });
});
