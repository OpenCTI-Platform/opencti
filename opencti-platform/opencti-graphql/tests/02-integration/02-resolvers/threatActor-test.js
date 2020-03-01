import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

// region queries
const CREATE_QUERY = gql`
  mutation ThreatActorAdd($input: ThreatActorAddInput) {
    threatActorAdd(input: $input) {
      id
      name
      description
    }
  }
`;

const READ_QUERY = gql`
  query threatActor($id: String!) {
    threatActor(id: $id) {
      id
      name
      description
    }
  }
`;

const DELETE_QUERY = gql`
  mutation threatActorDelete($id: ID!) {
    threatActorEdit(id: $id) {
      delete
    }
  }
`;
// endregion

describe('Threat actor resolver standard behavior', () => {
  it('should threat actor created', async () => {
    // Create the threat actor
    const stixId = 'threat-actor--667719d8-2e97-4e9f-914c-52e15870edc5';
    const THREAT_ACTOR_TO_CREATE = {
      input: {
        name: 'Threat actor',
        stix_id_key: stixId,
        description: 'Threat actor description'
      }
    };
    const restCreation = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: THREAT_ACTOR_TO_CREATE
    });
    expect(restCreation).not.toBeNull();
    expect(restCreation.data.threatActorAdd).not.toBeNull();
    expect(restCreation.data.threatActorAdd.name).toEqual('Threat actor');
    const threatActorId = restCreation.data.threatActorAdd.id;
    // Load the threat actor by Id
    let resSelect = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: threatActorId }
    });
    expect(resSelect).not.toBeNull();
    expect(resSelect.data.threatActor).not.toBeNull();
    expect(resSelect.data.threatActor.id).toEqual(threatActorId);
    // Load the thread actor by stixId
    resSelect = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: stixId }
    });
    expect(resSelect).not.toBeNull();
    expect(resSelect.data.threatActor).not.toBeNull();
    expect(resSelect.data.threatActor.id).toEqual(threatActorId);
    // Delete the threat actor
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: threatActorId }
    });
  });
});
