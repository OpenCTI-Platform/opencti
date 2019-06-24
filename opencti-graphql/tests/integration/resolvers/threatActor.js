import { query } from '../integration-test';

// region queries
const CREATE_QUERY = `
    mutation ThreatActorAdd($input: ThreatActorAddInput) {
      threatActorAdd(input: $input) {
        id
        name
        description
      }
    }`;

const READ_QUERY = `
    query threatActor($id: String!) {
      threatActor(id: $id) {
        id
        name
        description
      }
    }`;
// endregion

describe('Threat actor resolver standard behavior', () => {
  it('should threat actor created', async () => {
    const THREAT_ACTOR_TO_CREATE = {
      input: {
        name: 'Threat actor',
        description: 'Threat actor description'
      }
    };
    const restCreation = await query({
      query: CREATE_QUERY,
      variables: THREAT_ACTOR_TO_CREATE
    });
    expect(restCreation).not.toBeNull();
    expect(restCreation.data.threatActorAdd).not.toBeNull();
    expect(restCreation.data.threatActorAdd.name).toEqual('Threat actor')
    const threatActorId = restCreation.data.threatActorAdd.id;

    const resSelect = await query({
      query: READ_QUERY,
      variables: { id: threatActorId }
    });
    expect(resSelect).not.toBeNull();
    expect(resSelect.data.threatActor).not.toBeNull();
    expect(resSelect.data.threatActor.id).toEqual(threatActorId);
  });
});
