import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query threatActors(
    $first: Int
    $after: ID
    $orderBy: ThreatActorsOrdering
    $orderMode: OrderingMode
    $filters: [ThreatActorsFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    threatActors(
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
  query threatActor($id: String!) {
    threatActor(id: $id) {
      id
      name
      description
      toStix
    }
  }
`;

describe('Threat actor resolver standard behavior', () => {
  let threatActorInternalId;
  const threatActorStixId = 'threat-actor--16978493-d5fb-4b28-a39a-eca332f53189';
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
        stix_id: threatActorStixId,
        description: 'Threat actor description',
      },
    };
    const threatActor = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: THREAT_ACTOR_TO_CREATE,
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
    expect(queryResult.data.threatActor.toStix.length).toBeGreaterThan(5);
  });
  it('should threat actor loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: threatActorStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.threatActor).not.toBeNull();
    expect(queryResult.data.threatActor.id).toEqual(threatActorInternalId);
  });
  it('should list threat actors', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 1 } });
    expect(queryResult.data.threatActors.edges.length).toEqual(1);
  });
  it('should update threat actor', async () => {
    const UPDATE_QUERY = gql`
      mutation ThreatActorEdit($id: ID!, $input: [EditInput]!) {
        threatActorEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: threatActorInternalId, input: { key: 'name', value: ['Threat actor - test'] } },
    });
    expect(queryResult.data.threatActorEdit.fieldPatch.name).toEqual('Threat actor - test');
  });
  it('should context patch threat actor', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation ThreatActorEdit($id: ID!, $input: EditContext) {
        threatActorEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: threatActorInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.threatActorEdit.contextPatch.id).toEqual(threatActorInternalId);
  });
  it('should context clean threat actor', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation ThreatActorEdit($id: ID!) {
        threatActorEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: threatActorInternalId },
    });
    expect(queryResult.data.threatActorEdit.contextClean.id).toEqual(threatActorInternalId);
  });
  it('should add relation in threat actor', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation ThreatActorEdit($id: ID!, $input: StixMetaRelationshipAddInput!) {
        threatActorEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on ThreatActor {
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
        id: threatActorInternalId,
        input: {
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.threatActorEdit.relationAdd.from.objectMarking.edges.length).toEqual(1);
  });
  it('should delete relation in threat actor', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation ThreatActorEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        threatActorEdit(id: $id) {
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
        id: threatActorInternalId,
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.threatActorEdit.relationDelete.objectMarking.edges.length).toEqual(0);
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
      variables: { id: threatActorInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: threatActorStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.threatActor).toBeNull();
  });
});
