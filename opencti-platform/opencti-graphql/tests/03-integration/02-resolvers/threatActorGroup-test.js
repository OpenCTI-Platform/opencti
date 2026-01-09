import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query threatActorsGroup(
    $first: Int
    $after: ID
    $orderBy: ThreatActorsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    threatActorsGroup(
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      search: $search
    ) {
      edges {
        node {
          id
          name
          description
          objectAssignee {
            id
          }
          objectMarking {
            spec_version
          }
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query threatActorGroup($id: String!) {
    threatActorGroup(id: $id) {
      id
      name
      description
      objectAssignee {
        id
      }
      objectMarking {
        spec_version
      }
      toStix
    }
  }
`;

describe('Threat actor group resolver standard behavior', () => {
  let threatActorGroupInternalId;
  const threatActorsGroupStixId = 'threat-actor--16978493-d5fb-4b28-a39a-eca332f53189';
  it('should threat actor group created', async () => {
    const CREATE_QUERY = gql`
      mutation threatActorGroupAdd($input: ThreatActorGroupAddInput!) {
        threatActorGroupAdd(input: $input) {
          id
          name
          description
          objectAssignee {
            id
          }
          objectMarking {
            spec_version
          }
        }
      }
    `;
    // Create the threat actor group
    const THREAT_ACTOR_GROUP_TO_CREATE = {
      input: {
        name: 'Threat actor group',
        stix_id: threatActorsGroupStixId,
        description: 'Threat actor group description',
      },
    };
    const threatActorGroup = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: THREAT_ACTOR_GROUP_TO_CREATE,
    });
    expect(threatActorGroup).not.toBeNull();
    expect(threatActorGroup.data.threatActorGroupAdd).not.toBeNull();
    expect(threatActorGroup.data.threatActorGroupAdd.name).toEqual('Threat actor group');
    threatActorGroupInternalId = threatActorGroup.data.threatActorGroupAdd.id;
  });
  it('should threat actor group loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: threatActorGroupInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.threatActorGroup).not.toBeNull();
    expect(queryResult.data.threatActorGroup.id).toEqual(threatActorGroupInternalId);
    expect(queryResult.data.threatActorGroup.id).toEqual(threatActorGroupInternalId);
    expect(queryResult.data.threatActorGroup.toStix.length).toBeGreaterThan(5);
  });
  it('should threat actor group loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: threatActorsGroupStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.threatActorGroup).not.toBeNull();
    expect(queryResult.data.threatActorGroup.id).toEqual(threatActorGroupInternalId);
  });
  it('should list threat actors group', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 1 } });
    expect(queryResult.data.threatActorsGroup.edges.length).toEqual(1);
  });
  it('should update threat actor group', async () => {
    const UPDATE_QUERY = gql`
        mutation threatActorGroupEdit($id: ID!, $input: [EditInput]!) {
          threatActorGroupEdit(id: $id) {
            fieldPatch(input: $input) {
              id
              name
            }
          }
        }
      `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: threatActorGroupInternalId, input: { key: 'name', value: ['Threat actor group - test'] } },
    });
    expect(queryResult.data.threatActorGroupEdit.fieldPatch.name).toEqual('Threat actor group - test');
  });
  it('should context patch threat actor group', async () => {
    const CONTEXT_PATCH_QUERY = gql`
        mutation threatActorGroupEdit($id: ID!, $input: EditContext) {
          threatActorGroupEdit(id: $id) {
            contextPatch(input: $input) {
              id
            }
          }
        }
      `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: threatActorGroupInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.threatActorGroupEdit.contextPatch.id).toEqual(threatActorGroupInternalId);
  });
  it('should context clean threat actor group', async () => {
    const CONTEXT_PATCH_QUERY = gql`
        mutation threatActorGroupEdit($id: ID!) {
          threatActorGroupEdit(id: $id) {
            contextClean {
              id
            }
          }
        }
      `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: threatActorGroupInternalId },
    });
    expect(queryResult.data.threatActorGroupEdit.contextClean.id).toEqual(threatActorGroupInternalId);
  });
  it('should add relation in threat actor group', async () => {
    const RELATION_ADD_QUERY = gql`
        mutation threatActorGroupEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
          threatActorGroupEdit(id: $id) {
            relationAdd(input: $input) {
              id
              from {
                ... on ThreatActorGroup {
                  objectMarking {
                    id
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
        id: threatActorGroupInternalId,
        input: {
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.threatActorGroupEdit.relationAdd.from.objectMarking.length).toEqual(1);
  });
  it('should delete relation in threat actor group', async () => {
    const RELATION_DELETE_QUERY = gql`
        mutation threatActorGroupEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
          threatActorGroupEdit(id: $id) {
            relationDelete(toId: $toId, relationship_type: $relationship_type) {
              id
              objectMarking {
                id
              }
            }
          }
        }
      `;
    const queryResult = await queryAsAdmin({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: threatActorGroupInternalId,
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.threatActorGroupEdit.relationDelete.objectMarking.length).toEqual(0);
  });
  it('should threat actor group deleted', async () => {
    const DELETE_QUERY = gql`
        mutation threatActorGroupDelete($id: ID!) {
          threatActorGroupEdit(id: $id) {
            delete
          }
        }
      `;
      // Delete the threat actor group
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: threatActorGroupInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: threatActorsGroupStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.threatActorGroup).toBeNull();
  });
});
