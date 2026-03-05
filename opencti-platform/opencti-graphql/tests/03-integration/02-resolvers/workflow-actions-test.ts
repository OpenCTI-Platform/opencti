import gql from 'graphql-tag';
import { beforeAll, describe, expect, it } from 'vitest';
import { adminQuery, ADMIN_USER, TEST_ORGANIZATION } from '../../utils/testQuery';

const WORKFLOW_DEFINITION_SET_MUTATION = gql`
  mutation WorkflowDefinitionSet($entityType: String!, $definition: String!) {
    workflowDefinitionSet(entityType: $entityType, definition: $definition) {
      id
      target_type
      workflow_id
    }
  }
`;

const CREATE_DRAFT_WORKSPACE_QUERY = gql`
  mutation DraftWorkspaceAdd($input: DraftWorkspaceAddInput!) {
    draftWorkspaceAdd(input: $input) {
      id
      name
      draft_status
    }
  }
`;

const TRIGGER_WORKFLOW_EVENT_MUTATION = gql`
  mutation TriggerWorkflowEvent($entityId: String!, $eventName: String!) {
    triggerWorkflowEvent(entityId: $entityId, eventName: $eventName) {
      success
      newState
      reason
    }
  }
`;

const DRAFT_WORKSPACE_QUERY = gql`
  query DraftWorkspace($id: String!) {
    draftWorkspace(id: $id) {
      id
      name
      authorizedMembers {
        member_id
        access_right
      }
    }
  }
`;

const WORKFLOW_DEFINITION_DELETE_MUTATION = gql`
  mutation WorkflowDefinitionDelete($entityType: String!) {
    workflowDefinitionDelete(entityType: $entityType) {
      id
      workflow_id
    }
  }
`;

describe('Workflow Actions Resolver', () => {
  let draftWorkspaceId: string;

  beforeAll(async () => {
    const result = await adminQuery({
      query: CREATE_DRAFT_WORKSPACE_QUERY,
      variables: {
        input: { name: 'Workflow Action Test Workspace' },
      },
    });
    draftWorkspaceId = result.data.draftWorkspaceAdd.id;
  });

  it('should update authorized members on workflow event', async () => {
    // 1. Define a workflow with updateAuthorizedMembers action
    const authorizedMembersInput = [
      { id: ADMIN_USER.id, access_right: 'admin' },
      { id: TEST_ORGANIZATION.id, access_right: 'view' },
    ];

    const workflowDefinition = JSON.stringify({
      id: 'draft-workflow-with-action',
      name: 'Draft Workflow with Action',
      initialState: 'open',
      states: [
        { name: 'open' },
        {
          name: 'restricted',
          onEnter: [
            {
              type: 'updateAuthorizedMembers',
              params: {
                authorized_members: authorizedMembersInput
              },
            },
          ],
        },
      ],
      transitions: [{ from: 'open', to: 'restricted', event: 'restrict_event' }],
    });

    // 2. Set the workflow definition
    await adminQuery({
      query: WORKFLOW_DEFINITION_SET_MUTATION,
      variables: {
        entityType: 'DraftWorkspace',
        definition: workflowDefinition,
      },
    });

    // 3. Trigger the event
    const triggerResult = await adminQuery({
      query: TRIGGER_WORKFLOW_EVENT_MUTATION,
      variables: {
        entityId: draftWorkspaceId,
        eventName: 'restrict_event',
      },
    });
    expect(triggerResult.data.triggerWorkflowEvent.success).toBe(true);
    expect(triggerResult.data.triggerWorkflowEvent.newState).toBe('restricted');

    // 4. Verify authorized members
    const workspaceResult = await adminQuery({
      query: DRAFT_WORKSPACE_QUERY,
      variables: { id: draftWorkspaceId },
    });

    const { authorizedMembers } = workspaceResult.data.draftWorkspace;
    expect(authorizedMembers.length).toBe(2);
    expect(authorizedMembers).toEqual(expect.arrayContaining([
      expect.objectContaining({ member_id: ADMIN_USER.id, access_right: 'admin' }),
      expect.objectContaining({ member_id: TEST_ORGANIZATION.id, access_right: 'view' }),
    ]));
  });

  it('should cleanup after tests', async () => {
    await adminQuery({
      query: WORKFLOW_DEFINITION_DELETE_MUTATION,
      variables: {
        entityType: 'DraftWorkspace',
      },
    });
  });
});
