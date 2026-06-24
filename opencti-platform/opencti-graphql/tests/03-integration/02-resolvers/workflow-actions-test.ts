import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import * as ee from '../../../src/enterprise-edition/ee';
import { ADMIN_USER, TEST_ORGANIZATION } from '../../utils/testQuery';
import { queryAsAdmin } from '../../utils/testQueryHelper';

const WORKFLOW_DEFINITION_SET_MUTATION = gql`
  mutation WorkflowDefinitionSet($entityType: String!, $definition: String!) {
    workflowDefinitionSet(entityType: $entityType, definition: $definition) {
      id
      target_type
      workflow_id
    }
  }
`;

const WORKFLOW_DEFINITION_PUBLISH_MUTATION = gql`
  mutation WorkflowDefinitionPublish($entityType: String!) {
    workflowDefinitionPublish(entityType: $entityType) {
      id
      workflow_id
      published
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
    vi.spyOn(ee, 'checkEnterpriseEdition').mockResolvedValue();
    const result = await queryAsAdmin({
      query: CREATE_DRAFT_WORKSPACE_QUERY,
      variables: {
        input: { name: 'Workflow Action Test Workspace' },
      },
    });
    draftWorkspaceId = result.data?.draftWorkspaceAdd.id;
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
        { statusId: 'open' },
        {
          statusId: 'restricted',
          onEnter: [
            {
              type: 'updateAuthorizedMembers',
              params: {
                authorized_members: authorizedMembersInput,
              },
            },
          ],
        },
        { statusId: 'validated' },
      ],
      transitions: [
        { from: 'open', to: 'restricted', event: 'restrict_event' },
        { from: 'restricted', to: 'validated', event: 'validate_event', syncActions: [{ type: 'validateDraft' }] },
      ],
    });

    // 2. Set the workflow definition
    await queryAsAdmin({
      query: WORKFLOW_DEFINITION_SET_MUTATION,
      variables: {
        entityType: 'DraftWorkspace',
        definition: workflowDefinition,
      },
    });

    // 3. Publish the workflow definition so it can be used at runtime
    await queryAsAdmin({
      query: WORKFLOW_DEFINITION_PUBLISH_MUTATION,
      variables: {
        entityType: 'DraftWorkspace',
      },
    });

    // 4. Trigger the event
    const triggerResult = await queryAsAdmin({
      query: TRIGGER_WORKFLOW_EVENT_MUTATION,
      variables: {
        entityId: draftWorkspaceId,
        eventName: 'restrict_event',
      },
    });
    expect(triggerResult.data?.triggerWorkflowEvent.success).toBe(true);
    expect(triggerResult.data?.triggerWorkflowEvent.newState).toBe('restricted');

    // 5. Verify authorized members
    const workspaceResult = await queryAsAdmin({
      query: DRAFT_WORKSPACE_QUERY,
      variables: { id: draftWorkspaceId },
    });

    const { authorizedMembers } = workspaceResult.data?.draftWorkspace || {};
    expect(authorizedMembers.length).toBe(2);
    expect(authorizedMembers).toEqual(expect.arrayContaining([
      expect.objectContaining({ member_id: ADMIN_USER.id, access_right: 'admin' }),
      expect.objectContaining({ member_id: TEST_ORGANIZATION.id, access_right: 'view' }),
    ]));
  });

  it('should not execute actions from draft workflow when not published', async () => {
    // 1. Create a new workflow with different actions (don't publish)
    const draftOnlyWorkflow = JSON.stringify({
      id: 'draft-only-workflow',
      name: 'Draft Only Workflow',
      initialState: 'open',
      states: [
        { statusId: 'open' },
        {
          statusId: 'secret',
          onEnter: [
            {
              type: 'updateAuthorizedMembers',
              params: {
                authorized_members: [{ id: ADMIN_USER.id, access_right: 'edit' }],
              },
            },
          ],
        },
      ],
      transitions: [
        { from: 'open', to: 'secret', event: 'secret_event' },
      ],
    });

    // Set but don't publish
    await queryAsAdmin({
      query: WORKFLOW_DEFINITION_SET_MUTATION,
      variables: {
        entityType: 'DraftWorkspace',
        definition: draftOnlyWorkflow,
      },
    });

    // Try to trigger event - should fail because draft is not published
    const triggerResult = await queryAsAdmin({
      query: TRIGGER_WORKFLOW_EVENT_MUTATION,
      variables: {
        entityId: draftWorkspaceId,
        eventName: 'secret_event',
      },
    });

    // Should fail or not find transition since runtime uses published version
    expect(triggerResult.data?.triggerWorkflowEvent.success).toBe(false);
  });

  it('should cleanup after tests', async () => {
    await queryAsAdmin({
      query: WORKFLOW_DEFINITION_DELETE_MUTATION,
      variables: {
        entityType: 'DraftWorkspace',
      },
    });
  });

  afterAll(() => {
    vi.restoreAllMocks();
  });
});
