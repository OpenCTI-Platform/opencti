import gql from 'graphql-tag';
import { beforeAll, describe, expect, it } from 'vitest';
import { adminQuery } from '../../utils/testQuery';

const WORKFLOW_DEFINITION_ADD_MUTATION = gql`
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

describe('Workflow Conditions Resolver', () => {
  let draftWorkspaceId: string;
  const workspaceName = 'Conditions Test Workspace';

  const workflowDefinition = JSON.stringify({
    id: 'conditions-workflow',
    name: 'Conditions Workflow',
    initialState: 'open',
    states: [{ name: 'open' }, { name: 'step1' }, { name: 'step2' }, { name: 'done' }],
    transitions: [
      {
        from: 'open',
        to: 'step1',
        event: 'named_condition_event',
        conditions: [{ type: 'is-admin' }],
      },
      {
        from: 'step1',
        to: 'step2',
        event: 'field_comparison_event',
        conditions: [{ field: 'entity.name', operator: 'eq', value: workspaceName }],
      },
      {
        from: 'step2',
        to: 'done',
        event: 'mixed_conditions_event',
        conditions: [
          { type: 'is-admin' },
          { field: 'entity.name', operator: 'contains', value: 'Conditions' },
        ],
      },
    ],
  });

  beforeAll(async () => {
    // 1. Create a workspace
    const result = await adminQuery({
      query: CREATE_DRAFT_WORKSPACE_QUERY,
      variables: {
        input: { name: workspaceName },
      },
    });
    draftWorkspaceId = result.data.draftWorkspaceAdd.id;

    // 2. Set the workflow definition
    await adminQuery({
      query: WORKFLOW_DEFINITION_ADD_MUTATION,
      variables: {
        entityType: 'DraftWorkspace',
        definition: workflowDefinition,
      },
    });
  });

  it('should pass named condition (is-admin)', async () => {
    const result = await adminQuery({
      query: TRIGGER_WORKFLOW_EVENT_MUTATION,
      variables: {
        entityId: draftWorkspaceId,
        eventName: 'named_condition_event',
      },
    });
    expect(result.data.triggerWorkflowEvent.success).toBe(true);
    expect(result.data.triggerWorkflowEvent.newState).toBe('step1');
  });

  it('should pass field comparison (entity.name eq workspaceName)', async () => {
    const result = await adminQuery({
      query: TRIGGER_WORKFLOW_EVENT_MUTATION,
      variables: {
        entityId: draftWorkspaceId,
        eventName: 'field_comparison_event',
      },
    });
    expect(result.data.triggerWorkflowEvent.success).toBe(true);
    expect(result.data.triggerWorkflowEvent.newState).toBe('step2');
  });

  it('should pass mixed conditions (named + field)', async () => {
    const result = await adminQuery({
      query: TRIGGER_WORKFLOW_EVENT_MUTATION,
      variables: {
        entityId: draftWorkspaceId,
        eventName: 'mixed_conditions_event',
      },
    });
    expect(result.data.triggerWorkflowEvent.success).toBe(true);
    expect(result.data.triggerWorkflowEvent.newState).toBe('done');
  });
});
