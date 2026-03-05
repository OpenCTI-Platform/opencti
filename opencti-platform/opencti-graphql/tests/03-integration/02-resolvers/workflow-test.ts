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

const WORKFLOW_DEFINITION_QUERY = gql`
  query WorkflowDefinition($entityType: String!) {
    workflowDefinition(entityType: $entityType) {
      name
      initialState
      states {
        name
      }
      transitions {
        from
        to
        event
      }
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

const WORKFLOW_INSTANCE_QUERY = gql`
  query WorkflowInstance($entityId: String!) {
    workflowInstance(entityId: $entityId) {
      currentState
      allowedTransitions {
        event
        toState
      }
    }
  }
`;

const WORKFLOW_INSTANCE_NESTED_QUERY = gql`
  query WorkflowInstanceNested($entityId: String!) {
    draftWorkspace(id: $entityId) {
      workflowInstance {
        currentState
        allowedTransitions {
          event
          toState
        }
      }
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

const WORKFLOW_DEFINITION_DELETE_MUTATION = gql`
  mutation WorkflowDefinitionDelete($entityType: String!) {
    workflowDefinitionDelete(entityType: $entityType) {
      id
      workflow_id
    }
  }
`;

describe('Workflow Resolver', () => {
  let draftWorkspaceId: string;
  const workflowDefinition = JSON.stringify({
    id: 'draft-workflow',
    name: 'Draft Workflow',
    initialState: 'open',
    states: [{ name: 'open' }, { name: 'validated' }],
    transitions: [{ from: 'open', to: 'validated', event: 'validate_event' }],
  });

  beforeAll(async () => {
    const result = await adminQuery({
      query: CREATE_DRAFT_WORKSPACE_QUERY,
      variables: {
        input: { name: 'Workflow Test Workspace' },
      },
    });
    if (result.errors) {
      console.error('DraftWorkspaceAdd Error:', JSON.stringify(result.errors, null, 2));
    }
    draftWorkspaceId = result.data.draftWorkspaceAdd.id;
  });

  it('should create a workflow definition', async () => {
    const result = await adminQuery({
      query: WORKFLOW_DEFINITION_ADD_MUTATION,
      variables: {
        entityType: 'DraftWorkspace',
        definition: workflowDefinition,
      },
    });
    expect(result.data.workflowDefinitionSet.target_type).toBe('DraftWorkspace');
    expect(result.data.workflowDefinitionSet.workflow_id).toBeDefined();
  });

  it('should query a workflow definition', async () => {
    const result = await adminQuery({
      query: WORKFLOW_DEFINITION_QUERY,
      variables: {
        entityType: 'DraftWorkspace',
      },
    });
    expect(result.data.workflowDefinition.initialState).toBe('open');
    expect(result.data.workflowDefinition.states.length).toBe(2);
    expect(result.data.workflowDefinition.transitions[0].event).toBe('validate_event');
  });

  it('should query a workflow instance', async () => {
    const instanceResult = await adminQuery({
      query: WORKFLOW_INSTANCE_QUERY,
      variables: {
        entityId: draftWorkspaceId,
      },
    });
    expect(instanceResult.data.workflowInstance.currentState).toBe('open');
    expect(instanceResult.data.workflowInstance.allowedTransitions.length).toBe(1);
    expect(instanceResult.data.workflowInstance.allowedTransitions[0].event).toBe('validate_event');
  });

  it('should query a workflow instance via nested draftWorkspace', async () => {
    const instanceResult = await adminQuery({
      query: WORKFLOW_INSTANCE_NESTED_QUERY,
      variables: {
        entityId: draftWorkspaceId,
      },
    });
    expect(instanceResult.data.draftWorkspace.workflowInstance.currentState).toBe('open');
    expect(instanceResult.data.draftWorkspace.workflowInstance.allowedTransitions.length).toBe(1);
    expect(instanceResult.data.draftWorkspace.workflowInstance.allowedTransitions[0].event).toBe('validate_event');
  });

  it('should trigger a workflow event', async () => {
    const result = await adminQuery({
      query: TRIGGER_WORKFLOW_EVENT_MUTATION,
      variables: {
        entityId: draftWorkspaceId,
        eventName: 'validate_event',
      },
    });
    expect(result.data.triggerWorkflowEvent.success).toBe(true);
    expect(result.data.triggerWorkflowEvent.newState).toBe('validated');

    // Check if the entity was actually updated
    const instanceResult = await adminQuery({
      query: WORKFLOW_INSTANCE_QUERY,
      variables: {
        entityId: draftWorkspaceId,
      },
    });
    expect(instanceResult.data.workflowInstance.currentState).toBe('validated');
    expect(instanceResult.data.workflowInstance.allowedTransitions.length).toBe(0);
  });

  it('should fail to trigger an invalid event', async () => {
    const result = await adminQuery({
      query: TRIGGER_WORKFLOW_EVENT_MUTATION,
      variables: {
        entityId: draftWorkspaceId,
        eventName: 'invalid_event',
      },
    });
    expect(result.data.triggerWorkflowEvent.success).toBe(false);
    expect(result.data.triggerWorkflowEvent.reason).toContain('No transition found');
  });

  it('should delete a workflow definition', async () => {
    // 1. Delete the workflow definition
    const deleteResult = await adminQuery({
      query: WORKFLOW_DEFINITION_DELETE_MUTATION,
      variables: {
        entityType: 'DraftWorkspace',
      },
    });
    expect(deleteResult.data.workflowDefinitionDelete.workflow_id).toBeNull();

    // 2. Check if the definition is gone
    const queryResult = await adminQuery({
      query: WORKFLOW_DEFINITION_QUERY,
      variables: {
        entityType: 'DraftWorkspace',
      },
    });
    expect(queryResult.data.workflowDefinition).toBeNull();

    // 3. Check if instance now returns null
    const instanceResult = await adminQuery({
      query: WORKFLOW_INSTANCE_QUERY,
      variables: {
        entityId: draftWorkspaceId,
      },
    });
    expect(instanceResult.data.workflowInstance).toBeNull();
  });
});
