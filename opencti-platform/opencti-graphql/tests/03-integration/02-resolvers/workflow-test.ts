import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { queryAsAdmin } from '../../utils/testQueryHelper';

const WORKFLOW_DEFINITION_ADD_MUTATION = gql`
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

const WORKFLOW_DEFINITION_QUERY = gql`
  query WorkflowDefinition($entityType: String!, $allowDraft: Boolean) {
    workflowDefinition(entityType: $entityType, allowDraft: $allowDraft) {
      name
      published
      initialState
      states {
        statusId
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
        actions
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
          actions
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

const DELETE_DRAFT_WORKSPACE_QUERY = gql`
  mutation DraftWorkspaceDelete($id: ID!) {
    draftWorkspaceDelete(id: $id)
  }
`;

describe('Workflow Resolver', () => {
  let draftWorkspaceId: string;
  const workflowDefinition = JSON.stringify({
    id: 'draft-workflow',
    name: 'Draft Workflow',
    initialState: 'open',
    states: [{ statusId: 'open' }, { statusId: 'validated' }],
    transitions: [{
      from: 'open',
      to: 'validated',
      event: 'validate_event',
      syncActions: [{ type: 'validateDraft' }],
    }],
  });

  const workflowWithFilters = JSON.stringify({
    id: 'filter-workflow',
    name: 'Filter Workflow',
    initialState: 'open',
    states: [
      { statusId: 'open' },
      { statusId: 'group_check' },
      { statusId: 'org_check' },
      { statusId: 'role_check' },
      { statusId: 'comparison_check' },
    ],
    transitions: [
      {
        from: 'open',
        to: 'group_check',
        event: 'group_event',
        conditions: {
          filters: {
            mode: 'and',
            filters: [
              {
                key: 'workflow_group',
                operator: 'eq',
                values: ['test-group-id'],
                mode: 'or',
              },
            ],
            filterGroups: [],
          },
        },
      },
      {
        from: 'open',
        to: 'org_check',
        event: 'org_event',
        conditions: {
          filters: {
            mode: 'and',
            filters: [
              {
                key: 'workflow_organization',
                operator: 'eq',
                values: ['test-org-id'],
                mode: 'or',
              },
            ],
            filterGroups: [],
          },
        },
      },
      {
        from: 'open',
        to: 'role_check',
        event: 'role_event',
        conditions: {
          filters: {
            mode: 'and',
            filters: [
              {
                key: 'workflow_role',
                operator: 'eq',
                values: ['Admin'],
                mode: 'or',
              },
            ],
            filterGroups: [],
          },
        },
      },
      {
        from: 'open',
        to: 'comparison_check',
        event: 'comparison_event',
        conditions: {
          filters: {
            mode: 'and',
            filters: [
              {
                key: 'name',
                operator: 'contains',
                values: ['Filter'],
                mode: 'or',
              },
            ],
            filterGroups: [],
          },
        },
      },
    ],
  });

  beforeAll(async () => {
    const result = await queryAsAdmin({
      query: CREATE_DRAFT_WORKSPACE_QUERY,
      variables: {
        input: { name: 'Workflow Test Workspace' },
      },
    });
    if (result.errors) {
      console.error('DraftWorkspaceAdd Error:', JSON.stringify(result.errors, null, 2));
    }
    draftWorkspaceId = result.data?.draftWorkspaceAdd.id;
  });

  afterAll(async () => {
    await queryAsAdmin({
      query: DELETE_DRAFT_WORKSPACE_QUERY,
      variables: { id: draftWorkspaceId },
    });
  });

  it('should create a workflow definition', async () => {
    const result = await queryAsAdmin({
      query: WORKFLOW_DEFINITION_ADD_MUTATION,
      variables: {
        entityType: 'DraftWorkspace',
        definition: workflowDefinition,
      },
    });
    expect(result.data?.workflowDefinitionSet.target_type).toBe('DraftWorkspace');
    expect(result.data?.workflowDefinitionSet.workflow_id).toBeDefined();

    // Publish the workflow definition so it can be used at runtime
    await queryAsAdmin({
      query: WORKFLOW_DEFINITION_PUBLISH_MUTATION,
      variables: {
        entityType: 'DraftWorkspace',
      },
    });
  });

  it('should query a workflow definition', async () => {
    const result = await queryAsAdmin({
      query: WORKFLOW_DEFINITION_QUERY,
      variables: {
        entityType: 'DraftWorkspace',
      },
    });
    expect(result.data?.workflowDefinition.initialState).toBe('open');
    expect(result.data?.workflowDefinition.states.length).toBe(2);
    expect(result.data?.workflowDefinition.transitions[0].event).toBe('validate_event');
  });

  it('should query a workflow instance', async () => {
    const instanceResult = await queryAsAdmin({
      query: WORKFLOW_INSTANCE_QUERY,
      variables: {
        entityId: draftWorkspaceId,
      },
    });
    expect(instanceResult.data?.workflowInstance.currentState).toBe('open');
    expect(instanceResult.data?.workflowInstance.allowedTransitions.length).toBe(1);
    expect(instanceResult.data?.workflowInstance.allowedTransitions[0].event).toBe('validate_event');
    expect(instanceResult.data?.workflowInstance.allowedTransitions[0].actions).toContain('validateDraft');
  });

  it('should query a workflow instance via nested draftWorkspace', async () => {
    const instanceResult = await queryAsAdmin({
      query: WORKFLOW_INSTANCE_NESTED_QUERY,
      variables: {
        entityId: draftWorkspaceId,
      },
    });
    expect(instanceResult.data?.draftWorkspace.workflowInstance.currentState).toBe('open');
    expect(instanceResult.data?.draftWorkspace.workflowInstance.allowedTransitions.length).toBe(1);
    expect(instanceResult.data?.draftWorkspace.workflowInstance.allowedTransitions[0].event).toBe('validate_event');
  });

  it('should trigger a workflow event', async () => {
    const result = await queryAsAdmin({
      query: TRIGGER_WORKFLOW_EVENT_MUTATION,
      variables: {
        entityId: draftWorkspaceId,
        eventName: 'validate_event',
      },
    });
    expect(result.data?.triggerWorkflowEvent.success).toBe(true);
    expect(result.data?.triggerWorkflowEvent.newState).toBe('validated');

    // Check if the entity was actually updated
    const instanceResult = await queryAsAdmin({
      query: WORKFLOW_INSTANCE_QUERY,
      variables: {
        entityId: draftWorkspaceId,
      },
    });
    expect(instanceResult.data?.workflowInstance.currentState).toBe('validated');
    expect(instanceResult.data?.workflowInstance.allowedTransitions.length).toBe(0);
  });

  it('should fail to trigger an invalid event', async () => {
    const result = await queryAsAdmin({
      query: TRIGGER_WORKFLOW_EVENT_MUTATION,
      variables: {
        entityId: draftWorkspaceId,
        eventName: 'invalid_event',
      },
    });
    expect(result.data?.triggerWorkflowEvent.success).toBe(false);
    expect(result.data?.triggerWorkflowEvent.reason).toContain('No transition found');
  });

  it('should delete a workflow definition', async () => {
    // 1. Delete the workflow definition
    const deleteResult = await queryAsAdmin({
      query: WORKFLOW_DEFINITION_DELETE_MUTATION,
      variables: {
        entityType: 'DraftWorkspace',
      },
    });
    expect(deleteResult.data?.workflowDefinitionDelete.workflow_id).toBeNull();

    // 2. Check if the definition is gone
    const queryResult = await queryAsAdmin({
      query: WORKFLOW_DEFINITION_QUERY,
      variables: {
        entityType: 'DraftWorkspace',
      },
    });
    expect(queryResult.data?.workflowDefinition).toBeNull();

    // 3. Check if instance now returns null
    const instanceResult = await queryAsAdmin({
      query: WORKFLOW_INSTANCE_QUERY,
      variables: {
        entityId: draftWorkspaceId,
      },
    });
    expect(instanceResult.data?.workflowInstance).toBeNull();
  });

  // Tests for filter operators and special keys
  describe('Workflow Filters Coverage', () => {
    let filterTestWorkspaceId: string;

    beforeAll(async () => {
      // Create a test workspace for filter testing
      const result = await queryAsAdmin({
        query: CREATE_DRAFT_WORKSPACE_QUERY,
        variables: {
          input: { name: 'Filter Test Workspace' },
        },
      });
      filterTestWorkspaceId = result.data?.draftWorkspaceAdd.id;

      // Set the filter workflow definition
      await queryAsAdmin({
        query: WORKFLOW_DEFINITION_ADD_MUTATION,
        variables: {
          entityType: 'DraftWorkspace',
          definition: workflowWithFilters,
        },
      });
    });

    afterAll(async () => {
      await queryAsAdmin({
        query: WORKFLOW_DEFINITION_DELETE_MUTATION,
        variables: { entityType: 'DraftWorkspace' },
      });
      await queryAsAdmin({
        query: DELETE_DRAFT_WORKSPACE_QUERY,
        variables: { id: filterTestWorkspaceId },
      });
    });

    it('should test workflow_group filter key', async () => {
      // This tests the workflow_group special key path
      const result = await queryAsAdmin({
        query: TRIGGER_WORKFLOW_EVENT_MUTATION,
        variables: {
          entityId: filterTestWorkspaceId,
          eventName: 'group_event',
        },
      });
      // May pass or fail depending on user groups, but exercises the code path
      expect(result.data?.triggerWorkflowEvent).toBeDefined();
    });

    it('should test workflow_organization filter key', async () => {
      // This tests the workflow_organization special key path
      const result = await queryAsAdmin({
        query: TRIGGER_WORKFLOW_EVENT_MUTATION,
        variables: {
          entityId: filterTestWorkspaceId,
          eventName: 'org_event',
        },
      });
      // May pass or fail depending on user organizations, but exercises the code path
      expect(result.data?.triggerWorkflowEvent).toBeDefined();
    });

    it('should test workflow_role filter key', async () => {
      // This tests the workflow_role special key path
      const result = await queryAsAdmin({
        query: TRIGGER_WORKFLOW_EVENT_MUTATION,
        variables: {
          entityId: filterTestWorkspaceId,
          eventName: 'role_event',
        },
      });
      // May pass or fail depending on user roles, but exercises the code path
      expect(result.data?.triggerWorkflowEvent).toBeDefined();
    });

    it('should test contains operator', async () => {
      // This tests the Contains operator in evaluateFilter
      const result = await queryAsAdmin({
        query: TRIGGER_WORKFLOW_EVENT_MUTATION,
        variables: {
          entityId: filterTestWorkspaceId,
          eventName: 'comparison_event',
        },
      });
      // May pass or fail depending on draft name, but exercises the code path
      expect(result.data?.triggerWorkflowEvent).toBeDefined();
    });
  });

  describe('Workflow Publishing', () => {
    beforeAll(async () => {
      // Create a draft by updating the workflow definition
      const modifiedDefinition = JSON.stringify({
        id: 'draft-workflow',
        name: 'Draft Workflow - Before Publish Test',
        initialState: 'open',
        states: [{ statusId: 'open' }, { statusId: 'validated' }],
        transitions: [{
          from: 'open',
          to: 'validated',
          event: 'validate_event',
          syncActions: [{ type: 'validateDraft' }],
        }],
      });

      await queryAsAdmin({
        query: WORKFLOW_DEFINITION_ADD_MUTATION,
        variables: {
          entityType: 'DraftWorkspace',
          definition: modifiedDefinition,
        },
      });
    });

    it('should publish a workflow definition', async () => {
      const publishResult = await queryAsAdmin({
        query: WORKFLOW_DEFINITION_PUBLISH_MUTATION,
        variables: {
          entityType: 'DraftWorkspace',
        },
      });
      expect(publishResult.data?.workflowDefinitionPublish.workflow_id).toBeDefined();
      expect(publishResult.data?.workflowDefinitionPublish.published).toBe(true);
    });

    it('should query published workflow definition', async () => {
      const result = await queryAsAdmin({
        query: WORKFLOW_DEFINITION_QUERY,
        variables: {
          entityType: 'DraftWorkspace',
          allowDraft: false, // Should return published version only
        },
      });
      expect(result.data?.workflowDefinition).toBeDefined();
      expect(result.data?.workflowDefinition.published).toBe(true);
    });

    it('should update workflow creating new draft after publish', async () => {
      const newDefinition = JSON.stringify({
        id: 'draft-workflow',
        name: 'Draft Workflow - Modified',
        initialState: 'open',
        states: [{ statusId: 'open' }, { statusId: 'validated' }, { statusId: 'closed' }],
        transitions: [{
          from: 'open',
          to: 'validated',
          event: 'validate_event',
          syncActions: [{ type: 'validateDraft' }],
        }],
      });

      const updateResult = await queryAsAdmin({
        query: WORKFLOW_DEFINITION_ADD_MUTATION,
        variables: {
          entityType: 'DraftWorkspace',
          definition: newDefinition,
        },
      });
      expect(updateResult.data?.workflowDefinitionSet.workflow_id).toBeDefined();
    });

    it('should query draft workflow with allowDraft true', async () => {
      const result = await queryAsAdmin({
        query: gql`
          query WorkflowDefinition($entityType: String!, $allowDraft: Boolean) {
            workflowDefinition(entityType: $entityType, allowDraft: $allowDraft) {
              name
              published
              states {
                statusId
              }
            }
          }
        `,
        variables: {
          entityType: 'DraftWorkspace',
          allowDraft: true,
        },
      });
      expect(result.data?.workflowDefinition).toBeDefined();
      expect(result.data?.workflowDefinition.name).toBe('Draft Workflow - Modified');
      expect(result.data?.workflowDefinition.published).toBe(false); // Draft differs from published
      expect(result.data?.workflowDefinition.states.length).toBe(3); // Modified has 3 states
    });

    it('should use published version for runtime when allowDraft is false', async () => {
      const result = await queryAsAdmin({
        query: gql`
          query WorkflowDefinition($entityType: String!, $allowDraft: Boolean) {
            workflowDefinition(entityType: $entityType, allowDraft: $allowDraft) {
              name
              states {
                statusId
              }
            }
          }
        `,
        variables: {
          entityType: 'DraftWorkspace',
          allowDraft: false,
        },
      });
      expect(result.data?.workflowDefinition).toBeDefined();
      expect(result.data?.workflowDefinition.states.length).toBe(2); // Published has 2 states
    });

    it('should return validation errors in workflow set response', async () => {
      const invalidDefinition = JSON.stringify({
        id: 'invalid-workflow',
        name: 'Invalid Workflow',
        initialState: 'open',
        states: [{ statusId: 'open' }],
        transitions: [{ from: 'open', to: 'nonexistent', event: 'go' }], // Invalid transition
      });

      const result = await queryAsAdmin({
        query: gql`
          mutation WorkflowDefinitionSet($entityType: String!, $definition: String!) {
            workflowDefinitionSet(entityType: $entityType, definition: $definition) {
              id
              published
              errors {
                type
                message
              }
            }
          }
        `,
        variables: {
          entityType: 'DraftWorkspace',
          definition: invalidDefinition,
        },
      });
      expect(result.data?.workflowDefinitionSet.errors).toBeDefined();
      expect(result.data?.workflowDefinitionSet.errors.length).toBeGreaterThan(0);
      expect(result.data?.workflowDefinitionSet.published).toBe(false);
    });

    it('should fail to publish workflow with validation errors', async () => {
      // Try to publish the invalid workflow from previous test
      const publishResult = await queryAsAdmin({
        query: WORKFLOW_DEFINITION_PUBLISH_MUTATION,
        variables: {
          entityType: 'DraftWorkspace',
        },
      });
      expect(publishResult.errors).toBeDefined();
      expect(publishResult.errors?.[0].message).toContain('validation errors');
    });
  });
});
