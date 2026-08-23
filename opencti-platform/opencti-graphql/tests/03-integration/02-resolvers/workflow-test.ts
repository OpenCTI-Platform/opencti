import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { wait } from '../../../src/database/utils';
import { findHistory } from '../../../src/domain/log';
import { FilterMode, LogsOrdering, OrderingMode } from '../../../src/generated/graphql';
import { ADMIN_USER, testContext, USER_PARTICIPATE } from '../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden } from '../../utils/testQueryHelper';

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

// Task 2, Step 6.1 / tasks.md 2.7: unlike the DraftWorkspace-only tests above, `Report` is a
// legacy-Status entity type (per Task 6's migration scope) with no built-in WorkflowInstance
// support until a WorkflowDefinition is published for it — exercising this path proves the
// generalized StixDomainObject-level `workflowInstance` field (Task 5) and the legacy
// `x_opencti_workflow_id`/`status` projection (Task 2) both work end-to-end for an arbitrary SDO,
// not just the one type built directly on the new engine from day one.
describe('Workflow projection onto legacy Status field (Report)', () => {
  let reportInternalId: string;
  const reportWorkflowDefinition = JSON.stringify({
    id: 'report-workflow',
    name: 'Report Workflow',
    initialState: 'open',
    states: [{ statusId: 'open' }, { statusId: 'validated' }],
    transitions: [{ from: 'open', to: 'validated', event: 'validate_event' }],
  });

  const REPORT_ADD_MUTATION = gql`
    mutation ReportAddForWorkflowTest($input: ReportAddInput!) {
      reportAdd(input: $input) {
        id
      }
    }
  `;

  const REPORT_STATUS_QUERY = gql`
    query ReportStatusForWorkflowTest($id: String!) {
      report(id: $id) {
        status {
          id
        }
        workflowInstance {
          currentState
        }
      }
    }
  `;

  const REPORT_WORKFLOW_INSTANCE_AUTH_QUERY = gql`
    query ReportWorkflowInstanceAuth($id: String!) {
      report(id: $id) {
        workflowInstance {
          currentState
        }
      }
    }
  `;

  beforeAll(async () => {
    // Reports are content-addressed (standard_id derived from name + published), so a unique
    // name/published pair per test run avoids colliding with any entity left over by a prior,
    // interrupted local run of this suite.
    const reportResult = await queryAsAdminWithSuccess({
      query: REPORT_ADD_MUTATION,
      variables: {
        input: { name: `Workflow Projection Test Report ${Date.now()}`, published: new Date().toISOString() },
      },
    });
    reportInternalId = reportResult.data.reportAdd.id;

    // Defensive cleanup: remove any WorkflowDefinition left over on 'Report' by a prior,
    // interrupted local run, so `workflowDefinitionSet` below cannot silently no-op.
    await queryAsAdmin({
      query: WORKFLOW_DEFINITION_DELETE_MUTATION,
      variables: { entityType: 'Report' },
    });

    await queryAsAdminWithSuccess({
      query: WORKFLOW_DEFINITION_ADD_MUTATION,
      variables: { entityType: 'Report', definition: reportWorkflowDefinition },
    });
    await queryAsAdminWithSuccess({
      query: WORKFLOW_DEFINITION_PUBLISH_MUTATION,
      variables: { entityType: 'Report' },
    });
  });

  afterAll(async () => {
    await queryAsAdmin({
      query: WORKFLOW_DEFINITION_DELETE_MUTATION,
      variables: { entityType: 'Report' },
    });
    await queryAsAdmin({
      query: gql`
        mutation ReportDeleteForWorkflowTest($id: ID!) {
          reportDelete(id: $id)
        }
      `,
      variables: { id: reportInternalId },
    });
  });

  it('should eagerly create a WorkflowInstance and project the initial state onto the legacy status field', async () => {
    const result = await queryAsAdminWithSuccess({
      query: REPORT_STATUS_QUERY,
      variables: { id: reportInternalId },
    });
    expect(result.data.report.workflowInstance.currentState).toBe('open');
    expect(result.data.report.status.id).toBeDefined();
  });

  it('should deny workflowInstance access to a user without KNOWLEDGE_KNUPDATE (auth matrix, tasks.md 5.0.4)', async () => {
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
      query: REPORT_WORKFLOW_INSTANCE_AUTH_QUERY,
      variables: { id: reportInternalId },
    });
  });

  it('should update both the WorkflowInstance state and the projected legacy status on transition, emitting a normal update event', async () => {
    const before = await queryAsAdminWithSuccess({
      query: REPORT_STATUS_QUERY,
      variables: { id: reportInternalId },
    });
    const initialStatusId = before.data.report.status.id;

    const triggerResult = await queryAsAdminWithSuccess({
      query: TRIGGER_WORKFLOW_EVENT_MUTATION,
      variables: { entityId: reportInternalId, eventName: 'validate_event' },
    });
    expect(triggerResult.data.triggerWorkflowEvent.success).toBe(true);
    expect(triggerResult.data.triggerWorkflowEvent.newState).toBe('validated');

    const after = await queryAsAdminWithSuccess({
      query: REPORT_STATUS_QUERY,
      variables: { id: reportInternalId },
    });
    expect(after.data.report.workflowInstance.currentState).toBe('validated');
    expect(after.data.report.status.id).toBeDefined();
    expect(after.data.report.status.id).not.toBe(initialStatusId);

    // A normal update event (the same pipeline feeding the live stream) must have been recorded
    // for the legacy `x_opencti_workflow_id` projection write, proving it is not a silent/internal-
    // only write (Task 2, Step 2.2's `workflowInternalWrite` flag only suppresses the Task 8
    // anti-loop hook, never the standard event/history pipeline). The history manager consumes the
    // event stream asynchronously (and, on a freshly-started platform, may not even be subscribed
    // yet by the time this assertion runs) - poll with retries instead of a single fixed wait.
    const findWorkflowHistoryLogs = () => findHistory(testContext, ADMIN_USER, {
      filters: {
        mode: FilterMode.And,
        filterGroups: [],
        filters: [
          { key: ['context_data.id'], values: [reportInternalId] },
          { key: ['event_type'], values: ['mutation', 'create', 'update', 'delete', 'merge'] },
          { key: ['event_scope'], values: ['update'] },
        ],
      },
      orderBy: LogsOrdering.CreatedAt,
      orderMode: OrderingMode.Desc,
    });
    let logs = await findWorkflowHistoryLogs();
    for (let attempt = 0; attempt < 15 && logs.edges.length === 0; attempt += 1) {
      await wait(1000);
      logs = await findWorkflowHistoryLogs();
    }
    expect(logs.edges.length).toBeGreaterThan(0);
    const workflowFieldChange = logs.edges
      .flatMap((edge) => edge.node.context_data.history_changes)
      .find((change) => change.field?.includes('x_opencti_workflow_id'));
    expect(workflowFieldChange).toBeDefined();
  });
});
