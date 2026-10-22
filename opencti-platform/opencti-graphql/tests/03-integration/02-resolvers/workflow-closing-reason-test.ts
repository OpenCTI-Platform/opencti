import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsUserIsExpectedError, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { ADMIN_USER, testContext, USER_EDITOR } from '../../utils/testQuery';
import { findByType } from '../../../src/domain/status';

const ENTITY_TYPE = 'Case-Incident';

const WORKFLOW_DEFINITION_SET_MUTATION = gql`
  mutation WorkflowClosingReasonDefinitionSet($entityType: String!, $definition: String!) {
    workflowDefinitionSet(entityType: $entityType, definition: $definition) {
      id
    }
  }
`;

const WORKFLOW_DEFINITION_PUBLISH_MUTATION = gql`
  mutation WorkflowClosingReasonDefinitionPublish($entityType: String!) {
    workflowDefinitionPublish(entityType: $entityType) {
      id
    }
  }
`;

const WORKFLOW_DEFINITION_DELETE_MUTATION = gql`
  mutation WorkflowClosingReasonDefinitionDelete($entityType: String!) {
    workflowDefinitionDelete(entityType: $entityType) {
      id
    }
  }
`;

const TRIGGER_MUTATION = gql`
  mutation WorkflowClosingReasonTrigger($entityId: String!, $eventName: String!, $closingReason: String) {
    triggerWorkflowEvent(entityId: $entityId, eventName: $eventName, closingReason: $closingReason) {
      success
      newState
      reason
    }
  }
`;

const BYPASS_MUTATION = gql`
  mutation WorkflowClosingReasonBypass($entityId: String!, $targetStatusId: String!) {
    setWorkflowStatus(entityId: $entityId, targetStatusId: $targetStatusId, applyTransitionActions: false) {
      success
      newState
      reason
    }
  }
`;

const CASE_INCIDENT_ADD_MUTATION = gql`
  mutation WorkflowClosingReasonCaseAdd($input: CaseIncidentAddInput!) {
    caseIncidentAdd(input: $input) {
      id
    }
  }
`;

const CASE_INCIDENT_DELETE_MUTATION = gql`
  mutation WorkflowClosingReasonCaseDelete($id: ID!) {
    caseIncidentDelete(id: $id)
  }
`;

const CASE_INCIDENT_QUERY = gql`
  query WorkflowClosingReasonCase($id: String!) {
    caseIncident(id: $id) {
      x_opencti_closing_reason
      workflowInstance {
        currentState
        allowedTransitions {
          event
          closingReason
        }
      }
    }
  }
`;

const CASE_INCIDENTS_BY_CLOSING_REASON_QUERY = gql`
  query WorkflowClosingReasonCases($filters: FilterGroup) {
    caseIncidents(filters: $filters) {
      edges {
        node {
          id
        }
      }
    }
  }
`;

const definition = JSON.stringify({
  id: 'case-incident-closing-reason-workflow',
  name: 'Case incident closing reason workflow',
  initialState: 'open',
  states: [{ statusId: 'open' }, { statusId: 'triaged' }, { statusId: 'closed' }, { statusId: 'archived' }],
  // closed and archived are final: only a bypass or an external status write moves an entity out of them
  transitions: [
    { from: ['open', 'triaged'], to: 'closed', event: 'close', closingReason: 'required' },
    { from: 'open', to: 'triaged', event: 'triage' },
    { from: 'open', to: 'archived', event: 'archive' },
  ],
});

// The editor cannot bypass mandatory fields, unlike the admin
const FIELD_PATCH_MUTATION = gql`
  mutation WorkflowClosingReasonFieldPatch($id: ID!, $input: [EditInput]!) {
    stixDomainObjectEdit(id: $id) {
      fieldPatch(input: $input) {
        id
        x_opencti_closing_reason
      }
    }
  }
`;

const MERGE_MUTATION = gql`
  mutation WorkflowClosingReasonMerge($id: ID!, $stixObjectsIds: [String]!) {
    stixEdit(id: $id) {
      merge(stixObjectsIds: $stixObjectsIds) {
        id
      }
    }
  }
`;

const trigger = async (entityId: string, eventName: string, closingReason?: string) => {
  const result = await queryAsUserWithSuccess(USER_EDITOR, { query: TRIGGER_MUTATION, variables: { entityId, eventName, closingReason } });
  return result.data.triggerWorkflowEvent;
};

const bypass = async (entityId: string, targetStatusId: string) => {
  const result = await queryAsAdminWithSuccess({ query: BYPASS_MUTATION, variables: { entityId, targetStatusId } });
  return result.data.setWorkflowStatus;
};

const readCase = async (id: string) => {
  const result = await queryAsAdminWithSuccess({ query: CASE_INCIDENT_QUERY, variables: { id } });
  return result.data.caseIncident;
};

describe('Workflow closing reason (Case-Incident)', () => {
  let caseId: string;
  const statusIds: Record<string, string> = {};

  beforeAll(async () => {
    await queryAsAdmin({ query: WORKFLOW_DEFINITION_DELETE_MUTATION, variables: { entityType: ENTITY_TYPE } });
    await queryAsAdminWithSuccess({ query: WORKFLOW_DEFINITION_SET_MUTATION, variables: { entityType: ENTITY_TYPE, definition } });
    await queryAsAdminWithSuccess({ query: WORKFLOW_DEFINITION_PUBLISH_MUTATION, variables: { entityType: ENTITY_TYPE } });
    const result = await queryAsAdminWithSuccess({
      query: CASE_INCIDENT_ADD_MUTATION,
      variables: { input: { name: `Closing reason case ${Date.now()}` } },
    });
    caseId = result.data.caseIncidentAdd.id;
    const statuses = await findByType(testContext, ADMIN_USER, ENTITY_TYPE);
    for (const state of ['open', 'closed', 'archived']) {
      statusIds[state] = statuses.find((status) => status.template_id === state)!.id;
    }
  });

  afterAll(async () => {
    await queryAsAdmin({ query: CASE_INCIDENT_DELETE_MUTATION, variables: { id: caseId } });
    await queryAsAdmin({ query: WORKFLOW_DEFINITION_DELETE_MUTATION, variables: { entityType: ENTITY_TYPE } });
  });

  it('should expose the closing reason mode on allowed transitions', async () => {
    const caseIncident = await readCase(caseId);
    expect(caseIncident.workflowInstance.currentState).toBe('open');
    expect(caseIncident.workflowInstance.allowedTransitions).toContainEqual({ event: 'close', closingReason: 'required' });
    expect(caseIncident.workflowInstance.allowedTransitions).toContainEqual({ event: 'triage', closingReason: null });
  });

  it('should reject closing without a required closing reason', async () => {
    const result = await trigger(caseId, 'close');
    expect(result).toMatchObject({ success: false, reason: 'A closing reason is required for this transition' });
    expect((await readCase(caseId)).workflowInstance.currentState).toBe('open');
  });

  it('should reject a closing reason that is not in the vocabulary', async () => {
    const result = await trigger(caseId, 'close', 'not-a-closing-reason');
    expect(result).toMatchObject({ success: false, reason: 'Closing reason must be a value of the closing reason vocabulary' });
    expect((await readCase(caseId)).workflowInstance.currentState).toBe('open');
  });

  it('should reject a closing reason on a transition that does not enable it', async () => {
    const result = await trigger(caseId, 'triage', 'duplicate');
    expect(result).toMatchObject({ success: false, reason: 'Closing reason is not enabled for this transition' });
    expect((await readCase(caseId)).workflowInstance.currentState).toBe('open');
  });

  it('should store the closing reason on the entity when closing', async () => {
    const result = await trigger(caseId, 'close', 'false-positive');
    expect(result).toMatchObject({ success: true, newState: 'closed' });
    expect((await readCase(caseId)).x_opencti_closing_reason).toBe('false-positive');
  });

  it('should find the entity by its closing reason', async () => {
    const result = await queryAsAdminWithSuccess({
      query: CASE_INCIDENTS_BY_CLOSING_REASON_QUERY,
      variables: {
        filters: {
          mode: 'and',
          filters: [{ key: ['x_opencti_closing_reason'], values: ['false-positive'] }],
          filterGroups: [],
        },
      },
    });
    expect(result.data.caseIncidents.edges.map(({ node }: { node: { id: string } }) => node.id)).toContain(caseId);
  });

  it('should clear the closing reason when a bypass moves the entity out of the final state', async () => {
    const result = await bypass(caseId, statusIds.open);
    expect(result).toMatchObject({ success: true, newState: 'open' });
    expect((await readCase(caseId)).x_opencti_closing_reason).toBeNull();
  });

  it('should keep the closing reason when a bypass moves the entity to another final state', async () => {
    await trigger(caseId, 'close', 'duplicate');
    const result = await bypass(caseId, statusIds.archived);
    expect(result).toMatchObject({ success: true, newState: 'archived' });
    expect((await readCase(caseId)).x_opencti_closing_reason).toBe('duplicate');
  });

  it('should reject a direct edit of the closing reason outside the workflow', async () => {
    await queryAsUserIsExpectedError(
      USER_EDITOR,
      { query: FIELD_PATCH_MUTATION, variables: { id: caseId, input: [{ key: 'x_opencti_closing_reason', value: ['other'] }] } },
      'Closing reason can only be changed through a workflow transition',
    );
    expect((await readCase(caseId)).x_opencti_closing_reason).toBe('duplicate');
  });

  it('should not copy the closing reason of a merged entity onto an open target', async () => {
    const target = await queryAsAdminWithSuccess({ query: CASE_INCIDENT_ADD_MUTATION, variables: { input: { name: `Closing reason merge target ${Date.now()}` } } });
    const targetId = target.data.caseIncidentAdd.id;
    const source = await queryAsAdminWithSuccess({ query: CASE_INCIDENT_ADD_MUTATION, variables: { input: { name: `Closing reason merge source ${Date.now()}` } } });
    const sourceId = source.data.caseIncidentAdd.id;
    await trigger(sourceId, 'close', 'false-positive');
    await queryAsAdminWithSuccess({ query: MERGE_MUTATION, variables: { id: targetId, stixObjectsIds: [sourceId] } });
    const merged = await readCase(targetId);
    expect(merged.workflowInstance.currentState).toBe('open');
    expect(merged.x_opencti_closing_reason).toBeNull();
    await queryAsAdmin({ query: CASE_INCIDENT_DELETE_MUTATION, variables: { id: targetId } });
  });

  it('should apply the closing reason rules to a status written outside the workflow', async () => {
    const created = await queryAsAdminWithSuccess({ query: CASE_INCIDENT_ADD_MUTATION, variables: { input: { name: `Closing reason status write ${Date.now()}` } } });
    const id = created.data.caseIncidentAdd.id;
    // A required reason cannot be skipped by writing the closed status
    await queryAsUserWithSuccess(USER_EDITOR, { query: FIELD_PATCH_MUTATION, variables: { id, input: [{ key: 'x_opencti_workflow_id', value: [statusIds.closed] }] } });
    expect((await readCase(id)).workflowInstance.currentState).toBe('open');
    // Reopening by writing the open status, which only a bypass user can do from a final state, clears the reason
    await trigger(id, 'close', 'duplicate');
    await queryAsAdminWithSuccess({ query: FIELD_PATCH_MUTATION, variables: { id, input: [{ key: 'x_opencti_workflow_id', value: [statusIds.open] }] } });
    const reopened = await readCase(id);
    expect(reopened.workflowInstance.currentState).toBe('open');
    expect(reopened.x_opencti_closing_reason).toBeNull();
    await queryAsAdmin({ query: CASE_INCIDENT_DELETE_MUTATION, variables: { id } });
  });

  it('should let a bypass user edit the closing reason directly', async () => {
    const result = await queryAsAdminWithSuccess({
      query: FIELD_PATCH_MUTATION,
      variables: { id: caseId, input: [{ key: 'x_opencti_closing_reason', value: ['other'] }] },
    });
    expect(result.data.stixDomainObjectEdit.fieldPatch.x_opencti_closing_reason).toBe('other');
  });
});
