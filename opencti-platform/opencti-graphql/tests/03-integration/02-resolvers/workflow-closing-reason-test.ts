import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { USER_EDITOR } from '../../utils/testQuery';

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
  states: [{ statusId: 'open' }, { statusId: 'closed' }, { statusId: 'archived' }],
  transitions: [
    { from: 'open', to: 'closed', event: 'close', closingReason: 'required' },
    { from: 'closed', to: 'open', event: 'reopen' },
    { from: 'closed', to: 'archived', event: 'archive' },
  ],
});

// The editor cannot bypass mandatory fields, unlike the admin
const trigger = async (entityId: string, eventName: string, closingReason?: string) => {
  const result = await queryAsUserWithSuccess(USER_EDITOR, { query: TRIGGER_MUTATION, variables: { entityId, eventName, closingReason } });
  return result.data.triggerWorkflowEvent;
};

const readCase = async (id: string) => {
  const result = await queryAsAdminWithSuccess({ query: CASE_INCIDENT_QUERY, variables: { id } });
  return result.data.caseIncident;
};

describe('Workflow closing reason (Case-Incident)', () => {
  let caseId: string;

  beforeAll(async () => {
    await queryAsAdmin({ query: WORKFLOW_DEFINITION_DELETE_MUTATION, variables: { entityType: ENTITY_TYPE } });
    await queryAsAdminWithSuccess({ query: WORKFLOW_DEFINITION_SET_MUTATION, variables: { entityType: ENTITY_TYPE, definition } });
    await queryAsAdminWithSuccess({ query: WORKFLOW_DEFINITION_PUBLISH_MUTATION, variables: { entityType: ENTITY_TYPE } });
    const result = await queryAsAdminWithSuccess({
      query: CASE_INCIDENT_ADD_MUTATION,
      variables: { input: { name: `Closing reason case ${Date.now()}` } },
    });
    caseId = result.data.caseIncidentAdd.id;
  });

  afterAll(async () => {
    await queryAsAdmin({ query: CASE_INCIDENT_DELETE_MUTATION, variables: { id: caseId } });
    await queryAsAdmin({ query: WORKFLOW_DEFINITION_DELETE_MUTATION, variables: { entityType: ENTITY_TYPE } });
  });

  it('should expose the closing reason mode on allowed transitions', async () => {
    const caseIncident = await readCase(caseId);
    expect(caseIncident.workflowInstance.currentState).toBe('open');
    expect(caseIncident.workflowInstance.allowedTransitions).toEqual([{ event: 'close', closingReason: 'required' }]);
  });

  it('should reject closing without a required closing reason', async () => {
    const result = await trigger(caseId, 'close');
    expect(result).toMatchObject({ success: false, reason: 'A closing reason is required for this transition' });
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

  it('should reject a closing reason on a transition that does not enable it', async () => {
    const result = await trigger(caseId, 'reopen', 'duplicate');
    expect(result).toMatchObject({ success: false, reason: 'Closing reason is not enabled for this transition' });
    expect((await readCase(caseId)).x_opencti_closing_reason).toBe('false-positive');
  });

  it('should clear the closing reason when leaving the closing state', async () => {
    const result = await trigger(caseId, 'reopen');
    expect(result).toMatchObject({ success: true, newState: 'open' });
    expect((await readCase(caseId)).x_opencti_closing_reason).toBeNull();
  });
});
