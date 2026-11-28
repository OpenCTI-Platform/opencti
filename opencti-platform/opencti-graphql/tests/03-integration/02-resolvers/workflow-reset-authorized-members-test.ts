import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import * as ee from '../../../src/enterprise-edition/ee';
import { ADMIN_USER } from '../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithSuccess } from '../../utils/testQueryHelper';

const WORKFLOW_DEFINITION_SET_MUTATION = gql`
  mutation WorkflowDefinitionSet($entityType: String!, $definition: String!) {
    workflowDefinitionSet(entityType: $entityType, definition: $definition) { id }
  }
`;
const WORKFLOW_DEFINITION_PUBLISH_MUTATION = gql`
  mutation WorkflowDefinitionPublish($entityType: String!) {
    workflowDefinitionPublish(entityType: $entityType) { id }
  }
`;
const WORKFLOW_DEFINITION_DELETE_MUTATION = gql`
  mutation WorkflowDefinitionDelete($entityType: String!) {
    workflowDefinitionDelete(entityType: $entityType) { id }
  }
`;
const TRIGGER_WORKFLOW_EVENT_MUTATION = gql`
  mutation TriggerWorkflowEvent($entityId: String!, $eventName: String!) {
    triggerWorkflowEvent(entityId: $entityId, eventName: $eventName) {
      success
      newState
      reason
      entity { id ... on Report { authorized_members { member_id } } }
    }
  }
`;
const REPORT_ADD_MUTATION = gql`
  mutation ReportAddForResetAuthorizedMembers($input: ReportAddInput!) {
    reportAdd(input: $input) { id }
  }
`;
const REPORT_EDIT_AUTHORIZED_MEMBERS_MUTATION = gql`
  mutation ReportEditAuthorizedMembers($id: ID!, $input: [MemberAccessInput!]) {
    containerEdit(id: $id) {
      editAuthorizedMembers(input: $input) { id }
    }
  }
`;
const REPORT_AUTHORIZED_MEMBERS_QUERY = gql`
  query ReportAuthorizedMembers($id: String!) {
    report(id: $id) {
      authorized_members { member_id access_right }
    }
  }
`;
const REPORT_DELETE_MUTATION = gql`
  mutation ReportDeleteForResetAuthorizedMembers($id: ID!) {
    reportEdit(id: $id) { delete }
  }
`;

describe('Workflow resetAuthorizedMembers transition action (Report)', () => {
  let reportId: string;

  beforeAll(async () => {
    vi.spyOn(ee, 'checkEnterpriseEdition').mockResolvedValue();
    await queryAsAdmin({ query: WORKFLOW_DEFINITION_DELETE_MUTATION, variables: { entityType: 'Report' } });
    await queryAsAdminWithSuccess({
      query: WORKFLOW_DEFINITION_SET_MUTATION,
      variables: {
        entityType: 'Report',
        definition: JSON.stringify({
          id: 'report-reset-authorized-members',
          name: 'Report reset authorized members',
          initialState: 'open',
          states: [{ statusId: 'open' }, { statusId: 'validated' }],
          transitions: [{ from: 'open', to: 'validated', event: 'release_event', syncActions: [{ type: 'resetAuthorizedMembers' }] }],
        }),
      },
    });
    await queryAsAdminWithSuccess({ query: WORKFLOW_DEFINITION_PUBLISH_MUTATION, variables: { entityType: 'Report' } });
    // Created once the workflow is published, so its only status write is the transition one (counted in syncCountHelper)
    const report = await queryAsAdminWithSuccess({
      query: REPORT_ADD_MUTATION,
      variables: { input: { name: `Reset authorized members report ${Date.now()}`, published: new Date().toISOString() } },
    });
    reportId = report.data.reportAdd.id;
    await queryAsAdminWithSuccess({
      query: REPORT_EDIT_AUTHORIZED_MEMBERS_MUTATION,
      variables: { id: reportId, input: [{ id: ADMIN_USER.id, access_right: 'admin' }] },
    });
  });

  afterAll(async () => {
    await queryAsAdmin({ query: WORKFLOW_DEFINITION_DELETE_MUTATION, variables: { entityType: 'Report' } });
    await queryAsAdmin({ query: REPORT_DELETE_MUTATION, variables: { id: reportId } });
    vi.restoreAllMocks();
  });

  it('should remove the access restriction when the transition runs', async () => {
    const before = await queryAsAdminWithSuccess({ query: REPORT_AUTHORIZED_MEMBERS_QUERY, variables: { id: reportId } });
    expect(before.data.report.authorized_members).toEqual([{ member_id: ADMIN_USER.id, access_right: 'admin' }]);

    const trigger = await queryAsAdminWithSuccess({
      query: TRIGGER_WORKFLOW_EVENT_MUTATION,
      variables: { entityId: reportId, eventName: 'release_event' },
    });
    expect(trigger.data.triggerWorkflowEvent.reason).toBeNull();
    expect(trigger.data.triggerWorkflowEvent.success).toBe(true);
    expect(trigger.data.triggerWorkflowEvent.newState).toBe('validated');
    // The payload carries the entity as the sync actions left it, so the UI drops the restriction at once
    expect(trigger.data.triggerWorkflowEvent.entity.id).toBe(reportId);
    expect(trigger.data.triggerWorkflowEvent.entity.authorized_members ?? []).toEqual([]);

    const after = await queryAsAdminWithSuccess({ query: REPORT_AUTHORIZED_MEMBERS_QUERY, variables: { id: reportId } });
    expect(after.data.report.authorized_members ?? []).toEqual([]);
  });
});
