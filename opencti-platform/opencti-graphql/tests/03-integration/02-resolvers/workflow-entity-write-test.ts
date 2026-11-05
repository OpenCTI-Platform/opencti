import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { ADMIN_USER, buildStandardUser, testContext, USER_EDITOR } from '../../utils/testQuery';
import { getAllowedTransitions, triggerWorkflowEvent } from '../../../src/modules/workflow/domain/workflow-domain';
import { resolveMappedStatusId } from '../../../src/modules/workflow/domain/workflow-projection';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { StatusScope } from '../../../src/generated/graphql';
import type { BasicStoreEntity } from '../../../src/types/store';

// A transition writes the new status onto the entity with the triggering user's rights.
// It must not report success with a moved instance while that write fails.
const ENTITY_TYPE = 'Report';

const WORKFLOW_DEFINITION_SET_MUTATION = gql`
  mutation WorkflowEntityWriteDefinitionSet($entityType: String!, $definition: String!) {
    workflowDefinitionSet(entityType: $entityType, definition: $definition) {
      id
    }
  }
`;

const WORKFLOW_DEFINITION_PUBLISH_MUTATION = gql`
  mutation WorkflowEntityWriteDefinitionPublish($entityType: String!) {
    workflowDefinitionPublish(entityType: $entityType) {
      id
    }
  }
`;

const WORKFLOW_DEFINITION_DELETE_MUTATION = gql`
  mutation WorkflowEntityWriteDefinitionDelete($entityType: String!) {
    workflowDefinitionDelete(entityType: $entityType) {
      id
    }
  }
`;

const TRIGGER_MUTATION = gql`
  mutation WorkflowEntityWriteTrigger($entityId: String!, $eventName: String!) {
    triggerWorkflowEvent(entityId: $entityId, eventName: $eventName) {
      success
      newState
      reason
    }
  }
`;

const REPORT_ADD_MUTATION = gql`
  mutation WorkflowEntityWriteReportAdd($input: ReportAddInput!) {
    reportAdd(input: $input) {
      id
    }
  }
`;

const REPORT_DELETE_MUTATION = gql`
  mutation WorkflowEntityWriteReportDelete($id: ID!) {
    reportEdit(id: $id) {
      delete
    }
  }
`;

const REPORT_STATUS_QUERY = gql`
  query WorkflowEntityWriteReportStatus($id: String!) {
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

const ENTITY_SETTING_QUERY = gql`
  query WorkflowEntityWriteEntitySetting($targetType: String!) {
    entitySettingByType(targetType: $targetType) {
      id
    }
  }
`;

const ENTITY_SETTING_PATCH_MUTATION = gql`
  mutation WorkflowEntityWriteEntitySettingPatch($ids: [ID!]!, $input: [EditInput!]!) {
    entitySettingsFieldPatch(ids: $ids, input: $input) {
      id
    }
  }
`;

const definition = JSON.stringify({
  id: 'entity-write-workflow',
  name: 'Entity write workflow',
  initialState: 'open',
  states: [{ statusId: 'open' }, { statusId: 'validated' }],
  transitions: [{ from: 'open', to: 'validated', event: 'validate_event' }],
});

const addReport = async (confidence: number) => {
  const result = await queryAsAdminWithSuccess({
    query: REPORT_ADD_MUTATION,
    variables: { input: { name: `Workflow entity write ${confidence} ${Date.now()}`, published: new Date().toISOString(), confidence } },
  });
  return result.data.reportAdd.id as string;
};

const readReport = async (id: string) => {
  const result = await queryAsAdminWithSuccess({ query: REPORT_STATUS_QUERY, variables: { id } });
  return { state: result.data.report.workflowInstance.currentState, status: result.data.report.status?.id };
};

describe('Workflow transition and the entity status write', () => {
  const reportIds: string[] = [];
  let entitySettingId: string;

  beforeAll(async () => {
    await queryAsAdmin({ query: WORKFLOW_DEFINITION_DELETE_MUTATION, variables: { entityType: ENTITY_TYPE } });
    await queryAsAdminWithSuccess({ query: WORKFLOW_DEFINITION_SET_MUTATION, variables: { entityType: ENTITY_TYPE, definition } });
    await queryAsAdminWithSuccess({ query: WORKFLOW_DEFINITION_PUBLISH_MUTATION, variables: { entityType: ENTITY_TYPE } });
    const setting = await queryAsAdminWithSuccess({ query: ENTITY_SETTING_QUERY, variables: { targetType: ENTITY_TYPE } });
    entitySettingId = setting.data.entitySettingByType.id;
  });

  afterAll(async () => {
    await queryAsAdmin({ query: ENTITY_SETTING_PATCH_MUTATION, variables: { ids: [entitySettingId], input: [{ key: 'enforce_reference', value: ['false'] }] } });
    await queryAsAdmin({ query: WORKFLOW_DEFINITION_DELETE_MUTATION, variables: { entityType: ENTITY_TYPE } });
    for (let index = 0; index < reportIds.length; index += 1) {
      await queryAsAdmin({ query: REPORT_DELETE_MUTATION, variables: { id: reportIds[index] } });
    }
  });

  it('refuses a transition when the user confidence level is below the entity one', async () => {
    const reportId = await addReport(90);
    reportIds.push(reportId);
    const before = await readReport(reportId);

    const lowConfidenceUser = buildStandardUser([], [], [{ name: 'KNOWLEDGE_KNUPDATE' }], 50);
    expect(await getAllowedTransitions(testContext, lowConfidenceUser, reportId)).toEqual([]);

    const result = await triggerWorkflowEvent(testContext, lowConfidenceUser, reportId, 'validate_event');

    expect(result).toMatchObject({ success: false, reason: 'Your confidence level is too low to update this entity' });
    expect(await readReport(reportId)).toEqual(before);
  });

  it('writes the status of a transition when the entity type enforces references', async () => {
    const reportId = await addReport(50);
    reportIds.push(reportId);
    const before = await readReport(reportId);
    await queryAsAdminWithSuccess({ query: ENTITY_SETTING_PATCH_MUTATION, variables: { ids: [entitySettingId], input: [{ key: 'enforce_reference', value: ['true'] }] } });

    // USER_EDITOR has no KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE: the transition stands for the references
    const result = await queryAsUserWithSuccess(USER_EDITOR, { query: TRIGGER_MUTATION, variables: { entityId: reportId, eventName: 'validate_event' } });

    expect(result.data.triggerWorkflowEvent).toMatchObject({ success: true, newState: 'validated' });
    // Read the store directly: reading the workflow instance may run read-repair, which writes the status itself
    const report = await storeLoadById<BasicStoreEntity>(testContext, ADMIN_USER, reportId, ENTITY_TYPE);
    const validatedStatusId = await resolveMappedStatusId(testContext, ADMIN_USER, ENTITY_TYPE, StatusScope.Global, 'validated');
    expect(validatedStatusId).not.toBe(before.status);
    expect(report.x_opencti_workflow_id).toBe(validatedStatusId);
  });
});
