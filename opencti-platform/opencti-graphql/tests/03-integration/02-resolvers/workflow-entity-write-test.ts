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

const DRAFT_WORKSPACE_ADD_MUTATION = gql`
  mutation WorkflowEntityWriteDraftAdd($input: DraftWorkspaceAddInput!) {
    draftWorkspaceAdd(input: $input) {
      id
    }
  }
`;

const DRAFT_WORKSPACE_DELETE_MUTATION = gql`
  mutation WorkflowEntityWriteDraftDelete($id: ID!) {
    draftWorkspaceDelete(id: $id)
  }
`;

const REPORT_CONFIDENCE_PATCH_MUTATION = gql`
  mutation WorkflowEntityWriteReportConfidencePatch($id: ID!, $input: [EditInput]!) {
    reportEdit(id: $id) {
      fieldPatch(input: $input) {
        id
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

const addDraft = async (draftIds: string[]) => {
  const result = await queryAsAdminWithSuccess({ query: DRAFT_WORKSPACE_ADD_MUTATION, variables: { input: { name: `Workflow entity write draft ${Date.now()}` } } });
  const draftId = result.data.draftWorkspaceAdd.id as string;
  draftIds.push(draftId);
  return draftId;
};

const readReport = async (id: string) => {
  const result = await queryAsAdminWithSuccess({ query: REPORT_STATUS_QUERY, variables: { id } });
  return { state: result.data.report.workflowInstance.currentState, status: result.data.report.status?.id };
};

describe('Workflow transition and the entity status write', () => {
  const reportIds: string[] = [];
  const draftIds: string[] = [];
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
    for (let index = 0; index < draftIds.length; index += 1) {
      await queryAsAdmin({ query: DRAFT_WORKSPACE_DELETE_MUTATION, variables: { id: draftIds[index] } });
    }
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

  it('refuses a transition on an entity created inside a draft, which has no live version to write the status on', async () => {
    const draftId = await addDraft(draftIds);
    const created = await queryAsAdmin({
      query: REPORT_ADD_MUTATION,
      variables: { input: { name: `Workflow entity write in draft ${Date.now()}`, published: new Date().toISOString() } },
    }, draftId);
    expect(created.errors).toBeUndefined();
    const draftReportId = created.data?.reportAdd.id as string;
    const draftContext = { ...testContext, draft_context: draftId };

    expect(await getAllowedTransitions(draftContext, ADMIN_USER, draftReportId)).toEqual([]);
    const result = await triggerWorkflowEvent(draftContext, ADMIN_USER, draftReportId, 'validate_event');

    expect(result).toMatchObject({ success: false, reason: 'This entity has no live version to write the workflow status on' });
  });

  it('checks the confidence level against the live entity, not its draft copy, when triggered from a draft', async () => {
    // Live entity at 90, draft copy at 50: the status is written on the live one
    const reportId = await addReport(90);
    reportIds.push(reportId);
    const draftId = await addDraft(draftIds);
    const patched = await queryAsAdmin({ query: REPORT_CONFIDENCE_PATCH_MUTATION, variables: { id: reportId, input: [{ key: 'confidence', value: ['50'] }] } }, draftId);
    expect(patched.errors).toBeUndefined();
    const draftContext = { ...testContext, draft_context: draftId };
    const lowConfidenceUser = buildStandardUser([], [], [{ name: 'KNOWLEDGE_KNUPDATE' }], 50);

    // Control: a user above the live confidence level can take the transition from the draft
    const adminTransitions = await getAllowedTransitions(draftContext, ADMIN_USER, reportId);
    expect(adminTransitions.map((transition) => transition.event)).toEqual(['validate_event']);

    expect(await getAllowedTransitions(draftContext, lowConfidenceUser, reportId)).toEqual([]);
    const result = await triggerWorkflowEvent(draftContext, lowConfidenceUser, reportId, 'validate_event');
    expect(result).toMatchObject({ success: false, reason: 'Your confidence level is too low to update this entity' });
  });
});
