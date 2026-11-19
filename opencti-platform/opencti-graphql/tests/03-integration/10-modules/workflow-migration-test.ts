import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { queryAsAdmin, queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { updateAttribute } from '../../../src/database/middleware';
import { wait } from '../../../src/database/utils';
import { createStatus, createStatusTemplate, statusTemplateDelete } from '../../../src/domain/status';
import { StatusScope } from '../../../src/generated/graphql';
import { ENTITY_TYPE_CONTAINER_OPINION } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../../../src/modules/case/case-incident/case-incident-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFT } from '../../../src/modules/case/case-rft/case-rft-types';
import { deleteWorkflowDefinition, getWorkflowConfig, hasPublishedWorkflowDefinition } from '../../../src/modules/workflow/domain/workflow-domain';
import { ENTITY_TYPE_WORKFLOW_DEFINITION } from '../../../src/modules/workflow/types/workflow-types';
import { migrateAllWorkflowDefinitions, type WorkflowMigrationResult } from '../../../src/modules/workflow/workflow-migration';

// Three types: one with legacy statuses and no workflow, one with legacy statuses and a draft-only
// workflow (the migration must not touch it), one with neither.
const MIGRATED_TYPE = ENTITY_TYPE_CONTAINER_CASE_RFT;
const DRAFT_ONLY_TYPE = ENTITY_TYPE_CONTAINER_CASE_INCIDENT;
const NO_STATUSES_TYPE = ENTITY_TYPE_CONTAINER_OPINION;
const OWN_TYPES = [MIGRATED_TYPE, DRAFT_ONLY_TYPE, NO_STATUSES_TYPE];

const WORKFLOW_DEFINITION_DELETE_MUTATION = gql`
  mutation WorkflowDefinitionDeleteForMigrationTest($entityType: String!) {
    workflowDefinitionDelete(entityType: $entityType) {
      id
    }
  }
`;
const WORKFLOW_MIGRATE_MUTATION = gql`
  mutation WorkflowMigrateForMigrationTest($entityType: String!, $publish: Boolean) {
    workflowMigrate(entityType: $entityType, publish: $publish) {
      workflow_id
      published
    }
  }
`;
const CASE_RFT_ADD_MUTATION = gql`
  mutation CaseRftAddForWorkflowMigrationTest($input: CaseRftAddInput!) {
    caseRftAdd(input: $input) {
      id
    }
  }
`;
const CASE_RFT_DELETE_MUTATION = gql`
  mutation CaseRftDeleteForWorkflowMigrationTest($id: ID!) {
    caseRftDelete(id: $id)
  }
`;

describe('Workflow definitions migration', () => {
  const suffix = Date.now();
  const templateIds: string[] = [];
  const migratedTemplateIds: string[] = [];
  const migratedStatusIds: string[] = [];
  // Every type the migration published during this suite, whichever the suite created
  const publishedByMigration: Array<{ entityType: string; scope: StatusScope }> = [];
  let caseId: string;
  let draftOnlyDefinitionId: string;
  let draftOnlyDraftVersionId: string;
  let firstRun: WorkflowMigrationResult[];

  const seedStatuses = async (entityType: string, label: string) => {
    const created: Array<{ templateId: string; statusId: string }> = [];
    for (const [index, name] of ['open', 'done'].entries()) {
      const template = await createStatusTemplate(testContext, ADMIN_USER, { name: `${label} ${name} ${suffix}`, color: '#000000' });
      templateIds.push(template.id);
      // Orders far below anything else on the type, so the first status is the initial state
      const status = await createStatus(testContext, ADMIN_USER, entityType, { template_id: template.id, order: -30 + index, scope: StatusScope.Global });
      created.push({ templateId: template.id, statusId: status.id });
    }
    return created;
  };
  const resultOf = (results: WorkflowMigrationResult[], entityType: string, scope = StatusScope.Global) => {
    return results.find((result) => result.entityType === entityType && result.scope === scope);
  };
  const loadDefinition = async (entityType: string) => {
    const setting = await getWorkflowConfig(testContext, ADMIN_USER, entityType);
    return storeLoadById<any>(testContext, ADMIN_USER, setting!.workflow_id!, ENTITY_TYPE_WORKFLOW_DEFINITION);
  };
  const removeWorkflows = async () => {
    for (const entityType of OWN_TYPES) {
      await queryAsAdmin({ query: WORKFLOW_DEFINITION_DELETE_MUTATION, variables: { entityType } });
    }
  };

  beforeAll(async () => {
    await removeWorkflows();
    const migrated = await seedStatuses(MIGRATED_TYPE, 'Migration');
    migratedTemplateIds.push(...migrated.map(({ templateId }) => templateId));
    migratedStatusIds.push(...migrated.map(({ statusId }) => statusId));
    await seedStatuses(DRAFT_ONLY_TYPE, 'Draft only');
    // A draft with no published version: what an administrator leaves after saving a workflow without publishing it
    await queryAsAdminWithSuccess({ query: WORKFLOW_MIGRATE_MUTATION, variables: { entityType: DRAFT_ONLY_TYPE, publish: false } });
    const draftOnly = await loadDefinition(DRAFT_ONLY_TYPE);
    draftOnlyDefinitionId = draftOnly.id;
    draftOnlyDraftVersionId = draftOnly.draft_version.id;
    // An entity on a legacy status. The status reaches the middleware cache asynchronously: retry the write until it lands.
    const created = await queryAsAdminWithSuccess({ query: CASE_RFT_ADD_MUTATION, variables: { input: { name: `Workflow migration case ${suffix}` } } });
    caseId = created.data.caseRftAdd.id;
    let stored: string | undefined;
    for (let attempt = 0; attempt < 20 && stored !== migratedStatusIds[1]; attempt += 1) {
      if (attempt > 0) await wait(500);
      await updateAttribute(testContext, ADMIN_USER, caseId, MIGRATED_TYPE, [{ key: 'x_opencti_workflow_id', value: [migratedStatusIds[1]] }]);
      stored = (await storeLoadById<any>(testContext, ADMIN_USER, caseId, MIGRATED_TYPE)).x_opencti_workflow_id;
    }
    expect(stored).toBe(migratedStatusIds[1]);
    firstRun = await migrateAllWorkflowDefinitions(testContext, ADMIN_USER);
    publishedByMigration.push(...firstRun.filter(({ outcome }) => outcome === 'migrated'));
  });

  afterAll(async () => {
    // Leave the other suites a platform without the workflows this one created
    for (const { entityType, scope } of publishedByMigration) {
      await deleteWorkflowDefinition(testContext, ADMIN_USER, entityType, scope).catch(() => undefined);
    }
    await removeWorkflows();
    if (caseId) {
      await queryAsAdmin({ query: CASE_RFT_DELETE_MUTATION, variables: { id: caseId } });
    }
    for (const templateId of templateIds) {
      await statusTemplateDelete(testContext, ADMIN_USER, templateId).catch(() => undefined);
    }
  });

  it('publishes the workflow of a type with legacy statuses', async () => {
    expect(resultOf(firstRun, MIGRATED_TYPE)).toEqual({ entityType: MIGRATED_TYPE, scope: StatusScope.Global, outcome: 'migrated' });
    expect(await hasPublishedWorkflowDefinition(testContext, ADMIN_USER, MIGRATED_TYPE)).toBe(true);
    const published = JSON.parse((await loadDefinition(MIGRATED_TYPE)).published_version.content);
    expect(published.states.map((state: any) => state.statusId)).toEqual(expect.arrayContaining(migratedTemplateIds));
  });

  it('leaves the entity on its legacy status', async () => {
    const entity = await storeLoadById<any>(testContext, ADMIN_USER, caseId, MIGRATED_TYPE);
    expect(entity.x_opencti_workflow_id).toBe(migratedStatusIds[1]);
  });

  it('creates no workflow for a type with no legacy statuses', async () => {
    expect(resultOf(firstRun, NO_STATUSES_TYPE)).toEqual({ entityType: NO_STATUSES_TYPE, scope: StatusScope.Global, outcome: 'no_statuses' });
    const setting = await getWorkflowConfig(testContext, ADMIN_USER, NO_STATUSES_TYPE);
    expect(setting?.workflow_id).toBeFalsy();
  });

  it('leaves a draft-only workflow untouched', async () => {
    expect(resultOf(firstRun, DRAFT_ONLY_TYPE)).toEqual({ entityType: DRAFT_ONLY_TYPE, scope: StatusScope.Global, outcome: 'has_workflow' });
    const definition = await loadDefinition(DRAFT_ONLY_TYPE);
    expect(definition.id).toBe(draftOnlyDefinitionId);
    expect(definition.draft_version.id).toBe(draftOnlyDraftVersionId);
    expect(definition.all_versions).toHaveLength(1);
    expect(definition.published_version).toBeFalsy();
    expect(await hasPublishedWorkflowDefinition(testContext, ADMIN_USER, DRAFT_ONLY_TYPE)).toBe(false);
  });

  it('never migrates DraftWorkspace', async () => {
    expect(firstRun.some(({ entityType }) => entityType === 'DraftWorkspace')).toBe(false);
  });

  it('is idempotent: a second run migrates nothing and keeps the published workflow', async () => {
    const before = await loadDefinition(MIGRATED_TYPE);
    const secondRun = await migrateAllWorkflowDefinitions(testContext, ADMIN_USER);
    expect(resultOf(secondRun, MIGRATED_TYPE)).toEqual({ entityType: MIGRATED_TYPE, scope: StatusScope.Global, outcome: 'has_workflow' });
    expect(resultOf(secondRun, DRAFT_ONLY_TYPE)?.outcome).toBe('has_workflow');
    // Case-Rfi REQUEST_ACCESS is left out of the failure check: it needs Enterprise Edition and fails on a Community Edition test platform
    expect(secondRun.filter(({ outcome }) => outcome === 'migrated')).toEqual([]);
    expect(secondRun.filter(({ outcome, scope }) => outcome === 'failed' && scope === StatusScope.Global)).toEqual([]);
    const after = await loadDefinition(MIGRATED_TYPE);
    expect(after.id).toBe(before.id);
    expect(after.published_version.id).toBe(before.published_version.id);
    expect(after.all_versions).toHaveLength(before.all_versions.length);
  });
});
