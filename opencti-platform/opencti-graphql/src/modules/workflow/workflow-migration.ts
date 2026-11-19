import { logMigration } from '../../config/conf';
import { fullEntitiesList } from '../../database/middleware-loader';
import { StatusScope } from '../../generated/graphql';
import type { AuthContext, AuthUser } from '../../types/user';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../case/case-rfi/case-rfi-types';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../draftWorkspace/draftWorkspace-types';
import { type BasicStoreEntityEntitySetting, ENTITY_TYPE_ENTITY_SETTING } from '../entitySetting/entitySetting-types';
import { getAvailableSettings } from '../entitySetting/entitySetting-utils';
import { getWorkflowConfig, migrateWorkflowFromStatuses, resolveScopedDefinitionId } from './domain/workflow-domain';
import { NO_LEGACY_STATUSES_MESSAGE } from './migration/status-to-definition-converter';

export type WorkflowMigrationOutcome = 'migrated' | 'has_workflow' | 'no_statuses' | 'failed';

export type WorkflowMigrationResult = {
  entityType: string;
  scope: StatusScope;
  outcome: WorkflowMigrationOutcome;
  // Set when the outcome is `failed`
  reason?: string;
};

const OUTCOMES: WorkflowMigrationOutcome[] = ['migrated', 'has_workflow', 'no_statuses', 'failed'];

// Entity settings exist for every entity type, but only some of them hold a workflow.
const hasWorkflowSetting = (entityType: string): boolean => {
  try {
    return getAvailableSettings(entityType).includes('workflow_id');
  } catch (_error) {
    return false;
  }
};

const migrateScope = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  scope: StatusScope,
): Promise<WorkflowMigrationResult> => {
  try {
    // A workflow, draft or published, is never replaced: it may be one an administrator built or kept on purpose.
    // The migration function refuses to overwrite as well (overwrite = false), this check only avoids taking its lock.
    const entitySetting = await getWorkflowConfig(context, user, entityType);
    if (resolveScopedDefinitionId(entitySetting, scope)) {
      return { entityType, scope, outcome: 'has_workflow' };
    }
    await migrateWorkflowFromStatuses(context, user, entityType, true, false, scope);
    return { entityType, scope, outcome: 'migrated' };
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    if (reason === NO_LEGACY_STATUSES_MESSAGE) {
      return { entityType, scope, outcome: 'no_statuses' };
    }
    // Enterprise Edition refusals and lock failures end up here too: the type stays on its legacy statuses.
    return { entityType, scope, outcome: 'failed', reason };
  }
};

/**
 * Migrates, for each entity type that has a workflow setting, its legacy statuses into a published workflow
 * definition: the GLOBAL scope, plus the REQUEST_ACCESS scope for Case-Rfi. Never throws for a single type,
 * so one failing type does not stop the others nor the platform startup: every outcome is returned.
 */
export const migrateAllWorkflowDefinitions = async (context: AuthContext, user: AuthUser): Promise<WorkflowMigrationResult[]> => {
  const entitySettings = await fullEntitiesList<BasicStoreEntityEntitySetting>(context, user, [ENTITY_TYPE_ENTITY_SETTING]);
  const results: WorkflowMigrationResult[] = [];
  for (const { target_type: entityType } of entitySettings) {
    // The workflow of a draft must contain a validateDraft action, a migrated one never has it
    if (entityType === ENTITY_TYPE_DRAFT_WORKSPACE || !hasWorkflowSetting(entityType)) continue;
    results.push(await migrateScope(context, user, entityType, StatusScope.Global));
    if (entityType === ENTITY_TYPE_CONTAINER_CASE_RFI) {
      results.push(await migrateScope(context, user, entityType, StatusScope.RequestAccess));
    }
  }
  return results;
};

export const logWorkflowMigrationSummary = (results: WorkflowMigrationResult[]): void => {
  const counts = OUTCOMES.map((outcome) => `${outcome}=${results.filter((result) => result.outcome === outcome).length}`);
  logMigration.info(`[MIGRATION] Workflow definitions > ${counts.join(', ')}`);
  const failed = results.filter((result) => result.outcome === 'failed');
  if (failed.length === 0) return;
  const failures = failed.map((result) => `${result.entityType} (${result.scope}): ${result.reason}`).join('; ');
  // A failed request access scope leaves requests with no flow to run: it is more serious than a type kept on legacy statuses
  if (failed.some((result) => result.scope === StatusScope.RequestAccess)) {
    logMigration.error(`[MIGRATION] Workflow definitions not migrated, including a request access workflow: ${failures}`);
  } else {
    logMigration.warn(`[MIGRATION] Workflow definitions not migrated: ${failures}`);
  }
};
