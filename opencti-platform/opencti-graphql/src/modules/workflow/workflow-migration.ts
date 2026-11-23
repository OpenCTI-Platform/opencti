import { logMigration } from '../../config/conf';
import { ENTERPRISE_EDITION_REQUIRED_MESSAGE } from '../../enterprise-edition/ee';
import { fullEntitiesList } from '../../database/middleware-loader';
import { StatusScope } from '../../generated/graphql';
import { ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import type { AuthContext, AuthUser } from '../../types/user';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../case/case-rfi/case-rfi-types';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../draftWorkspace/draftWorkspace-types';
import { type BasicStoreEntityEntitySetting, ENTITY_TYPE_ENTITY_SETTING } from '../entitySetting/entitySetting-types';
import { getAvailableSettings } from '../entitySetting/entitySetting-utils';
import { getWorkflowConfig, migrateWorkflowFromStatuses, resolveScopedDefinitionId } from './domain/workflow-domain';
import { NO_LEGACY_STATUSES_MESSAGE } from './migration/status-to-definition-converter';

// `enterprise_only`: the migrated definition needs Enterprise Edition (e.g. the shareRequestedEntities action of REQUEST_ACCESS)
export type WorkflowMigrationOutcome = 'migrated' | 'has_workflow' | 'no_statuses' | 'enterprise_only' | 'failed';

export type WorkflowMigrationResult = {
  entityType: string;
  scope: StatusScope;
  outcome: WorkflowMigrationOutcome;
  // Set when the outcome is `failed` or `enterprise_only`
  reason?: string;
};

const OUTCOMES: WorkflowMigrationOutcome[] = ['migrated', 'has_workflow', 'no_statuses', 'enterprise_only', 'failed'];

const SKIPPED_ENTITY_TYPES = new Set<string>([
  // The workflow of a draft must contain a validateDraft action, a migrated one never has it
  ENTITY_TYPE_DRAFT_WORKSPACE,
  // Abstract relationship settings are only inherited defaults: the engine resolves the workflow of the concrete
  // relationship type (exact lookup), so a definition published here is never used, and it would make the
  // relationship edition forms read-only
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  STIX_SIGHTING_RELATIONSHIP,
]);

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
    // Expected on Community Edition, not a failure: the type stays on its legacy statuses
    if (reason === ENTERPRISE_EDITION_REQUIRED_MESSAGE) {
      return { entityType, scope, outcome: 'enterprise_only', reason };
    }
    // Lock failures end up here too: the type stays on its legacy statuses.
    return { entityType, scope, outcome: 'failed', reason };
  }
};

/**
 * Migrates, for each entity type that has a workflow setting, its legacy statuses into a published workflow
 * definition: the GLOBAL scope, plus the REQUEST_ACCESS scope for Case-Rfi. Never throws for a single type,
 * so one failing type does not stop the others: every outcome is returned. Throws when the types cannot be listed.
 */
export const migrateAllWorkflowDefinitions = async (context: AuthContext, user: AuthUser): Promise<WorkflowMigrationResult[]> => {
  const entitySettings = await fullEntitiesList<BasicStoreEntityEntitySetting>(context, user, [ENTITY_TYPE_ENTITY_SETTING]);
  const results: WorkflowMigrationResult[] = [];
  for (const { target_type: entityType } of entitySettings) {
    if (SKIPPED_ENTITY_TYPES.has(entityType) || !hasWorkflowSetting(entityType)) continue;
    results.push(await migrateScope(context, user, entityType, StatusScope.Global));
    if (entityType === ENTITY_TYPE_CONTAINER_CASE_RFI) {
      results.push(await migrateScope(context, user, entityType, StatusScope.RequestAccess));
    }
  }
  return results;
};

export const logWorkflowMigrationSummary = (results: WorkflowMigrationResult[]): void => {
  const counts = OUTCOMES.map((outcome) => `${outcome}=${results.filter((result) => result.outcome === outcome).length}`);
  logMigration.info(`[MIGRATION] Workflow definitions (counted per type and scope) > ${counts.join(', ')}`);
  const enterpriseOnly = results.filter((result) => result.outcome === 'enterprise_only');
  if (enterpriseOnly.length > 0) {
    const skipped = enterpriseOnly.map((result) => `${result.entityType} (${result.scope})`).join(', ');
    logMigration.info(`[MIGRATION] Workflow definitions skipped, they need Enterprise Edition: ${skipped} | They keep their legacy statuses`);
  }
  const failed = results.filter((result) => result.outcome === 'failed');
  if (failed.length === 0) return;
  const failures = failed.map((result) => `${result.entityType} (${result.scope}): ${result.reason}`).join('; ');
  // Requests keep running on the legacy request access flow while no REQUEST_ACCESS definition is published,
  // so a failed scope is not fatal: it stays on its legacy statuses until an administrator retries the migration
  const requestAccessNote = failed.some((result) => result.scope === StatusScope.RequestAccess)
    ? ' | The request access flow keeps running on its legacy statuses until an administrator retries through the migrateWorkflowFromStatuses mutation'
    : '';
  logMigration.warn(`[MIGRATION] Workflow definitions not migrated: ${failures}${requestAccessNote}`);
};
