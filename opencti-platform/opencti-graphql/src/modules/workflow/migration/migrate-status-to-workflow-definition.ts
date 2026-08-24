import { logApp, logMigration } from '../../../config/conf';
import { FunctionalError } from '../../../config/errors';
import { fullEntitiesList } from '../../../database/middleware-loader';
import { FilterMode, StatusScope } from '../../../generated/graphql';
import { ENTITY_TYPE_STATUS, ENTITY_TYPE_STATUS_TEMPLATE } from '../../../schema/internalObject';
import type { BasicWorkflowStatus, BasicWorkflowTemplateEntity } from '../../../types/store';
import type { AuthContext, AuthUser } from '../../../types/user';
import { findByType as findEntitySettingByType } from '../../entitySetting/entitySetting-domain';
import { publishWorkflowDefinition, setWorkflowDefinition } from '../domain/workflow-domain';
import { convertStatusToDefinition } from './status-to-definition-converter';

export type MigrateEntityTypeStatusStatus = 'migrated' | 'skipped_no_data' | 'skipped_already_migrated';

export interface MigrateEntityTypeStatusResult {
  entityType: string;
  status: MigrateEntityTypeStatusStatus;
}

/**
 * Task 8: migrates one entity type's legacy `Status` set to a published `WorkflowDefinition`,
 * reusing `convertStatusToDefinition` for the pure conversion and
 * `setWorkflowDefinition`/`publishWorkflowDefinition` for validated, invariant-preserving
 * persistence (full-status-mapping is enforced by `publishWorkflowDefinition` itself).
 *
 * Scope-driven: `StatusScope.Global` (the default) migrates into `entitySetting.workflow_id`,
 * while `StatusScope.RequestAccess` migrates into
 * `entitySetting.request_access_workflow.workflow_definition_id` — each scope is checked and
 * persisted independently, using only that scope's `Status` data.
 *
 * Idempotent: a no-op if the entity type has no legacy `Status` data for the given scope, or
 * already has a workflow definition configured for that scope (either from a prior run of this
 * migration, or a hand-authored definition — this function never overwrites an existing
 * definition).
 */
export const migrateEntityTypeStatusToWorkflowDefinition = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  scope: StatusScope = StatusScope.Global,
): Promise<MigrateEntityTypeStatusResult> => {
  const entitySetting = await findEntitySettingByType(context, user, entityType);
  if (!entitySetting) {
    throw FunctionalError('Cannot migrate: no EntitySetting found for entity type', { entityType });
  }
  const existingId = scope === StatusScope.RequestAccess
    ? entitySetting.request_access_workflow?.workflow_definition_id
    : entitySetting.workflow_id;
  if (existingId) {
    logMigration.info(`[MIGRATION] workflow-definition-migration > ${entityType}: already has a WorkflowDefinition for scope ${scope}, skipping`);
    return { entityType, status: 'skipped_already_migrated' };
  }

  const statuses = await fullEntitiesList<BasicWorkflowStatus>(context, user, [ENTITY_TYPE_STATUS], {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['type'], values: [entityType] }],
      filterGroups: [],
    },
  });
  const templates = await fullEntitiesList<BasicWorkflowTemplateEntity>(context, user, [ENTITY_TYPE_STATUS_TEMPLATE]);
  const { byScope } = convertStatusToDefinition(statuses, templates);

  const scopeResult = byScope[scope];
  if (!scopeResult || scopeResult.definition.states.length === 0) {
    logMigration.info(`[MIGRATION] workflow-definition-migration > ${entityType}: no legacy Status data for scope ${scope}, skipping`);
    return { entityType, status: 'skipped_no_data' };
  }

  if (scopeResult.diagnostics.length > 0) {
    logApp.warn('[MIGRATION] workflow-definition-migration > conversion diagnostics', { entityType, scope, diagnostics: scopeResult.diagnostics });
  }

  await setWorkflowDefinition(context, user, entityType, JSON.stringify(scopeResult.definition), scope);
  await publishWorkflowDefinition(context, user, entityType, scope);

  return { entityType, status: 'migrated' };
};
