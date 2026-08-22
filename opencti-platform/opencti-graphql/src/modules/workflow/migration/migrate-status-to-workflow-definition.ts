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
 * Task 6, Step 3.1 (scoped to `GLOBAL` only, per explicit product decision — see Step 3.1's
 * `request_access` precondition below): migrates one entity type's legacy `Status` set to a
 * published `WorkflowDefinition`, reusing `convertStatusToDefinition` for the pure conversion and
 * `setWorkflowDefinition`/`publishWorkflowDefinition` for validated, invariant-preserving
 * persistence (full-status-mapping is enforced by `publishWorkflowDefinition` itself).
 *
 * Idempotent: a no-op if the entity type has no legacy `Status` data, or already has a
 * `workflow_id` configured (either from a prior run of this migration, or a hand-authored
 * definition — this function never overwrites an existing definition).
 *
 * `request_access` precondition (per plan.md Task 6 Step 3.1, product decision to scope this
 * migration to `GLOBAL` only until Task 7 lands): fails loudly, rather than silently dropping
 * data, if the entity type has any `request_access`-scoped `Status` data — routing that scope
 * requires `RequestAccessFlow.workflow_definition_id` (Task 7 Steps 1.1-1.3), which does not
 * exist yet.
 */
export const migrateEntityTypeStatusToWorkflowDefinition = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
): Promise<MigrateEntityTypeStatusResult> => {
  const entitySetting = await findEntitySettingByType(context, user, entityType);
  if (!entitySetting) {
    throw FunctionalError('Cannot migrate: no EntitySetting found for entity type', { entityType });
  }
  if (entitySetting.workflow_id) {
    logMigration.info(`[MIGRATION] workflow-definition-migration > ${entityType}: already has a WorkflowDefinition, skipping`);
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

  const requestAccessResult = byScope[StatusScope.RequestAccess];
  if (requestAccessResult && requestAccessResult.definition.states.length > 0) {
    throw FunctionalError(
      'Cannot migrate: entity type has request_access-scoped Status data, which requires Task 7 '
      + '(RequestAccessFlow.workflow_definition_id routing) to be implemented first. This migration '
      + 'is deliberately scoped to GLOBAL-only for now.',
      { entityType },
    );
  }

  const globalResult = byScope[StatusScope.Global];
  if (!globalResult || globalResult.definition.states.length === 0) {
    logMigration.info(`[MIGRATION] workflow-definition-migration > ${entityType}: no legacy Status data, skipping`);
    return { entityType, status: 'skipped_no_data' };
  }

  if (globalResult.diagnostics.length > 0) {
    logApp.warn('[MIGRATION] workflow-definition-migration > conversion diagnostics', { entityType, diagnostics: globalResult.diagnostics });
  }

  await setWorkflowDefinition(context, user, entityType, JSON.stringify(globalResult.definition));
  await publishWorkflowDefinition(context, user, entityType);

  return { entityType, status: 'migrated' };
};
