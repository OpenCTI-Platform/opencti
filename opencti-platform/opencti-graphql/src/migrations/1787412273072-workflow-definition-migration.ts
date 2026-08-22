import nconf from 'nconf';
import { logMigration } from '../config/conf';
import { migrateEntityTypeStatusToWorkflowDefinition } from '../modules/workflow/migration/migrate-status-to-workflow-definition';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] workflow-definition-migration (Status -> WorkflowDefinition, canary opt-in)';

export const up = async (next: (error?: Error) => void) => {
  const context = executionContext('migration');
  logMigration.info(`${message} > started`);

  // Deliberately empty by default (per plan.md Task 6, Step 3.3): this migration activates
  // backend workflow mechanics for an entity type immediately (regardless of the ENTITIES_WORKFLOW
  // UI flag), so it must be rolled out per entity type as an explicit canary, never in bulk.
  // Add an entity type to this list only after reviewing the canary rollout guidance (monitor
  // read-repair metrics and stream event volume for one type before adding the next).
  const entityTypes: string[] = nconf.get('app:workflow_definition_migration:entity_types') ?? [];
  if (entityTypes.length === 0) {
    logMigration.info(`${message} > no entity types configured (app:workflow_definition_migration:entity_types), skipping`);
    next();
    return;
  }

  for (let i = 0; i < entityTypes.length; i += 1) {
    const entityType = entityTypes[i];
    logMigration.info(`${message} > migrating ${entityType} (${i + 1}/${entityTypes.length})`);
    const result = await migrateEntityTypeStatusToWorkflowDefinition(context, SYSTEM_USER, entityType);
    logMigration.info(`${message} > ${entityType}: ${result.status}`);
  }

  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
