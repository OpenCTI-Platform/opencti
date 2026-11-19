import { logMigration } from '../config/conf';
import { logWorkflowMigrationSummary, migrateAllWorkflowDefinitions } from '../modules/workflow/workflow-migration';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Migrating the legacy statuses to published workflow definitions';

export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  try {
    const results = await migrateAllWorkflowDefinitions(context, SYSTEM_USER);
    logWorkflowMigrationSummary(results);
  } catch (error) {
    // The legacy statuses are left as they are, so the platform starts anyway. An administrator can migrate
    // an entity type later with the workflowMigrate mutation.
    logMigration.error(`${message} > failed, no workflow definition was migrated: ${error instanceof Error ? error.message : String(error)}`);
  }
  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
