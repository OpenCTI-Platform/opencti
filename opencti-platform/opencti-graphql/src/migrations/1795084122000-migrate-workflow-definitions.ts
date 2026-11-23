import { logMigration } from '../config/conf';
import { logWorkflowMigrationSummary, migrateAllWorkflowDefinitions } from '../modules/workflow/workflow-migration';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Migrating the legacy statuses to published workflow definitions';

export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  try {
    // A single type failing is only logged: it keeps its legacy statuses. A global failure (the entity settings
    // cannot be listed) fails the migration, so it is replayed on the next start.
    const results = await migrateAllWorkflowDefinitions(context, SYSTEM_USER);
    logWorkflowMigrationSummary(results);
  } catch (error) {
    logMigration.error(`${message} > failed, it will be replayed on the next start`);
    next(error instanceof Error ? error : new Error(String(error)));
    return;
  }
  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
