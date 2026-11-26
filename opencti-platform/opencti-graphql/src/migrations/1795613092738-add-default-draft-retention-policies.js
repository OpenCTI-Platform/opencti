import { logMigration } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { createRetentionRule, listRules } from '../modules/retentionRules/retentionRules-domain';

const message = '[MIGRATION] Add default draft retention policy';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');

  // Get all existing retention rules (no filters to avoid potential issues)
  const existingRules = await listRules(context, SYSTEM_USER, {});
  const existingScopes = existingRules.map((rule) => rule.scope);

  // Create draft retention rule if none exists
  if (!existingScopes.includes('draft')) {
    await createRetentionRule(context, SYSTEM_USER, {
      name: 'Draft retention',
      max_retention: 30,
      retention_unit: 'days',
      scope: 'draft',
      active: false,
    });
    logMigration.info(`${message} > Created draft retention rule (30 days for all drafts)`);
  } else {
    logMigration.info(`${message} > Draft retention rule already exists, skipping`);
  }

  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
