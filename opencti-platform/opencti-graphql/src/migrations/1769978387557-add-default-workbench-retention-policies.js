import { logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { createRetentionRule, listRules } from '../domain/retentionRule';

const message = '[MIGRATION] Add default workbench retention policy';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');

  // Check if a retention rule for workbench scope already exists
  const existingRules = await listRules(context, SYSTEM_USER, { filters: { mode: 'and', filters: [{ key: 'scope', values: ['workbench'] }], filterGroups: [] } });
  const hasWorkbenchRule = existingRules.length > 0;

  // Create retention rule for all workbenches if it doesn't exist
  if (!hasWorkbenchRule) {
    await createRetentionRule(context, SYSTEM_USER, {
      name: 'All workbenches retention',
      max_retention: 30,
      retention_unit: 'days',
      scope: 'workbench',
    });
    logApp.info(`${message} > Created workbench retention rule (30 days for all workbenches)`);
  } else {
    logApp.info(`${message} > Workbench retention rule already exists, skipping`);
  }

  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
