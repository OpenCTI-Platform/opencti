import { logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { createRetentionRule, listRules } from '../domain/retentionRule';

const message = '[MIGRATION] Add default file and workbench retention policies';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');

  // Check if a retention rule for file scope already exists
  const existingFileRules = await listRules(context, SYSTEM_USER, { filters: { mode: 'and', filters: [{ key: 'scope', values: ['file'] }], filterGroups: [] } });
  if (existingFileRules.length === 0) {
    await createRetentionRule(context, SYSTEM_USER, {
      name: 'Global files retention',
      max_retention: 30,
      retention_unit: 'days',
      scope: 'file',
    });
    logApp.info(`${message} > Created file retention rule (30 days for global files)`);
  } else {
    logApp.info(`${message} > File retention rule already exists, skipping`);
  }

  // Check if a retention rule for workbench scope already exists
  const existingWorkbenchRules = await listRules(context, SYSTEM_USER, { filters: { mode: 'and', filters: [{ key: 'scope', values: ['workbench'] }], filterGroups: [] } });
  if (existingWorkbenchRules.length === 0) {
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
