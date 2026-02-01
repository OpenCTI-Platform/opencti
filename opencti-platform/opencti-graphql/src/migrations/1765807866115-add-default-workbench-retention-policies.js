import { logApp, logMigration } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { createRetentionRule, listRules } from '../domain/retentionRule';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';

const message = '[MIGRATION] Add default file and workbench retention policies';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');

  // Fix existing retention rules missing base_type and parent_types
  const fixMessage = '[MIGRATION] Fix retention rules missing base_type and parent_types';
  logMigration.info(`${fixMessage} > started`);
  const updateQuery = {
    script: {
      source: `
        ctx._source.base_type = 'ENTITY';
        ctx._source.parent_types = ['Basic-Object', 'Internal-Object'];
      `,
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'RetentionRule' } } },
        ],
        should: [
          { bool: { must_not: [{ exists: { field: 'base_type' } }] } },
          { bool: { must_not: [{ exists: { field: 'parent_types' } }] } },
        ],
        minimum_should_match: 1,
      },
    },
  };
  await elUpdateByQueryForMigration(fixMessage, READ_INDEX_INTERNAL_OBJECTS, updateQuery);

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
