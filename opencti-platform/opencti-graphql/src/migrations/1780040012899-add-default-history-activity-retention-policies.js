import { logMigration } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { createRetentionRule, listRules } from '../modules/retentionRules/retentionRules-domain';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';

const message = '[MIGRATION] Add default history and activity retention policies';

const DEFAULT_RULE_NAMES = [
  'Global files retention',
  'All workbenches retention',
  'History retention',
  'Activity retention',
];

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');

  // ── Fix active=true on default rules that have never run ──────────────────
  // The previous migration created file/workbench rules without setting active,
  // so createRetentionRule defaulted to active=true. For consistency with new
  // platform initialization (active=false), we set active=false on those default
  // rules that have never been executed (last_execution_date is null).
  const fixActiveMessage = `${message} > Fix active field on default rules that have never run`;
  logMigration.info(`${fixActiveMessage} > started`);
  const fixActiveQuery = {
    script: {
      source: 'ctx._source.active = false;',
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'RetentionRule' } } },
          { terms: { 'name.keyword': DEFAULT_RULE_NAMES } },
          { term: { active: true } },
        ],
        must_not: [
          { exists: { field: 'last_execution_date' } },
        ],
      },
    },
  };
  await elUpdateByQueryForMigration(fixActiveMessage, READ_INDEX_INTERNAL_OBJECTS, fixActiveQuery);
  logMigration.info(`${fixActiveMessage} > done`);

  // ── Create history and activity rules for existing platforms ──────────────
  const existingRules = await listRules(context, SYSTEM_USER, {});
  const existingScopes = existingRules.map((rule) => rule.scope);

  if (!existingScopes.includes('history')) {
    await createRetentionRule(context, SYSTEM_USER, {
      name: 'History retention',
      max_retention: 30,
      retention_unit: 'days',
      scope: 'history',
      active: false,
    });
    logMigration.info(`${message} > Created history retention rule (30 days, inactive)`);
  } else {
    logMigration.info(`${message} > History retention rule already exists, skipping`);
  }

  if (!existingScopes.includes('activity')) {
    await createRetentionRule(context, SYSTEM_USER, {
      name: 'Activity retention',
      max_retention: 30,
      retention_unit: 'days',
      scope: 'activity',
      active: false,
    });
    logMigration.info(`${message} > Created activity retention rule (30 days, inactive)`);
  } else {
    logMigration.info(`${message} > Activity retention rule already exists, skipping`);
  }

  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
