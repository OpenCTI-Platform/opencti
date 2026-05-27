import { logMigration } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { createRetentionRule, deleteRetentionRule, listRules } from '../modules/retentionRules/retentionRules-domain';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';

const message = '[MIGRATION] Add active field to retention rules and create default disabled technical rules';

/**
 * For a given scope, if multiple rules exist, keep the one with the shortest max_retention
 * and delete all others. Returns the kept rule (or undefined if none).
 */
const deduplicateScopeRules = async (context, rules) => {
  if (rules.length <= 1) return rules[0];

  // Sort by max_retention ASC (keep the shortest), then by creation date ASC (keep oldest if tie)
  const sorted = [...rules].sort((a, b) => {
    if (a.max_retention !== b.max_retention) return a.max_retention - b.max_retention;
    return new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
  });

  const [keepRule, ...duplicates] = sorted;
  for (const duplicate of duplicates) {
    await deleteRetentionRule(context, SYSTEM_USER, duplicate.id);
    logMigration.info(`${message} > Deleted duplicate retention rule "${duplicate.name}" (id: ${duplicate.id}, max_retention: ${duplicate.max_retention})`);
  }
  logMigration.info(`${message} > Kept retention rule "${keepRule.name}" (id: ${keepRule.id}, max_retention: ${keepRule.max_retention})`);
  return keepRule;
};

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');

  // Set all existing retention rules as active = true
  const activateExistingQuery = {
    script: {
      source: `
        if (ctx._source.active == null) {
          ctx._source.active = true;
        }
      `,
    },
    query: {
      term: { 'entity_type.keyword': { value: 'RetentionRule' } },
    },
  };
  await elUpdateByQueryForMigration(
    '[MIGRATION] Set existing retention rules as active',
    READ_INDEX_INTERNAL_OBJECTS,
    activateExistingQuery,
  );
  logMigration.info(`${message} > Set all existing retention rules as active = true`);

  // Get all existing rules
  const existingRules = await listRules(context, SYSTEM_USER, {});

  // Group rules by scope
  const rulesByScope = existingRules.reduce((acc, rule) => {
    if (!acc[rule.scope]) acc[rule.scope] = [];
    acc[rule.scope].push(rule);
    return acc;
  }, {});

  // Deduplicate and create missing technical rules
  const technicalScopes = [
    { scope: 'file', name: 'Global files retention' },
    { scope: 'workbench', name: 'All workbenches retention' },
    { scope: 'history', name: 'History retention' },
    { scope: 'activity', name: 'Activity retention' },
  ];

  for (const { scope, name } of technicalScopes) {
    const scopeRules = rulesByScope[scope] ?? [];

    if (scopeRules.length === 0) {
      // No rule for this scope: create a disabled one with 365 days
      await createRetentionRule(context, SYSTEM_USER, {
        name,
        max_retention: 365,
        retention_unit: 'days',
        scope,
        active: false,
      });
      logMigration.info(`${message} > Created disabled ${scope} retention rule (365 days, inactive)`);
    } else if (scopeRules.length > 1) {
      // Multiple rules: keep the one with the shortest retention, delete the rest
      logMigration.info(`${message} > Found ${scopeRules.length} rules for scope "${scope}", deduplicating...`);
      await deduplicateScopeRules(context, scopeRules);
    } else {
      logMigration.info(`${message} > ${scope} retention rule already exists (1 rule), skipping`);
    }
  }

  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};