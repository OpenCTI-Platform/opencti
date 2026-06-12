import { logMigration } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { createRetentionRule, deleteRetentionRule, listRules } from '../modules/retentionRules/retentionRules-domain';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';

const message = '[MIGRATION] Add active field to retention rules and create default disabled technical rules';

const DEFAULT_RULE_NAMES = [
  'Global files retention',
  'All workbenches retention',
  'History retention',
  'Activity retention',
];

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

  // ── 1. Backward compat: set active=true on all pre-existing rules ─────────
  // Rules created before the active field was introduced have active=null.
  // We mark them as active so they keep running as before.
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

  // ── 2. Deduplicate and create missing technical rules ─────────────────────
  const existingRules = await listRules(context, SYSTEM_USER, {});
  const rulesByScope = existingRules.reduce((acc, rule) => {
    if (!acc[rule.scope]) acc[rule.scope] = [];
    acc[rule.scope].push(rule);
    return acc;
  }, {});

  const technicalScopes = [
    { scope: 'file', name: 'Global files retention', max_retention: 30 },
    { scope: 'workbench', name: 'All workbenches retention', max_retention: 30 },
    { scope: 'history', name: 'History retention', max_retention: 30 },
    { scope: 'activity', name: 'Activity retention', max_retention: 30 },
  ];

  for (const { scope, name, max_retention } of technicalScopes) {
    const scopeRules = rulesByScope[scope] ?? [];

    if (scopeRules.length === 0) {
      // No rule for this scope: create a disabled one
      await createRetentionRule(context, SYSTEM_USER, {
        name,
        max_retention,
        retention_unit: 'days',
        scope,
        active: false,
      });
      logMigration.info(`${message} > Created disabled ${scope} retention rule (${max_retention} days, inactive)`);
    } else if (scopeRules.length > 1) {
      logMigration.info(`${message} > Found ${scopeRules.length} rules for scope "${scope}", deduplicating...`);
      await deduplicateScopeRules(context, scopeRules);
    } else {
      logMigration.info(`${message} > ${scope} retention rule already exists (1 rule), skipping`);
    }
  }

  // ── 3. Deactivate default rules that have never run ───────────────────────
  // Step 1 set active=true on all pre-existing rules for backward compat.
  // However, the 4 technical rules above (file, workbench, history, activity)
  // are "opt-in by design": they should start as inactive so admins consciously
  // enable them. We set active=false only on those that have never been executed,
  // meaning the admin has not touched them yet.
  const deactivateDefaultsQuery = {
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
  await elUpdateByQueryForMigration(
    '[MIGRATION] Deactivate default retention rules that have never run',
    READ_INDEX_INTERNAL_OBJECTS,
    deactivateDefaultsQuery,
  );
  logMigration.info(`${message} > Set default retention rules that have never run to active = false`);

  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
