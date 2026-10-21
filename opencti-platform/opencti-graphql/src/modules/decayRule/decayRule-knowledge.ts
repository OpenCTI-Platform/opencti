import type { AuthContext, AuthUser } from '../../types/user';
import type { EditInput, FilterGroup, KnowledgeDecayRuleAddInput } from '../../generated/graphql';
import { EditOperation, FilterMode } from '../../generated/graphql';
import { fullEntitiesList } from '../../database/middleware-loader';
import { getEntitiesListFromCache } from '../../database/cache';
import { elAggregationCount, elRawUpdateByQuery } from '../../database/engine';
import {
  READ_INDEX_STIX_CORE_RELATIONSHIPS,
  READ_INDEX_STIX_CYBER_OBSERVABLES,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_INDEX_STIX_SIGHTING_RELATIONSHIPS,
  wait,
} from '../../database/utils';
import { createInternalObject } from '../../domain/internalObject';
import { DatabaseError, FunctionalError } from '../../config/errors';
import { now } from '../../utils/format';
import { SYSTEM_USER } from '../../utils/access';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { isStixCoreRelationship, STIX_CORE_RELATIONSHIPS } from '../../schema/stixCoreRelationship';
import { isStixSightingRelationship, STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { isStixDomainObject } from '../../schema/stixDomainObject';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import { checkFiltersValidity } from '../../utils/filtering/filtering-utils';
import { addKnowledgeDecayRuleCreationCount } from '../../manager/telemetryManager';
import { ATTRIBUTE_FRESHNESS_RULE_ID, ATTRIBUTE_FRESHNESS_STALE, ATTRIBUTE_FRESHNESS_STALE_AT } from '../provenance/provenance-types';
import { listProvenanceTrackedTypes } from '../provenance/provenance-tracking';
import { PROVENANCE_ENABLED } from '../provenance/provenance-config';
import {
  ATTRIBUTE_FRESHNESS_CONFIGURED_AT,
  type BasicStoreEntityDecayRule,
  DECAY_RULE_SCOPE_ENTITY,
  DECAY_RULE_SCOPE_INDICATOR,
  DECAY_RULE_SCOPE_RELATIONSHIP,
  type DecayRuleScope,
  DEFAULT_FRESHNESS_CONFIDENCE_STEP,
  ENTITY_TYPE_DECAY_RULE,
  FRESHNESS_POLICY_FLAG,
  FRESHNESS_POLICY_LOWER_CONFIDENCE,
  FRESHNESS_POLICY_REVOKE,
  KNOWLEDGE_FRESHNESS_POLICIES,
  type KnowledgeFreshnessPolicyValue,
  type StoreEntityDecayRule,
} from './decayRule-types';

// Knowledge decay never applies to inferred knowledge: it follows the knowledge it is inferred from.
export const KNOWLEDGE_FRESHNESS_INDICES = [
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_INDEX_STIX_CYBER_OBSERVABLES,
  READ_INDEX_STIX_CORE_RELATIONSHIPS,
  READ_INDEX_STIX_SIGHTING_RELATIONSHIPS,
];

// Indicator-only fields, meaningless for knowledge decay rules.
const INDICATOR_DECAY_FIELDS = ['decay_lifetime', 'decay_pound', 'decay_points', 'decay_revoke_score'];
// Knowledge-only fields, meaningless for indicator decay rules.
export const KNOWLEDGE_DECAY_FIELDS = ['target_types', 'freshness_policy', 'stale_after_days', 'freshness_confidence_step'];
// Edit values are received as strings
const NUMERIC_KNOWLEDGE_DECAY_FIELDS = ['order', 'stale_after_days', 'freshness_confidence_step'];
// Changing one of these fields releases the knowledge the rule flagged: the freshness manager skips flagged
// knowledge, so only a release lets it be evaluated again under the new configuration (fresh again, new policy,
// or taken over by an overlapping rule that now has a higher priority).
const FRESHNESS_RESET_FIELDS = ['active', 'order', 'target_types', 'decay_filters', 'stale_after_days', 'freshness_policy', 'freshness_confidence_step'];
// Edits that can make a rule take over elements targeted by lower priority rules
export const KNOWLEDGE_PRIORITY_FIELDS = ['active', 'order', 'target_types', 'decay_filters'];

// Held by a change of a knowledge decay rule until its flags are released, and by the freshness manager around each
// policy it applies with the rule: a policy is applied either before the release or with the new configuration
export const knowledgeDecayRuleLockKey = (ruleId: string) => `knowledge_decay_rule_lock_${ruleId}`;

// Whether a stored rule still has the configuration a freshness run loaded (a deleted rule has none)
export const hasSameFreshnessConfiguration = (loaded: object, stored: object | undefined | null) => {
  if (!stored) {
    return false;
  }
  const valueOf = (rule: object, field: string) => JSON.stringify((rule as Record<string, unknown>)[field] ?? null);
  return FRESHNESS_RESET_FIELDS.every((field) => valueOf(loaded, field) === valueOf(stored, field));
};

export interface KnowledgeDecayRuleDefinition {
  name: string;
  description?: string | null;
  order: number;
  active: boolean;
  target_scope: DecayRuleScope;
  target_types?: string[] | null;
  decay_filters?: string | null;
  freshness_policy: KnowledgeFreshnessPolicyValue;
  stale_after_days: number;
  freshness_confidence_step?: number | null;
}

export const getDecayRuleScope = (rule: { target_scope?: DecayRuleScope | null }): DecayRuleScope => {
  return rule.target_scope ?? DECAY_RULE_SCOPE_INDICATOR;
};

export const isKnowledgeDecayRule = (rule: { target_scope?: DecayRuleScope | null }) => {
  return getDecayRuleScope(rule) !== DECAY_RULE_SCOPE_INDICATOR;
};

const isRelationshipScopeType = (type: string) => isStixCoreRelationship(type) || isStixSightingRelationship(type);
const isEntityScopeType = (type: string) => (isStixDomainObject(type) || isStixCyberObservable(type)) && type !== ENTITY_TYPE_INDICATOR;

/**
 * Concrete types targeted by a knowledge rule (abstract types are never used so that rules of the same scope can be subtracted).
 * An empty relationship type list targets every Stix core relationship and sightings.
 */
export const resolveKnowledgeDecayRuleTypes = (rule: { target_scope?: DecayRuleScope | null; target_types?: string[] | null }): string[] => {
  const scope = getDecayRuleScope(rule);
  const types = rule.target_types ?? [];
  if (scope === DECAY_RULE_SCOPE_RELATIONSHIP) {
    return types.length > 0 ? [...types] : [...STIX_CORE_RELATIONSHIPS, STIX_SIGHTING_RELATIONSHIP];
  }
  if (scope === DECAY_RULE_SCOPE_ENTITY) {
    return [...types];
  }
  return [];
};

export const parseKnowledgeDecayFilters = (decayFilters: string | null | undefined): FilterGroup | undefined => {
  if (!decayFilters) {
    return undefined;
  }
  let filterGroup: FilterGroup;
  try {
    filterGroup = JSON.parse(decayFilters);
  } catch {
    throw FunctionalError('Knowledge decay rule filters must be a valid filter group', { decay_filters: decayFilters });
  }
  checkFiltersValidity(filterGroup);
  return filterGroup;
};

export const validateKnowledgeDecayRule = (rule: KnowledgeDecayRuleDefinition) => {
  const scope = rule.target_scope;
  if (scope !== DECAY_RULE_SCOPE_RELATIONSHIP && scope !== DECAY_RULE_SCOPE_ENTITY) {
    throw FunctionalError('Knowledge decay rules target relationships or entities', { target_scope: scope });
  }
  if (!Number.isInteger(rule.stale_after_days) || rule.stale_after_days < 1) {
    throw FunctionalError('The number of days before knowledge becomes stale must be a positive integer', { stale_after_days: rule.stale_after_days });
  }
  if (!KNOWLEDGE_FRESHNESS_POLICIES.includes(rule.freshness_policy)) {
    throw FunctionalError('Unknown knowledge freshness policy', { freshness_policy: rule.freshness_policy });
  }
  const step = rule.freshness_confidence_step;
  if (rule.freshness_policy === FRESHNESS_POLICY_LOWER_CONFIDENCE && (!Number.isInteger(step) || (step as number) < 1 || (step as number) > 100)) {
    throw FunctionalError('Lowering the confidence requires a step between 1 and 100', { freshness_confidence_step: step });
  }
  const declaredTypes = rule.target_types ?? [];
  if (scope === DECAY_RULE_SCOPE_ENTITY && declaredTypes.length === 0) {
    throw FunctionalError('An entity knowledge decay rule must target at least one entity type');
  }
  const isTypeInScope = scope === DECAY_RULE_SCOPE_RELATIONSHIP ? isRelationshipScopeType : isEntityScopeType;
  const invalidTypes = declaredTypes.filter((type) => !isTypeInScope(type));
  if (invalidTypes.length > 0) {
    throw FunctionalError('These types cannot be targeted by this knowledge decay rule', { target_scope: scope, types: invalidTypes });
  }
  const requiredAttribute = rule.freshness_policy === FRESHNESS_POLICY_REVOKE ? 'revoked' : (rule.freshness_policy === FRESHNESS_POLICY_LOWER_CONFIDENCE ? 'confidence' : null);
  if (requiredAttribute) {
    const unsupported = resolveKnowledgeDecayRuleTypes(rule).filter((type) => !schemaAttributesDefinition.getAttribute(type, requiredAttribute));
    if (unsupported.length > 0) {
      throw FunctionalError(`The ${rule.freshness_policy} policy needs the ${requiredAttribute} attribute on every targeted type`, { types: unsupported });
    }
  }
  parseKnowledgeDecayFilters(rule.decay_filters);
};

const normalizeKnowledgeDecayRule = (input: KnowledgeDecayRuleAddInput | KnowledgeDecayRuleDefinition): KnowledgeDecayRuleDefinition => ({
  name: input.name,
  description: input.description ?? null,
  order: input.order,
  active: input.active ?? false,
  target_scope: input.target_scope as DecayRuleScope,
  target_types: [...new Set(input.target_types ?? [])],
  decay_filters: input.decay_filters || null,
  freshness_policy: input.freshness_policy as KnowledgeFreshnessPolicyValue,
  stale_after_days: input.stale_after_days,
  freshness_confidence_step: input.freshness_policy === FRESHNESS_POLICY_LOWER_CONFIDENCE
    ? (input.freshness_confidence_step ?? DEFAULT_FRESHNESS_CONFIDENCE_STEP)
    : null,
});

export const addKnowledgeDecayRule = async (context: AuthContext, user: AuthUser, input: KnowledgeDecayRuleAddInput | KnowledgeDecayRuleDefinition, builtIn = false) => {
  const definition = normalizeKnowledgeDecayRule(input);
  validateKnowledgeDecayRule(definition);
  const at = now();
  const ruleInput = { ...definition, built_in: builtIn, created_at: at, updated_at: at, [ATTRIBUTE_FRESHNESS_CONFIGURED_AT]: at };
  const created = await createInternalObject<StoreEntityDecayRule>(context, user, ruleInput, ENTITY_TYPE_DECAY_RULE);
  if (!builtIn) {
    await addKnowledgeDecayRuleCreationCount();
  }
  return created;
};

// The target types an edition leaves, computed as the update of a multiple attribute computes them
const patchTargetTypes = (current: string[], { operation, value }: EditInput): string[] => {
  const values = (value ?? []) as string[];
  if (operation === EditOperation.Add) {
    return [...new Set([...current, ...values])].filter((type) => !!type);
  }
  if (operation === EditOperation.Remove) {
    return current.filter((type) => !values.includes(type));
  }
  return values;
};

/**
 * Validate an edition of a decay rule against its scope. Returns true when the stale flags set by the rule must be cleared.
 */
export const checkDecayRulePatch = (decayRule: BasicStoreEntityDecayRule, input: EditInput[]) => {
  const keys = input.map((editInput) => editInput.key);
  if (keys.includes('target_scope')) {
    throw FunctionalError('The target scope of a decay rule cannot be changed', { id: decayRule.id });
  }
  if (keys.includes(ATTRIBUTE_FRESHNESS_CONFIGURED_AT)) {
    throw FunctionalError('The freshness configuration date of a decay rule is set by the platform', { id: decayRule.id });
  }
  if (!isKnowledgeDecayRule(decayRule)) {
    if (decayRule.built_in) {
      throw FunctionalError(`Cannot update built-in decay rule ${decayRule.id}`);
    }
    const invalid = keys.filter((key) => KNOWLEDGE_DECAY_FIELDS.includes(key));
    if (invalid.length > 0) {
      throw FunctionalError('These fields only apply to knowledge decay rules', { keys: invalid });
    }
    return false;
  }
  // Built-in knowledge rules ship disabled: they can only be activated or deactivated.
  if (decayRule.built_in && keys.some((key) => key !== 'active')) {
    throw FunctionalError(`Built-in knowledge decay rule ${decayRule.id} can only be activated or deactivated`);
  }
  const invalid = keys.filter((key) => INDICATOR_DECAY_FIELDS.includes(key));
  if (invalid.length > 0) {
    throw FunctionalError('These fields only apply to indicator decay rules', { keys: invalid });
  }
  const patched: Record<string, any> = { ...decayRule };
  input.forEach((editInput) => {
    const raw = editInput.value?.[0];
    if (editInput.key === 'target_types') {
      patched[editInput.key] = patchTargetTypes(patched[editInput.key] ?? [], editInput);
    } else if (NUMERIC_KNOWLEDGE_DECAY_FIELDS.includes(editInput.key)) {
      patched[editInput.key] = raw === null || raw === undefined || raw === '' ? null : Number(raw);
    } else {
      patched[editInput.key] = raw ?? null;
    }
  });
  validateKnowledgeDecayRule(normalizeKnowledgeDecayRule(patched as KnowledgeDecayRuleDefinition));
  return keys.some((key) => FRESHNESS_RESET_FIELDS.includes(key));
};

// Elements written while the flags are cleared (an upsert, a re-assertion) are skipped as version conflicts
const CLEAR_FRESHNESS_FLAGS_ATTEMPTS = 5;
const CLEAR_FRESHNESS_FLAGS_RETRY_DELAY_MS = 200;

/**
 * Knowledge flagged as stale by a rule becomes fresh again (side-channel update, no stream event),
 * the freshness manager flags it again if it is still stale under the current rules.
 * The elements skipped as version conflicts are cleared again, and the operation fails rather than leave a
 * flag behind: the freshness scans never examine an element that is already flagged.
 */
const clearFreshnessFlags = async (query: Record<string, unknown>) => {
  let versionConflicts = 0;
  for (let attempt = 1; attempt <= CLEAR_FRESHNESS_FLAGS_ATTEMPTS; attempt += 1) {
    const response = await elRawUpdateByQuery({
      index: KNOWLEDGE_FRESHNESS_INDICES,
      refresh: true,
      conflicts: 'proceed',
      body: {
        script: {
          source: `ctx._source.${ATTRIBUTE_FRESHNESS_STALE} = false; ctx._source.remove('freshness_stale_at'); ctx._source.remove('${ATTRIBUTE_FRESHNESS_RULE_ID}');`,
          lang: 'painless',
        },
        query,
      },
    }).catch((err: unknown) => {
      throw DatabaseError('Error clearing knowledge freshness flags', { cause: err, query });
    });
    if ((response?.failures ?? []).length > 0) {
      throw DatabaseError('Error clearing knowledge freshness flags', { failures: response.failures, query });
    }
    versionConflicts = response?.version_conflicts ?? 0;
    if (versionConflicts === 0) {
      return response;
    }
    if (attempt < CLEAR_FRESHNESS_FLAGS_ATTEMPTS) {
      await wait(CLEAR_FRESHNESS_FLAGS_RETRY_DELAY_MS * attempt);
    }
  }
  throw DatabaseError('Knowledge freshness flags kept changing while they were cleared', { version_conflicts: versionConflicts, query });
};

export const clearFreshnessFlagsOfRule = async (ruleId: string) => {
  return clearFreshnessFlags({ term: { [`${ATTRIBUTE_FRESHNESS_RULE_ID}.keyword`]: ruleId } });
};

export const clearFreshnessFlagsOfElements = async (ids: string[]) => {
  return clearFreshnessFlags({ terms: { 'internal_id.keyword': ids } });
};

/**
 * Flags that no rule may keep: those of a rule that is no longer active, and those set before the last configuration
 * change of their rule. A rule change releases them itself; every knowledge freshness run completes a release that failed.
 */
export const clearOutdatedFreshnessFlags = async (activeRules: BasicStoreEntityDecayRule[]) => {
  const ruleIdField = `${ATTRIBUTE_FRESHNESS_RULE_ID}.keyword`;
  const outdated: Record<string, unknown>[] = [{ bool: { must_not: [{ terms: { [ruleIdField]: activeRules.map((rule) => rule.id) } }] } }];
  activeRules.filter((rule) => !!rule[ATTRIBUTE_FRESHNESS_CONFIGURED_AT]).forEach((rule) => {
    outdated.push({
      bool: {
        must: [
          { term: { [ruleIdField]: rule.id } },
          { range: { [ATTRIBUTE_FRESHNESS_STALE_AT]: { lt: rule[ATTRIBUTE_FRESHNESS_CONFIGURED_AT] } } },
        ],
      },
    });
  });
  return clearFreshnessFlags({ bool: { must: [{ term: { [ATTRIBUTE_FRESHNESS_STALE]: true } }], should: outdated, minimum_should_match: 1 } });
};

/**
 * Number of elements flagged as stale by each rule, counted in a single aggregation for a page of rules.
 * Only the types whose provenance is tracked count, as in the Stale knowledge lists: a type no longer tracked keeps
 * the flags it received, but its elements are left out of the lists.
 * Disabled provenance counts nothing, like the other provenance statistics, even for the flags set before.
 */
// One bucket per rule: the rules are counted by groups that fit in the bucket limit of an aggregation
const STALE_COUNT_RULES_PER_AGGREGATION = 100;

export const batchStaleElementsCounts = async (context: AuthContext, user: AuthUser, decayRules: BasicStoreEntityDecayRule[]) => {
  if (!PROVENANCE_ENABLED) {
    return decayRules.map(() => 0);
  }
  const knowledgeRuleIds = decayRules.filter((rule) => isKnowledgeDecayRule(rule)).map((rule) => rule.id);
  const countsByRule = new Map<string, number>();
  const trackedTypes = knowledgeRuleIds.length > 0 ? await listProvenanceTrackedTypes(context) : [];
  for (let start = 0; trackedTypes.length > 0 && start < knowledgeRuleIds.length; start += STALE_COUNT_RULES_PER_AGGREGATION) {
    const buckets = await elAggregationCount(context, user, KNOWLEDGE_FRESHNESS_INDICES, {
      field: ATTRIBUTE_FRESHNESS_RULE_ID,
      normalizeLabel: false,
      types: trackedTypes,
      filters: {
        mode: FilterMode.And,
        filters: [
          { key: [ATTRIBUTE_FRESHNESS_STALE], values: ['true'] },
          { key: [ATTRIBUTE_FRESHNESS_RULE_ID], values: knowledgeRuleIds.slice(start, start + STALE_COUNT_RULES_PER_AGGREGATION) },
        ],
        filterGroups: [],
      },
    });
    buckets.forEach((bucket: { label: string; count: number }) => countsByRule.set(bucket.label, bucket.count));
  }
  return decayRules.map((rule) => (isKnowledgeDecayRule(rule) ? countsByRule.get(rule.id) ?? 0 : 0));
};

/**
 * Number of knowledge decay rules, among every rule of the platform, that flag knowledge the user can access.
 */
export const countKnowledgeDecayRulesInvolved = async (context: AuthContext, user: AuthUser) => {
  if (!PROVENANCE_ENABLED) {
    return 0;
  }
  const rules = await getEntitiesListFromCache<BasicStoreEntityDecayRule>(context, SYSTEM_USER, ENTITY_TYPE_DECAY_RULE);
  const counts = await batchStaleElementsCounts(context, user, rules);
  return counts.filter((count) => count > 0).length;
};

/**
 * Highest priority first: the knowledge decay rule with the highest order applies to an element.
 */
export const getActiveKnowledgeDecayRules = async (context: AuthContext): Promise<BasicStoreEntityDecayRule[]> => {
  const rules = await getEntitiesListFromCache<BasicStoreEntityDecayRule>(context, SYSTEM_USER, ENTITY_TYPE_DECAY_RULE);
  return rules
    .filter((rule) => rule.active && isKnowledgeDecayRule(rule))
    .sort((a, b) => (b.order - a.order) || String(a.created_at).localeCompare(String(b.created_at)));
};

// region built-in knowledge decay rules, shipped disabled
export const BUILT_IN_KNOWLEDGE_DECAY_RULE_COMMUNICATES_WITH: KnowledgeDecayRuleDefinition = {
  name: 'Built-in communicates-with freshness',
  description: 'Flags communicates-with relationships that no source re-asserted for 180 days.',
  order: 1,
  active: false,
  target_scope: DECAY_RULE_SCOPE_RELATIONSHIP,
  target_types: ['communicates-with'],
  freshness_policy: FRESHNESS_POLICY_FLAG,
  stale_after_days: 180,
};

export const BUILT_IN_KNOWLEDGE_DECAY_RULE_USES: KnowledgeDecayRuleDefinition = {
  name: 'Built-in uses freshness',
  description: 'Flags uses relationships that no source re-asserted for 24 months.',
  order: 1,
  active: false,
  target_scope: DECAY_RULE_SCOPE_RELATIONSHIP,
  target_types: ['uses'],
  freshness_policy: FRESHNESS_POLICY_FLAG,
  stale_after_days: 730,
};

export const BUILT_IN_KNOWLEDGE_DECAY_RULE_INFRASTRUCTURE: KnowledgeDecayRuleDefinition = {
  name: 'Built-in infrastructure freshness',
  description: 'Flags infrastructures that no source re-asserted for one year.',
  order: 1,
  active: false,
  target_scope: DECAY_RULE_SCOPE_ENTITY,
  target_types: ['Infrastructure'],
  freshness_policy: FRESHNESS_POLICY_FLAG,
  stale_after_days: 365,
};

export const BUILT_IN_KNOWLEDGE_DECAY_RULES = [
  BUILT_IN_KNOWLEDGE_DECAY_RULE_COMMUNICATES_WITH,
  BUILT_IN_KNOWLEDGE_DECAY_RULE_USES,
  BUILT_IN_KNOWLEDGE_DECAY_RULE_INFRASTRUCTURE,
];

/**
 * Create the missing built-in knowledge decay rules, on new and existing platforms.
 */
export const initKnowledgeDecayRules = async (context: AuthContext, user: AuthUser) => {
  const args = { filters: { mode: FilterMode.And, filters: [{ key: ['built_in'], values: [true] }], filterGroups: [] } };
  const builtInRules = await fullEntitiesList<BasicStoreEntityDecayRule>(context, user, [ENTITY_TYPE_DECAY_RULE], args);
  const existingNames = new Set(builtInRules.filter(isKnowledgeDecayRule).map((rule) => rule.name));
  for (let index = 0; index < BUILT_IN_KNOWLEDGE_DECAY_RULES.length; index += 1) {
    const definition = BUILT_IN_KNOWLEDGE_DECAY_RULES[index];
    if (!existingNames.has(definition.name)) {
      await addKnowledgeDecayRule(context, user, definition, true);
    }
  }
};
// endregion
