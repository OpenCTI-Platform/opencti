import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { addIndicator } from '../../../src/modules/indicator/indicator-domain';
import type { IndicatorAddInput } from '../../../src/generated/graphql';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { type BasicStoreEntityIndicator, ENTITY_TYPE_INDICATOR } from '../../../src/modules/indicator/indicator-types';
import { STIX_PATTERN_TYPE } from '../../../src/utils/syntax';
import { addDecayRule, deleteDecayRule } from '../../../src/modules/decayRule/decayRule-domain';
import { addDecayExclusionRule, deleteDecayExclusionRule } from '../../../src/modules/decayRule/exclusions/decayExclusionRule-domain';
import { type BasicStoreEntityDecayRule, ENTITY_TYPE_DECAY_RULE } from '../../../src/modules/decayRule/decayRule-types';
import type { BasicStoreEntity } from '../../../src/types/store';
import { ENTITY_TYPE_DECAY_EXCLUSION_RULE } from '../../../src/modules/decayRule/exclusions/decayExclusionRule-types';
import { getEntitiesListFromCache } from '../../../src/database/cache';
import { SYSTEM_USER } from '../../../src/utils/access';
import { addLabel } from '../../../src/domain/label';
import { addOrganization } from '../../../src/modules/organization/organization-domain';
import { stixDomainObjectDelete } from '../../../src/domain/stixDomainObject';
import { deleteElementById } from '../../../src/database/middleware';
import { ENTITY_TYPE_LABEL } from '../../../src/schema/stixMetaObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import { CREATED_BY_FILTER, LABEL_FILTER } from '../../../src/utils/filtering/filtering-constants';
import * as indicatorUtils from '../../../src/modules/indicator/indicator-utils';
import { wait } from '../../../src/database/utils';

// The validity and decay an indicator gets at creation: the rule chosen (built-in by observable
// type, or a custom rule filtering on its labels or author), the exclusion, the dates and the score
// history. The snapshot is recorded on the code before the decay moved into the creation and must
// hold after it: the move changes where the computation runs, not what it computes.

const VALID_FROM = '2030-01-01T00:00:00.000Z';
const filterOn = (key: string, value: string) => JSON.stringify({
  mode: 'and',
  filters: [{ key: [key], operator: 'eq', values: [value], mode: 'or' }],
  filterGroups: [],
});

const waitInCache = async (type: string, id: string) => {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const cached = await getEntitiesListFromCache<BasicStoreEntity>(testContext, SYSTEM_USER, type);
    if (cached.some((entity) => entity.id === id)) return;
    await wait(200);
  }
  throw new Error(`${type} ${id} never reached the cache`);
};

describe('Indicator validity and decay at creation', () => {
  const created: string[] = [];
  let ruleNames: Map<string, string>;
  let label: { id: string };
  let excludedLabel: { id: string };
  let author: { id: string };
  let labelRule: { id: string };
  let authorRule: { id: string };
  let exclusionRule: { id: string };

  beforeAll(async () => {
    label = await addLabel(testContext, ADMIN_USER, { value: 'decay-parity-label' });
    excludedLabel = await addLabel(testContext, ADMIN_USER, { value: 'decay-parity-excluded' });
    author = await addOrganization(testContext, ADMIN_USER, { name: 'Decay parity author' });
    const custom = { active: true, decay_pound: 0.5, decay_points: [60], decay_revoke_score: 10 };
    labelRule = await addDecayRule(testContext, ADMIN_USER, { ...custom, name: 'Parity label rule', order: 10, decay_lifetime: 10, decay_filters: filterOn(LABEL_FILTER, label.id) });
    authorRule = await addDecayRule(testContext, ADMIN_USER, { ...custom, name: 'Parity author rule', order: 11, decay_lifetime: 20, decay_filters: filterOn(CREATED_BY_FILTER, author.id) });
    exclusionRule = await addDecayExclusionRule(testContext, ADMIN_USER, { name: 'Parity exclusion', active: true, decay_exclusion_filters: filterOn(LABEL_FILTER, excludedLabel.id) });
    await waitInCache(ENTITY_TYPE_DECAY_RULE, labelRule.id);
    await waitInCache(ENTITY_TYPE_DECAY_RULE, authorRule.id);
    await waitInCache(ENTITY_TYPE_DECAY_EXCLUSION_RULE, exclusionRule.id);
    const rules = await getEntitiesListFromCache<BasicStoreEntityDecayRule>(testContext, SYSTEM_USER, ENTITY_TYPE_DECAY_RULE);
    ruleNames = new Map(rules.map((rule) => [rule.id, rule.name]));
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    for (let i = 0; i < created.length; i += 1) {
      await stixDomainObjectDelete(testContext, ADMIN_USER, created[i], ENTITY_TYPE_INDICATOR);
    }
    await deleteDecayRule(testContext, ADMIN_USER, labelRule.id);
    await deleteDecayRule(testContext, ADMIN_USER, authorRule.id);
    await deleteDecayExclusionRule(testContext, ADMIN_USER, exclusionRule.id);
    await deleteElementById(testContext, ADMIN_USER, label.id, ENTITY_TYPE_LABEL);
    await deleteElementById(testContext, ADMIN_USER, excludedLabel.id, ENTITY_TYPE_LABEL);
    await deleteElementById(testContext, ADMIN_USER, author.id, ENTITY_TYPE_IDENTITY_ORGANIZATION);
  });

  // What the creation decided, without the ids of the run
  const decisionOf = (indicator: BasicStoreEntityIndicator & { decay_next_reaction_date?: Date }) => ({
    rule: indicator.decay_applied_rule ? ruleNames.get(indicator.decay_applied_rule.decay_rule_id) : null,
    applied_rule: indicator.decay_applied_rule ? { ...indicator.decay_applied_rule, decay_rule_id: undefined } : null,
    exclusion: indicator.decay_exclusion_applied_rule?.decay_exclusion_name ?? null,
    score: indicator.x_opencti_score,
    valid_from: indicator.valid_from,
    valid_until: indicator.valid_until,
    revoked: indicator.revoked,
    decay_base_score: indicator.decay_base_score ?? null,
    decay_base_score_date: indicator.decay_base_score_date ?? null,
    decay_next_reaction_date: indicator.decay_next_reaction_date ?? null,
    decay_history: (indicator.decay_history ?? []).map(({ score, updated_at }) => ({ score, updated_at })),
  });

  const create = async (name: string, pattern: string, extra: Partial<IndicatorAddInput> = {}) => {
    const indicator = await addIndicator(testContext, ADMIN_USER, {
      name, pattern, pattern_type: STIX_PATTERN_TYPE, x_opencti_score: 100, valid_from: VALID_FROM, ...extra,
    });
    created.push(indicator.id);
    return decisionOf(indicator as BasicStoreEntityIndicator);
  };

  it('should decide the same validity and decay as before the move', async () => {
    vi.spyOn(indicatorUtils, 'isDecayEnabled').mockResolvedValue(true);
    const decisions = {
      ip: await create('Parity IP', '[ipv4-addr:value = \'198.51.100.1\']', { x_opencti_main_observable_type: 'IPv4-Addr' }),
      domain: await create('Parity domain', '[domain-name:value = \'parity.example\']', { x_opencti_main_observable_type: 'Domain-Name' }),
      file: await create('Parity file', '[file:hashes.\'SHA-256\' = \'0f343b0931126a20f133d67c2b018a3b5c3a7e1e9a1b8f3c2d4e5f6a7b8c9d0e\']', { x_opencti_main_observable_type: 'StixFile' }),
      by_label: await create('Parity IP labelled', '[ipv4-addr:value = \'198.51.100.2\']', { x_opencti_main_observable_type: 'IPv4-Addr', objectLabel: [label.id] }),
      by_author: await create('Parity IP authored', '[ipv4-addr:value = \'198.51.100.3\']', { x_opencti_main_observable_type: 'IPv4-Addr', createdBy: author.id }),
      excluded: await create('Parity IP excluded', '[ipv4-addr:value = \'198.51.100.4\']', { x_opencti_main_observable_type: 'IPv4-Addr', objectLabel: [excludedLabel.id] }),
    };
    vi.spyOn(indicatorUtils, 'isDecayEnabled').mockResolvedValue(false);
    const disabled = await create('Parity IP no decay', '[ipv4-addr:value = \'198.51.100.5\']', { x_opencti_main_observable_type: 'IPv4-Addr' });
    // the rules chosen, readable
    expect(decisions.ip.rule).toEqual('Built-in IP and URL');
    expect(decisions.domain.rule).toEqual('Built-in domain name');
    expect(decisions.file.rule).toEqual('Built-in files and artifact');
    expect(decisions.by_label.rule).toEqual('Parity label rule');
    expect(decisions.by_author.rule).toEqual('Parity author rule');
    expect(decisions.excluded.exclusion).toEqual('Parity exclusion');
    expect(disabled.rule).toBeNull();
    // every field, as decided before the move
    expect({ ...decisions, disabled }).toMatchSnapshot();
  });
});
