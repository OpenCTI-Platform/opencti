import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { computeSnapshotRetentionDate, splitRunBudget } from '../../../../src/manager/snapshotManager';
import { buildAggregatesMessage, buildChangeMessage, parseTriggerFilters } from '../../../../src/modules/timeMachine/timeMachine-changeDigest';
import { DEFAULT_CHANGE_DIGEST_LOCALE, formatChangeDigestMessage, resolveChangeDigestLocale } from '../../../../src/modules/timeMachine/timeMachine-changeDigest-messages';
import { landscapeResultReferencedIds, SAVED_FILTER_SCOPES, savedFilterScopeEntityTypes } from '../../../../src/modules/timeMachine/landscapeDiff-domain';
import { isStixCoreObject } from '../../../../src/schema/stixCoreObject';
import type { BasicStoreEntityRetentionRule } from '../../../../src/modules/retentionRules/retentionRules-types';
import type { LandscapeDiffAggregates, LandscapeDiffEntitySummary } from '../../../../src/modules/timeMachine/timeMachine-types';

const rule = (input: Partial<BasicStoreEntityRetentionRule>) => ({
  scope: 'history',
  active: true,
  max_retention: 30,
  retention_unit: 'days',
  filters: '',
  ...input,
}) as BasicStoreEntityRetentionRule;

const NOW = '2026-10-01T00:00:00.000Z';

describe('Knowledge snapshot retention', () => {
  it('should keep snapshots when no active history retention applies', () => {
    expect(computeSnapshotRetentionDate([], NOW, 0)).toBeNull();
    expect(computeSnapshotRetentionDate([rule({ scope: 'knowledge' })], NOW, 0)).toBeNull();
    expect(computeSnapshotRetentionDate([rule({ active: false })], NOW, 0)).toBeNull();
  });

  it('should follow a filtered history retention, which purges part of the history a reconstruction replays', () => {
    const filtered = JSON.stringify({ mode: 'and', filters: [{ key: ['entity_type'], values: ['Report'] }], filterGroups: [] });
    expect(computeSnapshotRetentionDate([rule({ filters: filtered })], NOW, 0)).toEqual('2026-09-01T00:00:00.000Z');
  });

  it('should align snapshots with the shortest global history retention', () => {
    const date = computeSnapshotRetentionDate([rule({ max_retention: 90 }), rule({ max_retention: 30 })], NOW, 0);
    expect(date).toEqual('2026-09-01T00:00:00.000Z');
    const empty = JSON.stringify({ mode: 'and', filters: [], filterGroups: [] });
    expect(computeSnapshotRetentionDate([rule({ max_retention: 2, retention_unit: 'weeks', filters: empty })], NOW, 0)).toEqual('2026-09-17T00:00:00.000Z');
  });

  it('should apply the configured snapshot retention when it is shorter', () => {
    expect(computeSnapshotRetentionDate([rule({ max_retention: 90 })], NOW, 10)).toEqual('2026-09-21T00:00:00.000Z');
    expect(computeSnapshotRetentionDate([], NOW, 10)).toEqual('2026-09-21T00:00:00.000Z');
  });
});

describe('Knowledge snapshot run budget', () => {
  const retryIds = (count: number) => Array.from({ length: count }, (_, index) => `retry-${index}`);

  it('should give the whole budget to the discovery when nothing waits for a retry', () => {
    expect(splitRunBudget([], 10000)).toEqual({ retried: [], deferred: [], discoveryBudget: 10000 });
  });

  it('should count the retries in the budget of the run', () => {
    const { retried, deferred, discoveryBudget } = splitRunBudget(retryIds(1000), 10000);
    expect(retried).toHaveLength(1000);
    expect(deferred).toEqual([]);
    expect(retried.length + discoveryBudget).toEqual(10000);
  });

  it('should keep half of the budget for the discovery and defer the other retries', () => {
    const { retried, deferred, discoveryBudget } = splitRunBudget(retryIds(1000), 101);
    expect(retried).toEqual(retryIds(50));
    expect(deferred).toEqual(retryIds(1000).slice(50));
    expect(discoveryBudget).toEqual(51);
  });
});

describe('Change digest messages', () => {
  const summary: LandscapeDiffEntitySummary = {
    entity_id: 'id',
    entity_type: 'Intrusion-Set',
    name: 'APT-TEST',
    created_in_period: false,
    revoked_in_period: false,
    attributes_changed: 2,
    relationships_added: 3,
    relationships_removed: 1,
    relationships_revoked: 0,
    relationships_confidence_changed: 0,
    confidence_before: 50,
    confidence_after: 75,
    score_before: null,
    score_after: null,
    change_score: 12,
  };

  it('should summarize the changes of an entity', () => {
    expect(buildChangeMessage(summary)).toEqual('`3` new relationships, `1` removed relationship, `2` attributes changed, and confidence `50` -> `75`');
    expect(buildChangeMessage({ ...summary, created_in_period: true, relationships_added: 0, relationships_removed: 0, attributes_changed: 0, confidence_before: null }))
      .toEqual('created');
    expect(buildChangeMessage({ ...summary, attributes_changed: 1, confidence_before: null, score_before: 10, score_after: 40 }))
      .toEqual('`3` new relationships, `1` removed relationship, `1` attribute changed, and score `10` -> `40`');
    // An entity whose only change is the confidence of its relationships still gets a line
    const confidenceOnly = { ...summary, relationships_added: 0, relationships_removed: 0, attributes_changed: 0, confidence_before: null, relationships_confidence_changed: 2 };
    expect(buildChangeMessage(confidenceOnly)).toEqual('`2` confidence changes on relationships');
  });

  it('should write the changes of an entity in the language of the recipient', () => {
    expect(buildChangeMessage({ ...summary, relationships_added: 1 }, resolveChangeDigestLocale('fr-fr')))
      .toEqual('`1` nouvelle relation, `1` relation supprimée, `2` attributs modifiés et confiance `50` -> `75`');
    expect(buildChangeMessage({ ...summary, relationships_removed: 0, attributes_changed: 0, confidence_before: null }, resolveChangeDigestLocale('de-de')))
      .toEqual('`3` neue Beziehungen');
  });

  it('should take the plural rules of the language', () => {
    const russian = resolveChangeDigestLocale('ru-ru');
    expect(formatChangeDigestMessage(russian, 'relationships_added', { count: 1 })).toEqual('`1` новая связь');
    expect(formatChangeDigestMessage(russian, 'relationships_added', { count: 3 })).toEqual('`3` новые связи');
    expect(formatChangeDigestMessage(russian, 'relationships_added', { count: 5 })).toEqual('`5` новых связей');
    expect(formatChangeDigestMessage(russian, 'relationships_added', { count: 21 })).toEqual('`21` новая связь');
    expect(formatChangeDigestMessage(russian, 'relationships_confidence_changed', { count: 3 })).toEqual('`3` изменения уровня доверия связей');
    expect(formatChangeDigestMessage(resolveChangeDigestLocale('ja-jp'), 'relationships_added', { count: 3 })).toEqual('`3` 件の新しいリレーションシップ');
    expect(formatChangeDigestMessage(DEFAULT_CHANGE_DIGEST_LOCALE, 'relationships_added', { count: 1234 })).toEqual('`1,234` new relationships');
    expect(formatChangeDigestMessage(DEFAULT_CHANGE_DIGEST_LOCALE, 'entities_changed', { changed: 1, total: 1 })).toEqual('`1` of `1` entity changed');
  });

  it('should write a digest in the profile language, else the platform language, else English', () => {
    expect(resolveChangeDigestLocale('fr-fr', 'de-de')).toEqual({ language: 'fr', locale: 'fr-fr' });
    expect(resolveChangeDigestLocale('auto', 'zh-cn')).toEqual({ language: 'zh', locale: 'zh-cn' });
    expect(resolveChangeDigestLocale(undefined, 'ko-kr')).toEqual({ language: 'ko', locale: 'ko-kr' });
    expect(resolveChangeDigestLocale('auto', 'auto')).toEqual(DEFAULT_CHANGE_DIGEST_LOCALE);
    expect(resolveChangeDigestLocale('xx-yy', null)).toEqual(DEFAULT_CHANGE_DIGEST_LOCALE);
    expect(resolveChangeDigestLocale(null, undefined)).toEqual(DEFAULT_CHANGE_DIGEST_LOCALE);
  });

  it('should summarize the landscape aggregates', () => {
    const aggregates = {
      entities_in_scope: 10,
      entities_changed: 4,
      new_relationships: 12,
      removed_relationships: 2,
      revocations: 1,
      new_techniques: [{ id: 't', entity_type: 'Attack-Pattern', name: 'T1059', count: 2 }],
      new_techniques_count: 1,
      new_malware: [],
      new_malware_count: 0,
      new_tools: [],
      new_tools_count: 0,
      new_infrastructure_count: 3,
    } as unknown as LandscapeDiffAggregates;
    expect(buildAggregatesMessage(aggregates))
      .toEqual('`4` of `10` entities changed, `12` new relationships, `2` removed relationships, `1` revocation, `1` new technique, and `3` new infrastructure');
    // The named lists are capped, the message uses the totals
    const capped = { ...aggregates, new_malware: [{ id: 'm', entity_type: 'Malware', name: 'Malware', count: 1 }], new_malware_count: 120, new_tools_count: 75 };
    expect(buildAggregatesMessage(capped)).toContain('`120` new malware, `75` new tools');
    expect(buildAggregatesMessage(aggregates, { listed: 4 })).not.toContain('not listed');
    expect(buildAggregatesMessage(aggregates, { listed: 1 })).toContain('`3` other changed entities not listed');
    expect(buildAggregatesMessage(aggregates, { partial: false })).not.toContain('partial result');
    expect(buildAggregatesMessage(aggregates, { partial: true })).toContain(' | partial result: the filter set exceeds the limits of a change digest');
    expect(buildAggregatesMessage(aggregates, { listed: 3, locale: resolveChangeDigestLocale('fr-fr') }))
      .toEqual('`4` entités modifiées sur `10`, `12` nouvelles relations, `2` relations supprimées, `1` révocation, `1` nouvelle technique, '
        + '`3` nouvelles infrastructures et `1` autre entité modifiée non listée');
  });

  it('should never broaden the scope of a digest with malformed filters', () => {
    expect(parseTriggerFilters(null)).toBeNull();
    expect(parseTriggerFilters(JSON.stringify({ mode: 'and', filters: [], filterGroups: [] }))).toBeNull();
    const filters = { mode: 'and', filters: [{ key: ['name'], values: ['APT'], operator: 'eq', mode: 'or' }], filterGroups: [] };
    expect(parseTriggerFilters(JSON.stringify(filters))).toEqual(filters);
    expect(() => parseTriggerFilters('{not json')).toThrow('Change digest filters are malformed');
  });
});

describe('Landscape diff scopes', () => {
  it('should map saved filter list scopes to entity types', () => {
    expect(savedFilterScopeEntityTypes('intrusionSets')).toEqual(['Intrusion-Set']);
    expect(savedFilterScopeEntityTypes('malwares')).toEqual(['Malware']);
    // The scope is the storage key of the list, whatever its spelling
    expect(savedFilterScopeEntityTypes('indicators-list')).toEqual(['Indicator']);
    expect(savedFilterScopeEntityTypes('administrative-areas')).toEqual(['Administrative-Area']);
    expect(savedFilterScopeEntityTypes('securityPlatform')).toEqual(['SecurityPlatform']);
    expect(savedFilterScopeEntityTypes('caseIncidents')).toEqual(['Case-Incident']);
    expect(savedFilterScopeEntityTypes('unknown-list')).toBeNull();
    expect(savedFilterScopeEntityTypes(undefined)).toBeNull();
  });

  it('should only map saved filter scopes to entity types a landscape diff accepts', () => {
    Object.values(SAVED_FILTER_SCOPES).flat().forEach((type) => {
      expect(isStixCoreObject(type), type).toBe(true);
    });
  });

  it('should list every entity named by a landscape result', () => {
    const aggregates = {
      new_techniques: [{ id: 'technique', entity_type: 'Attack-Pattern', name: 'T1059', count: 1 }],
      new_malware: [{ id: 'malware', entity_type: 'Malware', name: 'Malware', count: 1 }],
      new_tools: [],
      new_infrastructure: [{ id: 'infrastructure', entity_type: 'Infrastructure', name: 'C2', count: 1 }],
      new_victims_by_sector: [{ key: 'sector', label: 'Finance', count: 1 }],
      new_victims_by_country: [{ key: 'country', label: 'France', count: 1 }],
      new_victims_by_region: [],
    } as unknown as LandscapeDiffAggregates;
    const entities = [{ entity_id: 'intrusion-set' }, { entity_id: 'malware' }] as unknown as LandscapeDiffEntitySummary[];
    expect(landscapeResultReferencedIds(aggregates, entities).sort())
      .toEqual(['country', 'infrastructure', 'intrusion-set', 'malware', 'sector', 'technique']);
    expect(landscapeResultReferencedIds(null, [])).toEqual([]);
  });
});
