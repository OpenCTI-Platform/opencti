import { describe, expect, it } from 'vitest';
import {
  buildSourceIndicatorFilters,
  connectorMatchesCatalogEntry,
  evaluateSourceRules,
  imageRepositoryOf,
  parseIsoDurationMs,
  type RuleInput,
  toIsoDuration,
} from '../../../../src/modules/sourceIntelligence/sourceIntelligence-rules';
import { DEFAULT_SOURCE_INTELLIGENCE_SETTINGS } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-settings';
import type { BasicStoreEntitySource, StoreSourceScorecard } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-types';

const settings = DEFAULT_SOURCE_INTELLIGENCE_SETTINGS;

const connectorSource = {
  internal_id: 'source-1',
  id: 'source-1',
  name: 'Feed vendor',
  source_kind: 'connector',
  ref_id: 'connector-1',
  source_user_ids: ['user-1'],
  enabled: true,
  quarantined: false,
} as unknown as BasicStoreEntitySource;

const scorecard = (overrides: Partial<StoreSourceScorecard> = {}): StoreSourceScorecard => ({
  id: 'scorecard-1',
  internal_id: 'scorecard-1',
  standard_id: 'scorecard-1',
  entity_type: 'SourceScorecard',
  base_type: 'ENTITY',
  parent_types: [],
  source_id: 'source-1',
  source_kind: 'connector',
  source_name: 'Feed vendor',
  scorecard_period: 'LAST_30_DAYS',
  period_start: '2026-09-03T00:00:00.000Z',
  period_end: '2026-10-03T00:00:00.000Z',
  scorecard_date: '2026-10-03',
  computed_at: '2026-10-03T02:00:00.000Z',
  created_at: '2026-10-03T02:00:00.000Z',
  updated_at: '2026-10-03T02:00:00.000Z',
  is_live: true,
  volume_total: 1000,
  volume_entities: 800,
  volume_relationships: 200,
  volume_indicators: 600,
  volume_observables: 100,
  new_objects: 900,
  volume_last_day: 30,
  unique_count: 300,
  unique_contribution: 0.3,
  corroborated_count: 200,
  corroboration_rate: 0.2,
  shared_count: 700,
  lead_time_hours: 2,
  first_reporter_share: 0.6,
  evaluated_count: 600,
  revoked_count: 10,
  negative_sightings_count: 2,
  false_positive_count: 1,
  decay_excluded_count: 0,
  accuracy: 0.85,
  pir_matched_count: 50,
  relevance: 0.05,
  sightings_count: 20,
  security_platform_sightings_count: 5,
  incidents_count: 0,
  impact_score: 40,
  unreferenced_count: 100,
  unsighted_count: 500,
  expired_count: 20,
  noise_count: 200,
  noise: 0.2,
  source_last_asserted_at: '2026-10-03T01:00:00.000Z',
  freshness_hours: 1,
  median_latency_hours: 3,
  actionable_count: 500,
  cost_per_actionable_object: null,
  cost_currency: null,
  value_score: 60,
  overlap: [],
  ...overrides,
});

const input = (overrides: Partial<RuleInput> = {}): RuleInput => ({
  source: connectorSource,
  scorecard: scorecard(),
  longScorecard: scorecard({ scorecard_period: 'LAST_90_DAYS' }),
  peerScorecards: new Map(),
  peerNames: new Map(),
  settings,
  sourceUser: { id: 'user-1', name: '[C] Feed vendor', service_account: true, shared: false, user_max_confidence: 80, effective_max_confidence: 80 },
  connector: { id: 'connector-1', managed: true, schedule: { key: 'CONNECTOR_DURATION_PERIOD', value: 'PT24H' }, requested_status: 'starting' },
  feed: null,
  maxDecayRuleOrder: 3,
  ...overrides,
});

const kinds = (proposals: ReturnType<typeof evaluateSourceRules>) => proposals.map((p) => p.kind).sort();

describe('Source intelligence rules', () => {
  it('should parse and format ISO durations', () => {
    expect(parseIsoDurationMs('PT24H')).toEqual(24 * 3600 * 1000);
    expect(parseIsoDurationMs('P1D')).toEqual(24 * 3600 * 1000);
    expect(parseIsoDurationMs('garbage')).toBeNull();
    expect(parseIsoDurationMs(null)).toBeNull();
    expect(toIsoDuration(90 * 60000)).toEqual('PT1H30M');
    expect(toIsoDuration(2 * 3600 * 1000)).toEqual('PT2H');
    expect(toIsoDuration(10)).toEqual('PT1M');
  });

  it('should target the indicators of the source in a decay rule filter', () => {
    expect(JSON.parse(buildSourceIndicatorFilters(connectorSource) as string).filters[0]).toEqual({ key: ['creator_id'], values: ['user-1'], operator: 'eq', mode: 'or' });
    const author = { ...connectorSource, source_kind: 'author', ref_id: 'identity-1' } as BasicStoreEntitySource;
    expect(JSON.parse(buildSourceIndicatorFilters(author) as string).filters[0].key).toEqual(['createdBy']);
    expect(buildSourceIndicatorFilters({ ...connectorSource, source_user_ids: [] } as BasicStoreEntitySource)).toBeNull();
  });

  it('should only accept the recommended catalog connector for a deployment, whatever its version', () => {
    const entry = { catalog_id: 'filigran-catalog', slug: 'misp', contract_image: 'opencti/connector-misp:6.9.0' };
    expect(connectorMatchesCatalogEntry({ catalog_id: 'filigran-catalog', manager_contract: { slug: 'misp' } }, entry)).toBe(true);
    // An older or newer version of the entry, deployed or upgraded, is the same connector
    expect(connectorMatchesCatalogEntry({ catalog_id: null, manager_contract_image: 'opencti/connector-misp:6.8.0' }, entry)).toBe(true);
    expect(connectorMatchesCatalogEntry({ manager_contract_image: 'opencti/connector-misp@sha256:0f1e' }, entry)).toBe(true);
    // The catalog identifier names the whole catalog: another entry of the same catalog is another connector
    expect(connectorMatchesCatalogEntry({ catalog_id: 'filigran-catalog', manager_contract: { slug: 'mitre' }, manager_contract_image: 'opencti/connector-mitre:6.9.0' }, entry)).toBe(false);
    expect(connectorMatchesCatalogEntry({ catalog_id: 'filigran-catalog', manager_contract_image: 'opencti/connector-misp-feed:6.9.0' }, entry)).toBe(false);
    // An externally deployed connector carries neither identifier and cannot fulfil the recommendation
    expect(connectorMatchesCatalogEntry({}, entry)).toBe(false);
    expect(connectorMatchesCatalogEntry({ catalog_id: null }, { catalog_id: null, slug: null, contract_image: null })).toBe(false);
  });

  it('should compare image repositories without their tag, digest or registry port confusion', () => {
    expect(imageRepositoryOf('opencti/connector-misp:6.9.0')).toBe('opencti/connector-misp');
    expect(imageRepositoryOf('opencti/connector-misp@sha256:0f1e')).toBe('opencti/connector-misp');
    expect(imageRepositoryOf('registry.local:5000/opencti/connector-misp')).toBe('registry.local:5000/opencti/connector-misp');
    expect(imageRepositoryOf('registry.local:5000/opencti/connector-misp:6.9.0')).toBe('registry.local:5000/opencti/connector-misp');
    expect(imageRepositoryOf(null)).toBeNull();
  });

  it('should propose nothing for a healthy source', () => {
    expect(evaluateSourceRules(input())).toEqual([]);
  });

  it('should never propose anything for a disabled source or below the minimum volume', () => {
    expect(evaluateSourceRules(input({ source: { ...connectorSource, enabled: false } as BasicStoreEntitySource, scorecard: scorecard({ accuracy: 0.1 }) }))).toEqual([]);
    expect(evaluateSourceRules(input({ scorecard: scorecard({ accuracy: 0.1, volume_total: 10 }) }))).toEqual([]);
  });

  it('should lower the confidence of an inaccurate source', () => {
    const proposals = evaluateSourceRules(input({ scorecard: scorecard({ accuracy: 0.6 }) }));
    expect(kinds(proposals)).toEqual(['lower_confidence']);
    expect(proposals[0].payload).toEqual({ target: 'user', user_id: 'user-1', current_max_confidence: 80, proposed_max_confidence: 65 });
    expect(proposals[0].fingerprint).toEqual('lower_confidence:source-1');
  });

  it('should quarantine a very inaccurate source instead of only lowering its confidence', () => {
    const proposals = evaluateSourceRules(input({ scorecard: scorecard({ accuracy: 0.3 }) }));
    expect(kinds(proposals)).toEqual(['quarantine']);
    expect(proposals[0].payload).toEqual({ target: 'connector_user', user_id: 'user-1' });
  });

  it('should never tune a user shared by several sources', () => {
    const sharedUser = { id: 'user-1', name: 'admin', service_account: false, shared: true, user_max_confidence: null, effective_max_confidence: 100 };
    expect(evaluateSourceRules(input({ sourceUser: sharedUser, scorecard: scorecard({ accuracy: 0.3 }) }))).toEqual([]);
  });

  it('should raise the confidence of an accurate and corroborated source', () => {
    const proposals = evaluateSourceRules(input({ scorecard: scorecard({ accuracy: 0.97, corroboration_rate: 0.7 }) }));
    expect(kinds(proposals)).toEqual(['raise_confidence']);
    expect(proposals[0].payload.proposed_max_confidence).toEqual(95);
  });

  it('should add a decay rule for a noisy source producing indicators', () => {
    const proposals = evaluateSourceRules(input({ scorecard: scorecard({ noise: 0.8 }) }));
    expect(kinds(proposals)).toEqual(['add_decay_rule']);
    expect(proposals[0].payload).toMatchObject({ decay_lifetime: settings.tuning.noisy_decay_lifetime_days, order: 4 });
    expect(evaluateSourceRules(input({ scorecard: scorecard({ noise: 0.8, volume_indicators: 0 }) }))).toEqual([]);
  });

  it('should propose a deny list when enough false positives are labelled', () => {
    expect(kinds(evaluateSourceRules(input({ scorecard: scorecard({ false_positive_count: 25 }) })))).toEqual(['add_deny_list']);
  });

  it('should retire a redundant source that brings nothing new and comes later', () => {
    const peer = scorecard({ source_id: 'source-2', lead_time_hours: 5 });
    const proposals = evaluateSourceRules(input({
      scorecard: scorecard({ unique_contribution: 0.01, lead_time_hours: -4, overlap: [{ source_id: 'source-2', shared_count: 950, share: 0.95 }] }),
      peerScorecards: new Map([['source-2', peer]]),
      peerNames: new Map([['source-2', 'Better vendor']]),
    }));
    expect(kinds(proposals)).toEqual(['retire']);
    expect(proposals[0].payload).toMatchObject({ target: 'connector', connector_id: 'connector-1', managed: true, peer_source_id: 'source-2' });
    expect(proposals[0].rationale).toContain('Better vendor');
  });

  it('should retire a redundant ingestion feed only when it is running', () => {
    const feedSource = { ...connectorSource, source_kind: 'ingestion_feed', ref_id: 'feed-1' } as BasicStoreEntitySource;
    const feed = { id: 'feed-1', entity_type: 'IngestionTaxii', scheduling_period: 'PT6H', ingestion_running: true };
    const redundant = {
      source: feedSource,
      connector: null,
      scorecard: scorecard({ unique_contribution: 0.01, lead_time_hours: -4, overlap: [{ source_id: 'source-2', shared_count: 950, share: 0.95 }] }),
      peerScorecards: new Map([['source-2', scorecard({ source_id: 'source-2', lead_time_hours: 5 })]]),
    };
    const proposals = evaluateSourceRules(input({ ...redundant, feed }));
    expect(kinds(proposals)).toEqual(['retire']);
    expect(proposals[0].payload).toMatchObject({ target: 'ingestion_feed', feed_id: 'feed-1', feed_type: 'IngestionTaxii' });
    expect(evaluateSourceRules(input({ ...redundant, feed: { ...feed, ingestion_running: false } }))).toEqual([]);
  });

  it('should keep a redundant source that reports first', () => {
    const peer = scorecard({ source_id: 'source-2', lead_time_hours: -6 });
    expect(evaluateSourceRules(input({
      scorecard: scorecard({ unique_contribution: 0.01, lead_time_hours: 6, overlap: [{ source_id: 'source-2', shared_count: 950, share: 0.95 }] }),
      peerScorecards: new Map([['source-2', peer]]),
    }))).toEqual([]);
  });

  it('should run a stale managed connector more often, never below the minimum schedule', () => {
    const proposals = evaluateSourceRules(input({ longScorecard: scorecard({ scorecard_period: 'LAST_90_DAYS', freshness_hours: 200 }) }));
    expect(kinds(proposals)).toEqual(['change_schedule']);
    expect(proposals[0].payload).toMatchObject({ target: 'connector', current_value: 'PT24H', proposed_value: 'PT12H' });
    const fastConnector = { id: 'connector-1', managed: true, schedule: { key: 'CONNECTOR_DURATION_PERIOD', value: 'PT1H' }, requested_status: null };
    expect(evaluateSourceRules(input({
      connector: fastConnector,
      longScorecard: scorecard({ scorecard_period: 'LAST_90_DAYS', freshness_hours: 200 }),
    }))).toEqual([]);
  });

  it('should reschedule a stale ingestion feed only when it is running', () => {
    const feedSource = { ...connectorSource, source_kind: 'ingestion_feed', ref_id: 'feed-1' } as BasicStoreEntitySource;
    const feed = { id: 'feed-1', entity_type: 'IngestionTaxii', scheduling_period: 'PT6H', ingestion_running: true };
    const stale = scorecard({ scorecard_period: 'LAST_90_DAYS', freshness_hours: 100 });
    const proposals = evaluateSourceRules(input({ source: feedSource, feed, connector: null, longScorecard: stale }));
    expect(kinds(proposals)).toEqual(['change_schedule']);
    expect(proposals[0].payload).toMatchObject({ target: 'ingestion_feed', feed_id: 'feed-1', proposed_value: 'PT3H' });
    expect(evaluateSourceRules(input({ source: feedSource, feed: { ...feed, ingestion_running: false }, connector: null, longScorecard: stale }))).toEqual([]);
  });
});
