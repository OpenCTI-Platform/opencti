import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import {
  buildAddConnectorProposal,
  computeGapCoverageScore,
  countCoveringRelationshipsPerSource,
  countRelationshipsByValue,
  criterionKey,
  extractCriterionFacets,
  hubCatalogStatusOf,
  hubQueriesBudget,
  latestCompatibleContractsBySlug,
  matchLocalCatalog,
  mergeRecommendedConnectors,
  resolveFacets,
  scoreCoverageMatch,
} from '../../../../src/modules/sourceIntelligence/sourceIntelligence-gaps';
import { buildSourceResolver } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-provenance';
import { recommendationFingerprint } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-rules';
import { DEFAULT_SOURCE_INTELLIGENCE_SETTINGS } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-settings';
import {
  type BasicStoreEntitySource,
  type CollectionGapRecommendedConnector,
  RECOMMENDATION_ADD_CONNECTOR,
  SOURCE_KIND_AUTHOR,
  SOURCE_KIND_CONNECTOR,
} from '../../../../src/modules/sourceIntelligence/sourceIntelligence-types';
import type { BasicStoreEntityCatalogContract } from '../../../../src/modules/catalog/catalog-types';
import type { HubIntegrationCoverageMatch } from '../../../../src/modules/xtm/hub/xtm-hub-client';
import { type FilterGroup, PirType } from '../../../../src/generated/graphql';

const hubMatch = (slug: string, score: number): HubIntegrationCoverageMatch => ({
  id: `hub-${slug}`,
  slug,
  name: `Hub ${slug}`,
  short_description: null,
  integration_type: 'connector',
  license_type: null,
  verified: true,
  manager_supported: true,
  object_types: ['Malware'],
  sectors: [],
  regions: [],
  coverage_inferred: false,
  matched_object_types: ['Malware'],
  matched_sectors: [],
  matched_regions: [],
  score,
});

const localMatch = (slug: string, score: number): CollectionGapRecommendedConnector => ({
  slug,
  title: `Local ${slug}`,
  origin: 'catalog',
  score,
  contract_image: `opencti/connector-${slug}`,
  manager_supported: true,
  deployed: false,
  matched_object_types: ['Malware'],
  matched_sectors: [],
  matched_regions: [],
});

const contract = (slug: string) => ({ slug, catalog_id: 'catalog-1', image: `opencti/connector-${slug}`, manager_supported: true }) as unknown as BasicStoreEntityCatalogContract;

describe('Source intelligence collection gaps', () => {
  it('should spend the XTM Hub time budget of a run across its requests, failed ones included', async () => {
    let clock = 0;
    const budget = hubQueriesBudget(1000, () => clock);
    const slowRequest = (durationMs: number, fail = false) => async () => {
      clock += durationMs;
      if (fail) throw new Error('XTM Hub timeout');
      return 'done';
    };
    await expect(budget.track(slowRequest(400))).resolves.toBe('done');
    expect(budget.exhausted()).toBe(false);
    await expect(budget.track(slowRequest(500, true))).rejects.toThrow('XTM Hub timeout');
    expect(budget.spentMs()).toBe(900);
    expect(budget.exhausted()).toBe(false);
    await budget.track(slowRequest(100));
    expect(budget.exhausted()).toBe(true);
  });

  it('should report a truncated XTM Hub ranking as partial, never as complete', () => {
    expect(hubCatalogStatusOf({ status: 'ok', matches: [], truncated: false })).toBe('ok');
    expect(hubCatalogStatusOf({ status: 'ok', matches: [], truncated: true })).toBe('partial');
    expect(hubCatalogStatusOf({ status: 'unreachable', matches: [], truncated: false })).toBe('unreachable');
    expect(hubCatalogStatusOf({ status: 'error', matches: [], truncated: false })).toBe('error');
  });

  it('should combine XTM Hub and local catalog matches by score, deployed connectors last', () => {
    const merged = mergeRecommendedConnectors(
      [hubMatch('alpha', 40), hubMatch('beta', 90)],
      [localMatch('beta', 10), localMatch('gamma', 70)],
      [contract('alpha'), contract('beta')],
      [{ manager_contract_image: 'opencti/connector-beta' }],
      3,
    );
    expect(merged.map((connector) => [connector.slug, connector.origin, connector.deployed])).toEqual([
      ['gamma', 'catalog', false],
      ['alpha', 'hub', false],
      ['beta', 'hub', true],
    ]);
  });

  it('should count a connector deployed from another version of a recommended entry as deployed, never another entry of its catalog', () => {
    const versioned = (slug: string, version: string) => ({
      ...contract(slug), contract_version: version, image: `opencti/connector-${slug}:${version}`,
    }) as unknown as BasicStoreEntityCatalogContract;
    const contracts = [versioned('alpha', '6.9.0'), versioned('beta', '6.9.0')];
    const merged = mergeRecommendedConnectors([hubMatch('alpha', 40), hubMatch('beta', 90)], [], contracts, [
      // Deployed from an older version of alpha, then never upgraded
      { catalog_id: 'catalog-1', manager_contract: { slug: 'alpha' }, manager_contract_image: 'opencti/connector-alpha:6.8.0' },
      // Another entry of the same catalog
      { catalog_id: 'catalog-1', manager_contract: { slug: 'delta' }, manager_contract_image: 'opencti/connector-delta:6.9.0' },
    ], 3);
    expect(merged.map((connector) => [connector.slug, connector.contract_image, connector.deployed])).toEqual([
      ['beta', 'opencti/connector-beta:6.9.0', false],
      ['alpha', 'opencti/connector-alpha:6.9.0', true],
    ]);
  });

  it('should deploy the latest compatible contract version for an XTM Hub recommendation', () => {
    const version = (contractVersion: string, image: string, extra: Record<string, unknown> = {}) => ({
      ...contract('alpha'), contract_version: contractVersion, image, ...extra,
    }) as unknown as BasicStoreEntityCatalogContract;
    const contracts = [
      version('6.8.0', 'opencti/connector-alpha:6.8.0'),
      // Newer, but requires a platform that does not exist yet
      version('99.0.0', 'opencti/connector-alpha:99.0.0', { min_version: '99.0.0' }),
      version('6.9.0', 'opencti/connector-alpha:6.9.0'),
      version('6.7.0', 'opencti/connector-alpha:6.7.0'),
    ];
    const [alpha] = mergeRecommendedConnectors([hubMatch('alpha', 40)], [], contracts, [], 3);
    expect(alpha.contract_image).toEqual('opencti/connector-alpha:6.9.0');
    expect(latestCompatibleContractsBySlug(contracts).get('alpha')?.contract_version).toEqual('6.9.0');
    // Without any compatible contract the recommendation cannot be deployed from this platform
    const [onlyIncompatible] = mergeRecommendedConnectors([hubMatch('alpha', 40)], [], [contracts[1]], [], 3);
    expect(onlyIncompatible.contract_image).toBeNull();
  });

  it('should keep at most the requested number of recommendations', () => {
    const merged = mergeRecommendedConnectors([hubMatch('alpha', 40)], [localMatch('gamma', 70), localMatch('delta', 20)], [], [], 2);
    expect(merged.map((connector) => connector.slug)).toEqual(['gamma', 'alpha']);
  });

  it('should count every covering source, page after page', async () => {
    const page = (from: number, size: number) => Array.from({ length: size }, (_, i) => ({ key: { id: `source-${from + i}` }, doc_count: 1 }));
    const requests: Array<Record<string, any>> = [];
    const aggregate = async (aggregations: Record<string, any>) => {
      requests.push(aggregations.values.composite);
      return requests.length === 1
        ? { values: { buckets: page(0, 1000), after_key: { id: 'source-999' } } }
        : { values: { buckets: page(1000, 3), after_key: { id: 'source-1002' } } };
    };
    const counts = await countRelationshipsByValue(aggregate, 'creator_id.keyword');
    expect(counts.size).toBe(1003);
    expect(requests.length).toBe(2);
    expect(requests[0]).toEqual({ size: 1000, sources: [{ id: { terms: { field: 'creator_id.keyword' } } }] });
    expect(requests[1].after).toEqual({ id: 'source-999' });
  });

  it('should credit the relationships to their creators and their author', () => {
    const source = (internalId: string, kind: string, refId: string, userIds: string[] = []) => ({
      internal_id: internalId, source_kind: kind, ref_id: refId, source_user_ids: userIds,
    }) as unknown as BasicStoreEntitySource;
    const resolver = buildSourceResolver([
      source('source-author', SOURCE_KIND_AUTHOR, 'identity-1'),
      source('source-connector', SOURCE_KIND_CONNECTOR, 'connector-1', ['user-1']),
    ]);
    const perSource = countCoveringRelationshipsPerSource(resolver, {
      // 7 relationships created by the connector user, 1 by an unknown user
      creators: new Map([['user-1', 7], ['user-unknown', 1]]),
      // 10 relationships authored by the identity, 3 by an identity that is not a source
      authors: new Map([['identity-1', 10], ['identity-unknown', 3]]),
    });
    expect(Object.fromEntries(perSource)).toEqual({ 'source-author': 10, 'source-connector': 7 });
  });

  it('should credit no source with the relationships of a user shared by several connectors', () => {
    const source = (internalId: string, refId: string, userIds: string[]) => ({
      internal_id: internalId, source_kind: SOURCE_KIND_CONNECTOR, ref_id: refId, source_user_ids: userIds,
    }) as unknown as BasicStoreEntitySource;
    const resolver = buildSourceResolver([
      source('source-connector-a', 'connector-a', ['user-shared']),
      source('source-connector-b', 'connector-b', ['user-shared']),
      source('source-connector-c', 'connector-c', ['user-c']),
    ]);
    const perSource = countCoveringRelationshipsPerSource(resolver, {
      creators: new Map([['user-shared', 5], ['user-c', 2]]),
      authors: new Map(),
    });
    expect(Object.fromEntries(perSource)).toEqual({ 'source-connector-c': 2 });
  });

  it('should read the targets, relationship types and source types of a criterion in every nested group', () => {
    const facets = extractCriterionFacets({
      mode: 'and',
      filters: [
        { key: ['toId'], values: ['sector-1', 'sector-1', 'country-1'] },
        { key: ['relationship_type'], values: ['targets'] },
      ],
      filterGroups: [{
        mode: 'or',
        // A single key is accepted as well as a list, and only string values are facets
        filters: [{ key: 'fromTypes', values: ['Malware', 42] }, { key: ['toId'], values: ['country-1'] }],
        filterGroups: [],
      }],
    } as unknown as FilterGroup);
    expect(facets).toEqual({ targetIds: ['sector-1', 'country-1'], relationshipTypes: ['targets'], fromTypes: ['Malware'] });
    expect(extractCriterionFacets(null)).toEqual({ targetIds: [], relationshipTypes: [], fromTypes: [] });
  });

  it('should resolve a criterion into the object types, sectors and regions a catalog entry must cover', () => {
    const targets = [
      { entity_type: 'Sector', name: 'Energy' },
      { entity_type: 'Country', name: 'France' },
      { entity_type: 'Vulnerability', name: 'CVE-2024-0001' },
    ];
    // A threat landscape without source types expects the threats targeting the sector or region
    expect(resolveFacets(PirType.ThreatLandscape, { targetIds: [], relationshipTypes: [], fromTypes: [] }, targets)).toEqual({
      objectTypes: ['Intrusion-Set', 'Malware', 'Campaign', 'Threat-Actor-Group', 'Vulnerability', 'Indicator'],
      sectors: ['Energy'],
      regions: ['France'],
      label: 'related to Energy, France, CVE-2024-0001',
    });
    // The source types and relationship types of the criterion win over the PIR type
    expect(resolveFacets(PirType.ThreatOrigin, { targetIds: [], relationshipTypes: ['targets', 'uses'], fromTypes: ['Malware'] }, [])).toEqual({
      objectTypes: ['Malware', 'Indicator'],
      sectors: [],
      regions: [],
      label: 'targets, uses',
    });
    expect(resolveFacets(PirType.ThreatCustom, { targetIds: [], relationshipTypes: [], fromTypes: [] }, []).objectTypes).toEqual(['Indicator']);
  });

  it('should score the coverage of a criterion from its volume, its sources and its freshness, within 0 and 100', () => {
    const { gaps } = DEFAULT_SOURCE_INTELLIGENCE_SETTINGS;
    expect(computeGapCoverageScore({ recent: 0, window: 0, distinctSources: 0 }, gaps)).toBe(0);
    expect(computeGapCoverageScore({ recent: gaps.target_relationships, window: gaps.target_relationships, distinctSources: gaps.target_sources }, gaps)).toBe(100);
    // Volume 10/50, one source of 3, a quarter of the window in the recent period
    expect(computeGapCoverageScore({ recent: 10, window: 40, distinctSources: 1 }, gaps)).toBe(26);
    expect(computeGapCoverageScore({ recent: 500, window: 100, distinctSources: 30 }, gaps)).toBe(100);
  });

  it('should score a catalog match on the families the criterion requests only', () => {
    const facets = { objectTypes: ['Malware', 'Indicator'], sectors: ['Energy'], regions: [], label: 'related to Energy' };
    expect(scoreCoverageMatch(facets, { objectTypes: ['Malware'], sectors: ['Energy'], regions: [] }, 0.6)).toBe(0.45);
    expect(scoreCoverageMatch({ objectTypes: [], sectors: [], regions: [], label: 'related to' }, { objectTypes: [], sectors: [], regions: [] }, 0.6)).toBe(0);
  });

  it('should match the local catalog on the latest compatible contract covering the sector or region of the criterion', () => {
    const catalogContract = (slug: string, version: string, text: Record<string, unknown>) => ({
      slug,
      catalog_id: 'catalog-1',
      contract_version: version,
      image: `opencti/connector-${slug}:${version}`,
      manager_supported: true,
      verified: true,
      title: slug,
      short_description: null,
      description: null,
      use_cases: [],
      solution_categories: [],
      ...text,
    }) as unknown as BasicStoreEntityCatalogContract;
    const contracts = [
      catalogContract('energy-feed', '1.0.0', { title: 'Energy threat feed', short_description: 'Malware and indicators targeting the energy sector' }),
      catalogContract('energy-feed', '0.9.0', { title: 'Energy threat feed', short_description: 'Malware and indicators targeting the energy sector' }),
      catalogContract('energy-reports', '1.0.0', { title: 'Energy reports', min_version: '99.0.0' }),
      catalogContract('malware-samples', '1.0.0', { title: 'Malware samples', use_cases: ['Sandbox'] }),
      catalogContract('banking-feed', '1.0.0', { title: 'Banking threat feed', solution_categories: ['Banking indicators'] }),
    ];
    const sectorFacets = { objectTypes: ['Malware', 'Indicator'], sectors: ['Energy'], regions: [], label: 'related to Energy' };
    // A criterion with a sector needs an entry covering it, newer contracts requiring another platform are left out
    expect(matchLocalCatalog(sectorFacets, contracts)).toEqual([{
      slug: 'energy-feed',
      title: 'Energy threat feed',
      short_description: 'Malware and indicators targeting the energy sector',
      origin: 'catalog',
      score: 0.6,
      catalog_id: 'catalog-1',
      contract_image: 'opencti/connector-energy-feed:1.0.0',
      manager_supported: true,
      verified: true,
      deployed: false,
      coverage_inferred: true,
      matched_object_types: ['Malware', 'Indicator'],
      matched_sectors: ['Energy'],
      matched_regions: [],
    }]);
    // Without sector or region, any entry covering one of the object types matches, with a score per family covered
    const typeFacets = { objectTypes: ['Malware'], sectors: [], regions: [], label: 'related to' };
    const scores = Object.fromEntries(matchLocalCatalog(typeFacets, contracts).map((match) => [match.slug, match.score]));
    expect(scores).toEqual({ 'energy-feed': 0.6, 'malware-samples': 0.6 });
  });

  it('should explain an add connector proposal with the coverage of the gap and what the connector covers', () => {
    const gap = {
      internal_id: 'gap-1',
      pir_id: 'pir-1',
      criterion_key: criterionKey('{"mode":"and","filters":[],"filterGroups":[]}'),
      criterion_label: 'targets Energy',
      gap_coverage_score: 12,
      recent_relationships: 3,
      matched_relationships: 8,
      distinct_sources: 1,
    };
    expect(gap.criterion_key).toMatch(/^[0-9a-f]{32}$/);
    const proposal = buildAddConnectorProposal(gap, 'Energy PIR', { ...localMatch('energy-feed', 0.6), matched_sectors: ['Energy'] }, 30);
    expect(proposal).toMatchObject({
      kind: RECOMMENDATION_ADD_CONNECTOR,
      source_id: null,
      fingerprint: recommendationFingerprint(RECOMMENDATION_ADD_CONNECTOR, 'pir-1', gap.criterion_key, 'energy-feed'),
      name: 'Deploy Local energy-feed for Energy PIR',
      payload: { pir_id: 'pir-1', collection_gap_id: 'gap-1', slug: 'energy-feed', contract_image: 'opencti/connector-energy-feed', origin: 'catalog' },
      evidence: { coverage_score: 12, recent_relationships: 3, matched_relationships: 8, distinct_sources: 1 },
    });
    expect(proposal.rationale).toBe('The criterion "targets Energy" of the PIR Energy PIR has a coverage of 12/100 (3 relationships in the last 30 days from 1 sources). '
      + 'Local energy-feed covers Malware, Energy.');
    const bare = buildAddConnectorProposal(gap, 'Energy PIR', { ...localMatch('energy-feed', 0.6), matched_object_types: [] }, 30);
    expect(bare.rationale.endsWith('Local energy-feed covers this criterion.')).toBe(true);
  });
});
