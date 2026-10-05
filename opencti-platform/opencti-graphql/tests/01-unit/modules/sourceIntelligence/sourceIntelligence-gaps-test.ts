import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import {
  countCoveringRelationshipsPerSource,
  countRelationshipsByValue,
  countRelationshipsWithValueListed,
  hubCatalogStatusOf,
  hubQueriesBudget,
  latestCompatibleContractsBySlug,
  mergeRecommendedConnectors,
} from '../../../../src/modules/sourceIntelligence/sourceIntelligence-gaps';
import { buildSourceResolver } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-provenance';
import {
  type BasicStoreEntitySource,
  type CollectionGapRecommendedConnector,
  SOURCE_KIND_AUTHOR,
  SOURCE_KIND_CONNECTOR,
} from '../../../../src/modules/sourceIntelligence/sourceIntelligence-types';
import type { BasicStoreEntityCatalogContract } from '../../../../src/modules/catalog/catalog-types';
import type { HubIntegrationCoverageMatch } from '../../../../src/modules/xtm/hub/xtm-hub-client';

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

  it('should count the relationships whose author is also one of their asserting sources, page after page', async () => {
    const requests: Array<Record<string, any>> = [];
    const aggregate = async (aggregations: Record<string, any>) => {
      requests.push(aggregations.pairs.composite);
      const pair = (value: string, listed: string, docCount: number) => ({ key: { value, listed }, doc_count: docCount });
      return requests.length === 1
        ? { pairs: { buckets: [pair('author-a', 'author-a', 4), pair('author-a', 'author-b', 2), ...Array.from({ length: 998 }, (_, i) => pair(`x-${i}`, `y-${i}`, 1))], after_key: { value: 'x-997', listed: 'y-997' } } }
        : { pairs: { buckets: [pair('author-b', 'author-b', 3)], after_key: { value: 'author-b', listed: 'author-b' } } };
    };
    const counts = await countRelationshipsWithValueListed(aggregate, 'rel_created-by.internal_id.keyword', 'x_opencti_assertion_source_ids.keyword');
    expect(Object.fromEntries(counts)).toEqual({ 'author-a': 4, 'author-b': 3 });
    expect(requests[0].sources).toEqual([
      { value: { terms: { field: 'rel_created-by.internal_id.keyword' } } },
      { listed: { terms: { field: 'x_opencti_assertion_source_ids.keyword' } } },
    ]);
    expect(requests[1].after).toEqual({ value: 'x-997', listed: 'y-997' });
  });

  it('should count a relationship once for an author that also asserted it', () => {
    const source = (internalId: string, kind: string, refId: string, userIds: string[] = []) => ({
      internal_id: internalId, source_kind: kind, ref_id: refId, source_user_ids: userIds,
    }) as unknown as BasicStoreEntitySource;
    const resolver = buildSourceResolver([
      source('source-author', SOURCE_KIND_AUTHOR, 'identity-1'),
      source('source-connector', SOURCE_KIND_CONNECTOR, 'connector-1', ['user-1']),
    ]);
    const perSource = countCoveringRelationshipsPerSource(resolver, {
      // 6 relationships asserted by the author, 5 by the connector
      assertions: new Map([['identity-1', 6], ['connector-1', 5]]),
      // 2 relationships without assertions created by the connector user
      creators: new Map([['user-1', 2]]),
      // 10 relationships authored by the identity, 6 of them also asserted by it
      authors: new Map([['identity-1', 10], ['identity-unknown', 3]]),
      authorAssertions: new Map([['identity-1', 6]]),
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
      assertions: new Map([['connector-a', 3]]),
      creators: new Map([['user-shared', 5], ['user-c', 2]]),
      authors: new Map(),
      authorAssertions: new Map(),
    });
    expect(Object.fromEntries(perSource)).toEqual({ 'source-connector-a': 3, 'source-connector-c': 2 });
  });

  it('should keep the author fallback when the author is not tracked through its assertions', () => {
    const resolver = buildSourceResolver([
      { internal_id: 'source-author', source_kind: SOURCE_KIND_AUTHOR, ref_id: 'identity-1', source_user_ids: [] } as unknown as BasicStoreEntitySource,
    ]);
    const perSource = countCoveringRelationshipsPerSource(resolver, {
      assertions: new Map(),
      creators: new Map(),
      authors: new Map([['identity-1', 4]]),
      authorAssertions: new Map(),
    });
    expect(perSource.get('source-author')).toBe(4);
  });
});
