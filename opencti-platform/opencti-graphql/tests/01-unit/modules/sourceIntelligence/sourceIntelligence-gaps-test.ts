import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import {
  countRelationshipsByValue,
  hubCatalogStatusOf,
  latestCompatibleContractsBySlug,
  mergeRecommendedConnectors,
} from '../../../../src/modules/sourceIntelligence/sourceIntelligence-gaps';
import type { CollectionGapRecommendedConnector } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-types';
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
      new Set(['opencti/connector-beta']),
      3,
    );
    expect(merged.map((connector) => [connector.slug, connector.origin, connector.deployed])).toEqual([
      ['gamma', 'catalog', false],
      ['alpha', 'hub', false],
      ['beta', 'hub', true],
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
    const [alpha] = mergeRecommendedConnectors([hubMatch('alpha', 40)], [], contracts, new Set(), 3);
    expect(alpha.contract_image).toEqual('opencti/connector-alpha:6.9.0');
    expect(latestCompatibleContractsBySlug(contracts).get('alpha')?.contract_version).toEqual('6.9.0');
    // Without any compatible contract the recommendation cannot be deployed from this platform
    const [onlyIncompatible] = mergeRecommendedConnectors([hubMatch('alpha', 40)], [], [contracts[1]], new Set(), 3);
    expect(onlyIncompatible.contract_image).toBeNull();
  });

  it('should keep at most the requested number of recommendations', () => {
    const merged = mergeRecommendedConnectors([hubMatch('alpha', 40)], [localMatch('gamma', 70), localMatch('delta', 20)], [], new Set(), 2);
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
});
