import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { hubCatalogStatusOf, mergeRecommendedConnectors } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-gaps';
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

  it('should keep at most the requested number of recommendations', () => {
    const merged = mergeRecommendedConnectors([hubMatch('alpha', 40)], [localMatch('gamma', 70), localMatch('delta', 20)], [], new Set(), 2);
    expect(merged.map((connector) => connector.slug)).toEqual(['gamma', 'alpha']);
  });
});
