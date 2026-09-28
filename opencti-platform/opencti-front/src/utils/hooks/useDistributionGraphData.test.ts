import { describe, expect, it } from 'vitest';
import { buildDistributionRedirectionUtils, type DistributionQueryData } from './useDistributionGraphData';

/**
 * ApexCharts reports the index of the clicked bar, and every other builder in
 * this module maps one entry per bucket. A builder that drops entries instead
 * shifts every following index, so a click resolves a neighbouring bucket.
 */
describe('buildDistributionRedirectionUtils', () => {
  const data = [
    { label: 'A', value: 1, entity: { id: 'a', entity_type: 'Malware' } },
    { label: 'B', value: 2, entity: null },
    { label: 'C', value: 3, entity: { id: 'c', entity_type: 'Tool' } },
  ] as DistributionQueryData;

  it('keeps one entry per bucket, aligned by index', () => {
    const result = buildDistributionRedirectionUtils(data);
    expect(result).toHaveLength(3);
    expect(result[0]).toMatchObject({ id: 'a', entity_type: 'Malware' });
    expect(result[1]).toBeNull();
    expect(result[2]).toMatchObject({ id: 'c', entity_type: 'Tool' });
  });

  it('stays aligned when the very first buckets have no entity', () => {
    const leadingGaps = [
      { label: 'A', value: 1, entity: null },
      { label: 'B', value: 2, entity: null },
      { label: 'C', value: 3, entity: { id: 'c', entity_type: 'Tool' } },
    ] as DistributionQueryData;
    expect(buildDistributionRedirectionUtils(leadingGaps)[2]).toMatchObject({ id: 'c' });
  });

  it('treats a bucket without an entity id as a gap rather than an entry', () => {
    const noId = [{ label: 'A', value: 1, entity: { entity_type: 'Malware' } }] as DistributionQueryData;
    expect(buildDistributionRedirectionUtils(noId)).toEqual([null]);
  });

  it('reports a workspace through its own type', () => {
    const workspace = [
      { label: 'W', value: 1, entity: { id: 'w', entity_type: 'Workspace', type: 'dashboard' } },
    ] as DistributionQueryData;
    expect(buildDistributionRedirectionUtils(workspace)[0]).toMatchObject({ entity_type: 'dashboard' });
  });

  it('keeps a null bucket as a gap', () => {
    expect(buildDistributionRedirectionUtils([null, undefined] as DistributionQueryData)).toEqual([null, null]);
  });
});
