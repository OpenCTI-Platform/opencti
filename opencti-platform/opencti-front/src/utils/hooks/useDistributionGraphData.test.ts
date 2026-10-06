import { describe, expect, it } from 'vitest';
import { buildDistributionBuckets, buildDistributionRedirectionUtils, type DistributionQueryData } from './useDistributionGraphData';

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

describe('buildDistributionBuckets', () => {
  it('carries the raw label, never the displayed one', () => {
    const data = [{ label: 'Intrusion-Set', value: 3, entity: null }] as DistributionQueryData;
    expect(buildDistributionBuckets(data)).toEqual([
      { kind: 'distribution', rawValue: 'Intrusion-Set', entityId: null },
    ]);
  });

  it('carries the entity id when the bucket resolves to one', () => {
    const data = [{ label: 'author-1', value: 2, entity: { id: 'author-1', entity_type: 'Organization' } }] as DistributionQueryData;
    expect(buildDistributionBuckets(data)[0]).toEqual({
      kind: 'distribution',
      rawValue: 'author-1',
      entityId: 'author-1',
    });
  });

  it('stays index-aligned with the series by keeping gaps', () => {
    const data = [
      null,
      { label: 'B', value: 1, entity: null },
    ] as DistributionQueryData;
    expect(buildDistributionBuckets(data)).toEqual([
      null,
      { kind: 'distribution', rawValue: 'B', entityId: null },
    ]);
  });
});
