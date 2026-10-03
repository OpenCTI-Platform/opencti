import { describe, expect, it } from 'vitest';
import { buildGraphClusterId, buildGraphClusterName, computeFeatureClusters, type ClusteringMember } from '../../../../src/modules/graphAnalytics/graphAnalytics-clustering';

const member = (id: string, features: ClusteringMember['features']): ClusteringMember => ({ id, type: 'Domain-Name', features });

describe('graph analytics clustering', () => {
  it('should build the same deterministic ids as the opencti-analytics process', () => {
    expect(buildGraphClusterId('infrastructure', '0a6f0f2e-4b4e-4f5e-9c3a-1d2e3f4a5b6c')).toBe('495765b1-3336-546c-9008-64acd11a1449');
    expect(buildGraphClusterId('campaign', '11111111-2222-4333-8444-555555555555')).toBe('155deb88-fd53-5237-b6fa-05f09a5983af');
  });

  it('should never derive a cluster name from member values', () => {
    const name = buildGraphClusterName('infrastructure', '495765b1-3336-546c-9008-64acd11a1449');
    expect(name).toBe('Infrastructure cluster 495765B1');
  });

  it('should link members sharing discriminative features into connected components', () => {
    const members = [
      member('d1', { certificates: ['cert-a'] }),
      member('d2', { certificates: ['cert-a'], nameservers: ['ns-1'] }),
      member('d3', { nameservers: ['ns-1'] }),
      member('d4', { hosting: ['ip-9'] }),
      member('d5', { hosting: ['ip-9'] }),
      member('d6', { asn: ['as-1'] }),
    ];
    const clusters = computeFeatureClusters(members, { families: ['certificates', 'nameservers', 'hosting', 'asn'], maxFeatureFanout: 10, minClusterSize: 2 });
    expect(clusters.map((c) => c.members)).toEqual([['d1', 'd2', 'd3'], ['d4', 'd5']]);
    expect(clusters[0].anchor).toBe('d1');
    expect(clusters[0].representative_ids[0]).toBe('d2');
    expect(clusters[0].features).toEqual([
      { family: 'certificates', ids: ['cert-a'] },
      { family: 'nameservers', ids: ['ns-1'] },
    ]);
  });

  it('should ignore features shared by too many members and small components', () => {
    const members = Array.from({ length: 6 }, (_, i) => member(`m${i}`, { asn: ['big-asn'], certificates: i < 2 ? ['c1'] : [] }));
    const clusters = computeFeatureClusters(members, { families: ['asn', 'certificates'], maxFeatureFanout: 5, minClusterSize: 3 });
    expect(clusters).toEqual([]);
    const smaller = computeFeatureClusters(members, { families: ['asn', 'certificates'], maxFeatureFanout: 5, minClusterSize: 2 });
    expect(smaller.map((c) => c.members)).toEqual([['m0', 'm1']]);
  });

  it('should ignore families that are not selected and self references', () => {
    const members = [member('a', { reports: ['r1'], hosting: ['a'] }), member('b', { reports: ['r1'], hosting: ['a'] })];
    expect(computeFeatureClusters(members, { families: ['certificates'], maxFeatureFanout: 10, minClusterSize: 2 })).toEqual([]);
    const byHosting = computeFeatureClusters(members, { families: ['hosting'], maxFeatureFanout: 10, minClusterSize: 2 });
    expect(byHosting).toEqual([]);
  });
});
