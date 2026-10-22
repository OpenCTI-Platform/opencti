import { describe, expect, it } from 'vitest';
import {
  buildDisplacedGraphClusterId,
  buildGraphClusterId,
  buildGraphClusterName,
  computeFeatureClusters,
  type ClusteringMember,
  matchClusterLineage,
} from '../../../../src/modules/graphAnalytics/graphAnalytics-clustering';

const member = (id: string, features: ClusteringMember['features']): ClusteringMember => ({ id, type: 'Domain-Name', features });
const displaced = (id: string) => `${id}-displaced`;

describe('graph analytics cluster lineage', () => {
  it('should keep the id of a growing cluster whose anchor moved', () => {
    // previous cluster P (10 members) now computed as C with 8 of them plus new members
    const renames = matchClusterLineage([{ next: 'C', previous: 'P', members: 8 }], new Map([['P', 10]]), displaced);
    expect(renames.get('C')).toBe('P');
  });

  it('should not continue a cluster holding a minority of the previous members', () => {
    const renames = matchClusterLineage([{ next: 'C', previous: 'P', members: 5 }], new Map([['P', 10]]), displaced);
    expect(renames.size).toBe(0);
  });

  it('should give a split cluster its id once, to the part holding most of it', () => {
    const renames = matchClusterLineage([
      { next: 'C1', previous: 'P', members: 7 },
      { next: 'C2', previous: 'P', members: 6 },
    ], new Map([['P', 12]]), displaced);
    expect(renames.get('C1')).toBe('P');
    expect(renames.has('C2')).toBe(false);
  });

  it('should keep the larger lineage when clusters merge', () => {
    const renames = matchClusterLineage([
      { next: 'C', previous: 'P1', members: 6 },
      { next: 'C', previous: 'P2', members: 4 },
    ], new Map([['P1', 6], ['P2', 4]]), displaced);
    expect(renames).toEqual(new Map([['C', 'P1']]));
  });

  it('should give a split cluster its id when the old anchor stayed in the minority, and move the minority', () => {
    // C holds 9 of the 12 members of P, the 3-member fragment holding the old anchor computed the provisional id P
    const renames = matchClusterLineage([
      { next: 'C', previous: 'P', members: 9 },
      { next: 'P', previous: 'P', members: 3 },
    ], new Map([['P', 12]]), displaced);
    expect(renames).toEqual(new Map([['C', 'P'], ['P', 'P-displaced']]));
  });

  it('should not move a fragment continuing another previous cluster', () => {
    const renames = matchClusterLineage([
      { next: 'C', previous: 'P', members: 9 },
      { next: 'P', previous: 'Q', members: 3 },
      { next: 'P', previous: 'P', members: 2 },
    ], new Map([['P', 11], ['Q', 4]]), displaced);
    expect(renames).toEqual(new Map([['C', 'P'], ['P', 'Q']]));
  });

  it('should build a deterministic id for a displaced cluster, different for each run', () => {
    expect(buildDisplacedGraphClusterId('P', 'run-1')).toBe(buildDisplacedGraphClusterId('P', 'run-1'));
    expect(buildDisplacedGraphClusterId('P', 'run-1')).not.toBe(buildDisplacedGraphClusterId('P', 'run-2'));
  });

  it('should move a cluster whose provisional id is a previous cluster it does not continue', () => {
    // previous P = {A, B, C, D}; computed {A, E, F} keeps the anchor A, hence the provisional id P, with 1 of 4 members
    const renames = matchClusterLineage([{ next: 'P', previous: 'P', members: 1 }], new Map([['P', 4]]), displaced);
    expect(renames).toEqual(new Map([['P', 'P-displaced']]));
  });

  it('should leave clusters keeping their computed id untouched', () => {
    expect(matchClusterLineage([{ next: 'P', previous: 'P', members: 9 }], new Map([['P', 10]]), displaced).size).toBe(0);
  });
});

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
