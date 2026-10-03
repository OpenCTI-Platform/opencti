import { v5 as uuidv5 } from 'uuid';
import { OPENCTI_NAMESPACE } from '../../schema/general';
import type { GraphClusterFeature, GraphClusterKind, GraphFeatureFamily, GraphFeatureSets } from './graphAnalytics-types';

export interface ClusteringMember {
  id: string;
  type: string;
  features: GraphFeatureSets;
}

export interface ClusteringOptions {
  families: GraphFeatureFamily[];
  // a feature shared by more members than this is too common to be discriminative (shared hosting, big ASN...)
  maxFeatureFanout: number;
  minClusterSize: number;
  maxFeaturesPerFamily?: number;
  maxRepresentatives?: number;
}

export interface ComputedCluster {
  anchor: string;
  members: string[];
  representative_ids: string[];
  features: GraphClusterFeature[];
}

// The anchor is the smallest member internal id: adding members rarely changes it, so ids stay stable across runs.
// The same rule is implemented by the opencti-analytics process. The id is provisional: when a run is published,
// matchClusterLineage gives a computed cluster the id of the previous cluster it continues.
export const buildGraphClusterId = (kind: GraphClusterKind, anchor: string): string => {
  return uuidv5(`graph-cluster:${kind}:${anchor}`, OPENCTI_NAMESPACE);
};

export interface ClusterLineageOverlap {
  next: string; // cluster computed by the run being published
  previous: string; // published cluster the members belonged to
  members: number; // members of `next` that belonged to `previous`
}

/**
 * Identity of the clusters of a run: a computed cluster continues the previous cluster most of whose members it holds,
 * and takes its id, so promotions, creation date and membership dates survive anchors moving as communities evolve.
 * Matches are made by decreasing overlap, one previous cluster per computed cluster and conversely; an id still
 * computed by the run is never given to another cluster. Returns the renames, computed id to previous id.
 */
export const matchClusterLineage = (overlaps: ClusterLineageOverlap[], previousSizes: Map<string, number>): Map<string, string> => {
  const computedIds = new Set(overlaps.map((overlap) => overlap.next));
  const matchedNext = new Set<string>();
  const matchedPrevious = new Set<string>();
  const renames = new Map<string, string>();
  const ordered = [...overlaps].sort((a, b) => (b.members - a.members) || a.next.localeCompare(b.next) || a.previous.localeCompare(b.previous));
  ordered.forEach(({ next, previous, members }) => {
    if (matchedNext.has(next) || matchedPrevious.has(previous)) return;
    // the computed cluster must hold the majority of the previous one to continue it
    if (members * 2 <= (previousSizes.get(previous) ?? 0)) return;
    matchedNext.add(next);
    matchedPrevious.add(previous);
    if (next !== previous && !computedIds.has(previous)) renames.set(next, previous);
  });
  return renames;
};

export const buildGraphClusterName = (kind: GraphClusterKind, clusterId: string): string => {
  // Never derived from member values: a cluster name is visible to users who may not access every member.
  const prefix = kind.charAt(0).toUpperCase() + kind.slice(1);
  return `${prefix} cluster ${clusterId.substring(0, 8).toUpperCase()}`;
};

class UnionFind {
  private parent = new Map<string, string>();

  find(x: string): string {
    let root = this.parent.get(x) ?? x;
    if (!this.parent.has(x)) this.parent.set(x, x);
    while (root !== (this.parent.get(root) ?? root)) {
      root = this.parent.get(root) as string;
    }
    // path compression
    let current = x;
    while (current !== root) {
      const next = this.parent.get(current) as string;
      this.parent.set(current, root);
      current = next;
    }
    return root;
  }

  union(a: string, b: string) {
    const ra = this.find(a);
    const rb = this.find(b);
    if (ra === rb) return;
    // deterministic: the smallest id becomes the root
    if (ra < rb) this.parent.set(rb, ra);
    else this.parent.set(ra, rb);
  }
}

/**
 * Connected components of the member graph where two members are linked when they share
 * a discriminative feature (shared by at least 2 and at most `maxFeatureFanout` members).
 */
export const computeFeatureClusters = (members: ClusteringMember[], opts: ClusteringOptions): ComputedCluster[] => {
  const maxFeaturesPerFamily = opts.maxFeaturesPerFamily ?? 50;
  const maxRepresentatives = opts.maxRepresentatives ?? 5;
  const featureMembers = new Map<string, { family: GraphFeatureFamily; id: string; members: string[] }>();
  members.forEach((member) => {
    opts.families.forEach((family) => {
      (member.features[family] ?? []).forEach((featureId) => {
        if (featureId === member.id) return;
        const key = `${family}:${featureId}`;
        const entry = featureMembers.get(key) ?? { family, id: featureId, members: [] };
        entry.members.push(member.id);
        featureMembers.set(key, entry);
      });
    });
  });
  const linking = Array.from(featureMembers.values())
    .filter((f) => f.members.length >= 2 && f.members.length <= opts.maxFeatureFanout);
  const uf = new UnionFind();
  linking.forEach((feature) => {
    for (let i = 1; i < feature.members.length; i += 1) {
      uf.union(feature.members[0], feature.members[i]);
    }
  });
  const components = new Map<string, Set<string>>();
  linking.forEach((feature) => {
    feature.members.forEach((memberId) => {
      const root = uf.find(memberId);
      const component = components.get(root) ?? new Set<string>();
      component.add(memberId);
      components.set(root, component);
    });
  });
  const clusters: ComputedCluster[] = [];
  components.forEach((componentSet, root) => {
    if (componentSet.size < opts.minClusterSize) return;
    const componentMembers = Array.from(componentSet).sort();
    const componentFeatures = linking.filter((f) => uf.find(f.members[0]) === root);
    const linkCount = new Map<string, number>();
    componentFeatures.forEach((f) => f.members.forEach((m) => linkCount.set(m, (linkCount.get(m) ?? 0) + 1)));
    const representatives = [...componentMembers]
      .sort((a, b) => ((linkCount.get(b) ?? 0) - (linkCount.get(a) ?? 0)) || a.localeCompare(b))
      .slice(0, maxRepresentatives);
    const byFamily = new Map<GraphFeatureFamily, Array<{ id: string; count: number }>>();
    componentFeatures.forEach((f) => {
      const list = byFamily.get(f.family) ?? [];
      list.push({ id: f.id, count: f.members.length });
      byFamily.set(f.family, list);
    });
    const features: GraphClusterFeature[] = Array.from(byFamily.entries())
      .map(([family, list]) => ({
        family,
        ids: list.sort((a, b) => (b.count - a.count) || a.id.localeCompare(b.id)).slice(0, maxFeaturesPerFamily).map((l) => l.id),
      }))
      .sort((a, b) => a.family.localeCompare(b.family));
    clusters.push({ anchor: componentMembers[0], members: componentMembers, representative_ids: representatives, features });
  });
  return clusters.sort((a, b) => (b.members.length - a.members.length) || a.anchor.localeCompare(b.anchor));
};
