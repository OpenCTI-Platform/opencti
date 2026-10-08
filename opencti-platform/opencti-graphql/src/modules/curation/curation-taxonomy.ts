import vendorTaxonomy from './data/vendor-taxonomy.json';
import { canonicalizeName, type TaxonomyFamily } from './curation-normalization';

interface RawTaxonomyCluster {
  k: TaxonomyFamily;
  n: string[];
  r: string;
}

interface RawTaxonomy {
  version: string;
  sources: Array<{ id: string; name: string; license: string; url: string }>;
  clusters: RawTaxonomyCluster[];
}

export interface TaxonomyCluster {
  ref: string;
  source: string;
  family: TaxonomyFamily;
  names: string[];
  canonicals: Set<string>;
}

export interface TaxonomyMatch {
  cluster: TaxonomyCluster;
  leftName: string;
  rightName: string;
}

// MITRE ATT&CK clusters are curated per object, vendor aggregations are broader and noisier.
const SOURCE_RELIABILITY: Record<string, number> = {
  mitre: 0.85,
  'misp-threat-actor': 0.7,
  'misp-malpedia': 0.75,
};

export const getTaxonomySourceReliability = (source: string) => SOURCE_RELIABILITY[source] ?? 0.6;

let clusters: TaxonomyCluster[] | undefined;
let index: Map<string, number[]> | undefined;

const familyEntityType = (family: TaxonomyFamily) => {
  if (family === 'actor') return 'Intrusion-Set';
  if (family === 'software') return 'Malware';
  return 'Campaign';
};

const indexKey = (family: TaxonomyFamily, canonical: string) => `${family}|${canonical}`;

const loadTaxonomy = () => {
  if (clusters && index) {
    return { clusters, index };
  }
  const raw = vendorTaxonomy as RawTaxonomy;
  const loadedClusters: TaxonomyCluster[] = [];
  const loadedIndex = new Map<string, number[]>();
  raw.clusters.forEach((rawCluster) => {
    const canonicals = new Set<string>();
    rawCluster.n.forEach((name) => {
      canonicalizeName(name, familyEntityType(rawCluster.k)).full.forEach((canonical) => canonicals.add(canonical));
    });
    if (canonicals.size < 2) {
      return;
    }
    const position = loadedClusters.length;
    loadedClusters.push({
      ref: rawCluster.r,
      source: rawCluster.r.split(':')[0],
      family: rawCluster.k,
      names: rawCluster.n,
      canonicals,
    });
    canonicals.forEach((canonical) => {
      const key = indexKey(rawCluster.k, canonical);
      const positions = loadedIndex.get(key);
      if (positions) {
        positions.push(position);
      } else {
        loadedIndex.set(key, [position]);
      }
    });
  });
  clusters = loadedClusters;
  index = loadedIndex;
  return { clusters, index };
};

export const getTaxonomyMetadata = () => {
  const raw = vendorTaxonomy as RawTaxonomy;
  return { version: raw.version, sources: raw.sources, clusters: loadTaxonomy().clusters.length };
};

/**
 * Clusters containing at least one of the given canonical forms.
 */
export const findTaxonomyClusters = (canonicals: Iterable<string>, family: TaxonomyFamily): TaxonomyCluster[] => {
  const { clusters: allClusters, index: allIndex } = loadTaxonomy();
  const positions = new Set<number>();
  for (const canonical of canonicals) {
    (allIndex.get(indexKey(family, canonical)) ?? []).forEach((position) => positions.add(position));
  }
  return [...positions].map((position) => allClusters[position]);
};

const nameForCanonical = (names: string[], canonical: string, entityType: string) => {
  return names.find((name) => canonicalizeName(name, entityType).full.has(canonical)) ?? canonical;
};

/**
 * Find a single vendor taxonomy cluster that holds a name of each entity: both names are known aliases of the same
 * object for at least one source. Clusters are never chained, a match always comes from one cluster only.
 */
export const findSharedTaxonomyCluster = (
  family: TaxonomyFamily,
  left: { names: string[]; canonicals: Set<string>; entityType: string },
  right: { names: string[]; canonicals: Set<string>; entityType: string },
): TaxonomyMatch | undefined => {
  const candidates = findTaxonomyClusters(left.canonicals, family);
  let best: TaxonomyMatch | undefined;
  candidates.forEach((cluster) => {
    const leftCanonical = [...left.canonicals].find((canonical) => cluster.canonicals.has(canonical));
    const rightCanonical = [...right.canonicals].find((canonical) => cluster.canonicals.has(canonical));
    if (!leftCanonical || !rightCanonical || leftCanonical === rightCanonical) {
      return;
    }
    const match: TaxonomyMatch = {
      cluster,
      leftName: nameForCanonical(left.names, leftCanonical, left.entityType),
      rightName: nameForCanonical(right.names, rightCanonical, right.entityType),
    };
    if (!best || getTaxonomySourceReliability(cluster.source) > getTaxonomySourceReliability(best.cluster.source)) {
      best = match;
    }
  });
  return best;
};

/**
 * Aliases known by the taxonomy for an entity and missing from it. Only clusters whose primary name (first name of the
 * cluster) is one of the entity names are used, so that a loose synonym never pulls a whole foreign cluster in.
 */
export const suggestTaxonomyAliases = (
  family: TaxonomyFamily,
  entity: { names: string[]; canonicals: Set<string>; entityType: string },
): Array<{ cluster: TaxonomyCluster; aliases: string[] }> => {
  const suggestions: Array<{ cluster: TaxonomyCluster; aliases: string[] }> = [];
  findTaxonomyClusters(entity.canonicals, family).forEach((cluster) => {
    const primaryCanonicals = canonicalizeName(cluster.names[0], entity.entityType).full;
    const isPrimaryMatch = [...primaryCanonicals].some((canonical) => entity.canonicals.has(canonical));
    if (!isPrimaryMatch) {
      return;
    }
    const aliases = cluster.names.filter((name) => {
      const forms = canonicalizeName(name, entity.entityType).full;
      return forms.size > 0 && ![...forms].some((canonical) => entity.canonicals.has(canonical));
    });
    if (aliases.length > 0) {
      suggestions.push({ cluster, aliases });
    }
  });
  return suggestions;
};
