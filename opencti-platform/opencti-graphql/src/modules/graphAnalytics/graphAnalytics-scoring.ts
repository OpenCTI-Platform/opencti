import { GRAPH_FEATURE_FAMILIES, type GraphFeatureFamily, type GraphFeatureProfile, type GraphFeatureSets } from './graphAnalytics-types';

// Relative weight of each feature family in the weighted Jaccard index.
// Rare and specific evidence (certificates, nameservers, malware) weighs more than broad context (victims, ASN).
export const GRAPH_FEATURE_WEIGHTS: Record<GraphFeatureFamily, number> = {
  techniques: 1,
  tools: 1.5,
  malware: 2,
  infrastructure: 2,
  victims: 0.5,
  certificates: 3,
  asn: 0.5,
  registrar: 1,
  nameservers: 2,
  hosting: 1.5,
  reports: 0.75,
  objects: 1,
};

// Share of the final score taken by the structural (relationship type profile) part.
export const STRUCTURAL_SCORE_WEIGHT = 0.15;

export interface GraphSimilarityScore {
  score: number;
  jaccard: number;
  structural: number;
  shared: GraphFeatureSets;
  shared_count: number;
}

const round = (value: number) => Math.round(value * 10000) / 10000;

export const intersect = (a: string[], b: string[]): string[] => {
  if (a.length === 0 || b.length === 0) return [];
  const [small, large] = a.length <= b.length ? [a, b] : [b, a];
  const largeSet = new Set(large);
  return Array.from(new Set(small.filter((value) => largeSet.has(value))));
};

const unionSize = (a: string[], b: string[]): number => new Set([...a, ...b]).size;

/**
 * Weighted Jaccard index over feature families: sum of weighted intersections divided by sum of weighted unions.
 * Families absent from both sides do not contribute.
 */
export const weightedJaccard = (
  a: GraphFeatureSets,
  b: GraphFeatureSets,
  weights: Record<GraphFeatureFamily, number> = GRAPH_FEATURE_WEIGHTS,
): { value: number; shared: GraphFeatureSets; sharedCount: number } => {
  let numerator = 0;
  let denominator = 0;
  let sharedCount = 0;
  const shared: GraphFeatureSets = {};
  for (let i = 0; i < GRAPH_FEATURE_FAMILIES.length; i += 1) {
    const family = GRAPH_FEATURE_FAMILIES[i];
    const left = a[family] ?? [];
    const right = b[family] ?? [];
    if (left.length === 0 && right.length === 0) continue;
    const common = intersect(left, right);
    const weight = weights[family];
    numerator += weight * common.length;
    denominator += weight * unionSize(left, right);
    if (common.length > 0) {
      shared[family] = common.sort();
      sharedCount += common.length;
    }
  }
  return { value: denominator === 0 ? 0 : numerator / denominator, shared, sharedCount };
};

/** Cosine similarity of two sparse count vectors. */
export const cosineSimilarity = (a: Record<string, number>, b: Record<string, number>): number => {
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  let dot = 0;
  let normA = 0;
  let normB = 0;
  keys.forEach((key) => {
    const x = a[key] ?? 0;
    const y = b[key] ?? 0;
    dot += x * y;
    normA += x * x;
    normB += y * y;
  });
  if (normA === 0 || normB === 0) return 0;
  return dot / (Math.sqrt(normA) * Math.sqrt(normB));
};

/**
 * Score between two profiles. Without any shared evidence the score is 0, whatever the structural
 * resemblance: a similarity must always be explainable by the elements listed in `shared`.
 */
export const computeSimilarityScore = (a: GraphFeatureProfile, b: GraphFeatureProfile): GraphSimilarityScore => {
  const { value: jaccard, shared, sharedCount } = weightedJaccard(a.features, b.features);
  if (sharedCount === 0) {
    return { score: 0, jaccard: 0, structural: 0, shared: {}, shared_count: 0 };
  }
  const structural = cosineSimilarity(a.relation_vector, b.relation_vector);
  const score = (1 - STRUCTURAL_SCORE_WEIGHT) * jaccard + STRUCTURAL_SCORE_WEIGHT * structural;
  return {
    score: round(score),
    jaccard: round(jaccard),
    structural: round(structural),
    shared,
    shared_count: sharedCount,
  };
};

export interface RankedSimilarity extends GraphSimilarityScore {
  target_id: string;
  target_type: string;
}

/** Top-N most similar candidates, ties broken by the amount of shared evidence then by id for determinism. */
export const rankSimilarProfiles = (
  source: GraphFeatureProfile,
  candidates: GraphFeatureProfile[],
  topN: number,
  minScore: number,
): RankedSimilarity[] => {
  const ranked: RankedSimilarity[] = [];
  for (let i = 0; i < candidates.length; i += 1) {
    const candidate = candidates[i];
    if (candidate.id === source.id) continue;
    const result = computeSimilarityScore(source, candidate);
    if (result.shared_count > 0 && result.score >= minScore) {
      ranked.push({ ...result, target_id: candidate.id, target_type: candidate.entity_type });
    }
  }
  ranked.sort((x, y) => (y.score - x.score) || (y.shared_count - x.shared_count) || x.target_id.localeCompare(y.target_id));
  return ranked.slice(0, topN);
};

/** Number of shared elements weighted by family, used to pre-rank candidates before loading their full profile. */
export const weightedSharedCount = (sharedByFamily: Partial<Record<GraphFeatureFamily, number>>): number => {
  return Object.entries(sharedByFamily)
    .reduce((acc, [family, count]) => acc + (GRAPH_FEATURE_WEIGHTS[family as GraphFeatureFamily] ?? 1) * (count ?? 0), 0);
};
