import { CoverageInformation } from './SecurityCoverage-types';

export interface CoveredEntityLike {
  readonly relationship_id?: string;
  readonly coverage_information?: ReadonlyArray<CoverageInformation> | null;
  readonly to?: { readonly id?: string | null; readonly name?: string | null } | null;
}

export type CoverageMap = Map<string, CoverageInformation[]>;

/**
 * Builds a map from entity id to its averaged coverage entries.
 *
 * A Security Coverage aggregates multiple Security Coverage Results, each
 * producing a distinct `has-covered` relation toward the same entity with its
 * own scores. This deduplicates by entity id and averages the scores per
 * `coverage_name` (rounded), mirroring the backend `getAverageCoverageInformation`.
 *
 * @param entities Flat list of covered entities from a SecurityCoverage.
 * @returns Map of averages: Map<entityId, CoverageInformation[]>.
 */
export const buildAverageCoverageMap = (
  entities: ReadonlyArray<CoveredEntityLike>,
): CoverageMap => {
  const scoresByEntity = new Map<string, Map<string, number[]>>();
  for (const entity of entities) {
    const entityId = entity?.to?.id;
    if (!entityId) continue;
    if (!scoresByEntity.has(entityId)) {
      scoresByEntity.set(entityId, new Map());
    }
    const byName = scoresByEntity.get(entityId)!;
    for (const info of entity.coverage_information ?? []) {
      const existing = byName.get(info.coverage_name) ?? [];
      existing.push(info.coverage_score);
      byName.set(info.coverage_name, existing);
    }
  }

  const result: CoverageMap = new Map();
  scoresByEntity.forEach((byName, entityId) => {
    const coverageInformation: CoverageInformation[] = [];
    byName.forEach((scores, coverageName) => {
      const average = Math.round(scores.reduce((sum, score) => sum + score, 0) / scores.length);
      coverageInformation.push({ coverage_name: coverageName, coverage_score: average });
    });
    result.set(entityId, coverageInformation);
  });

  return result;
};

/**
 * Deduplicates covered entities to a single entry per entity id.
 *
 * The first occurrence wins (preserving input ordering and its `relationship_id`
 * used for the popover and relation link), and its `coverage_information` is
 * replaced by the averaged values across all results covering that entity.
 *
 * @param entities Flat list of covered entities (one per has-covered relation).
 * @returns One entry per distinct entity with averaged coverage information.
 */
export const dedupeCoveredEntities = <T extends CoveredEntityLike>(
  entities: ReadonlyArray<T>,
): T[] => {
  const averageMap = buildAverageCoverageMap(entities);
  const seen = new Set<string>();
  const deduped: T[] = [];
  for (const entity of entities) {
    const entityId = entity?.to?.id;
    if (!entityId || seen.has(entityId)) continue;
    seen.add(entityId);
    deduped.push({
      ...entity,
      coverage_information: averageMap.get(entityId) ?? entity.coverage_information ?? [],
    });
  }
  return deduped;
};
