interface CoverageResult {
  readonly coverage_name: string;
  readonly coverage_score: number;
}
export interface CoverageRelationEdge {
  readonly node: {
    readonly coverage_information?: ReadonlyArray<CoverageResult> | null;
    readonly to?: { readonly id?: string | null; readonly name?: string | null } | null;
  } | null;
}

export type CoverageMap = Map<string, CoverageResult[]>;

/**
 * Builds a map from attackPatternId to averaged coverage entries.
 *
 * A Security Coverage can have multiple SC Results, each producing a distinct
 * `has-covered` relation toward the same entity with different scores.
 * This function deduplicates by id and averages scores per coverage_name.
 *
 * @param edges - Flat list of stixCoreRelationship edges from a SecurityCoverage
 * @returns Map of averages: Map<entityId, CoverageResult[]>
 */
export function buildAverageCoverageMap(
  edges: ReadonlyArray<CoverageRelationEdge>,
): CoverageMap {
  // Pass 1: accumulate raw scores per (apId, coverage_name) and capture AP name
  const accumulator = new Map<string, { name: string; byName: Map<string, number[]> }>();

  for (const edge of edges) {
    const entityId = edge?.node?.to?.id;
    if (!entityId) continue;
    if (!accumulator.has(entityId)) {
      accumulator.set(
        entityId,
        {
          name: edge.node?.to?.name ?? entityId,
          byName: new Map(),
        },
      );
    }
    const { byName } = accumulator.get(entityId)!;
    for (const info of edge.node?.coverage_information ?? []) {
      const existing = byName.get(info.coverage_name) ?? [];
      existing.push(info.coverage_score);
      byName.set(info.coverage_name, existing);
    }
  }

  // Pass 2: compute per-entity averages
  const result = new Map<string, CoverageResult[]>();
  accumulator.forEach(({ byName }, entityId) => {
    const coverage_information: CoverageResult[] = [];
    byName.forEach((scores, coverage_name) => {
      const avg = Math.round(scores.reduce((sum, s) => sum + s, 0) / scores.length);
      coverage_information.push({ coverage_name, coverage_score: avg });
    });
    result.set(entityId, coverage_information);
  });

  return result;
}
