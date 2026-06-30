export interface CoverageEntry {
  readonly coverage_name: string;
  readonly coverage_score: number;
}

export interface CoverageRelationEdge {
  readonly node: {
    readonly coverage_information?: ReadonlyArray<CoverageEntry> | null;
    readonly to?: { readonly id?: string | null; readonly name?: string | null } | null;
  } | null;
}

export interface AttackPatternCoverage {
  readonly id: string;
  readonly name: string;
  readonly averages: CoverageEntry[];
}

/**
 * Builds a map from attackPatternId to averaged coverage entries.
 *
 * A Security Coverage can have multiple SC Results, each producing a distinct
 * `has-covered` relation toward the same Attack Pattern with different scores.
 * This function deduplicates by AP id and averages scores per coverage_name.
 *
 * @param edges - Flat list of stixCoreRelationship edges from a SecurityCoverage
 * @returns Map<attackPatternId, AttackPatternCoverage>
 */
export function buildAttackPatternCoverageMap(
  edges: ReadonlyArray<CoverageRelationEdge>,
): Map<string, AttackPatternCoverage> {
  // Pass 1: accumulate raw scores per (apId, coverage_name) and capture AP name
  const accumulator = new Map<string, { name: string; byName: Map<string, number[]> }>();

  for (const edge of edges) {
    const apId = edge?.node?.to?.id;
    if (!apId) continue;

    if (!accumulator.has(apId)) {
      accumulator.set(apId, { name: edge.node?.to?.name ?? apId, byName: new Map() });
    }
    const { byName } = accumulator.get(apId)!;

    for (const info of edge.node?.coverage_information ?? []) {
      const existing = byName.get(info.coverage_name) ?? [];
      existing.push(info.coverage_score);
      byName.set(info.coverage_name, existing);
    }
  }

  // Pass 2: compute per-AP averages
  const result = new Map<string, AttackPatternCoverage>();

  accumulator.forEach(({ name, byName }, apId) => {
    const averages: CoverageEntry[] = [];
    byName.forEach((scores, coverage_name) => {
      const avg = Math.round(scores.reduce((sum, s) => sum + s, 0) / scores.length);
      averages.push({ coverage_name, coverage_score: avg });
    });
    result.set(apId, { id: apId, name, averages });
  });

  return result;
}
