import { describe, it, expect } from 'vitest';
import { buildAttackPatternCoverageMap, CoverageRelationEdge } from './securityCoverageAggregation';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const makeEdge = (
  apId: string,
  coverages: Array<{ name: string; score: number }>,
  apName = apId,
): CoverageRelationEdge => ({
  node: {
    coverage_information: coverages.map((c) => ({
      coverage_name: c.name,
      coverage_score: c.score,
    })),
    to: { id: apId, name: apName },
  },
});

const AP_1 = 'attack-pattern-T1059';
const AP_2 = 'attack-pattern-T1078';
const AP_3 = 'attack-pattern-T1566';

// ---------------------------------------------------------------------------
// buildAttackPatternCoverageMap
// ---------------------------------------------------------------------------

describe('buildAttackPatternCoverageMap', () => {
  it('returns an empty map when given no edges', () => {
    const result = buildAttackPatternCoverageMap([]);
    expect(result.size).toBe(0);
  });

  it('skips edges with a null/missing node', () => {
    const edges: CoverageRelationEdge[] = [{ node: null }];
    const result = buildAttackPatternCoverageMap(edges);
    expect(result.size).toBe(0);
  });

  it('skips edges with a null/missing to field', () => {
    const edges: CoverageRelationEdge[] = [
      { node: { coverage_information: [{ coverage_name: 'DETECTION', coverage_score: 80 }], to: null } },
    ];
    const result = buildAttackPatternCoverageMap(edges);
    expect(result.size).toBe(0);
  });

  it('handles a single edge with a single coverage correctly', () => {
    const edges = [makeEdge(AP_1, [{ name: 'DETECTION', score: 80 }], 'Command and Scripting Interpreter')];
    const result = buildAttackPatternCoverageMap(edges);

    expect(result.size).toBe(1);
    const entry = result.get(AP_1)!;
    expect(entry.id).toBe(AP_1);
    expect(entry.name).toBe('Command and Scripting Interpreter');
    expect(entry.averages).toEqual([{ coverage_name: 'DETECTION', coverage_score: 80 }]);
  });

  it('handles a single edge with multiple coverages correctly', () => {
    const edges = [
      makeEdge(AP_1, [
        { name: 'DETECTION', score: 80 },
        { name: 'PREVENTION', score: 70 },
      ]),
    ];
    const result = buildAttackPatternCoverageMap(edges);
    const { averages } = result.get(AP_1)!;

    expect(averages).toHaveLength(2);
    expect(averages.find((e) => e.coverage_name === 'DETECTION')?.coverage_score).toBe(80);
    expect(averages.find((e) => e.coverage_name === 'PREVENTION')?.coverage_score).toBe(70);
  });

  it('averages scores for the same AP appearing in two edges (same coverage_name)', () => {
    // SC Result A: DETECTION=80, SC Result B: DETECTION=60 → average=70
    const edges = [
      makeEdge(AP_1, [{ name: 'DETECTION', score: 80 }]),
      makeEdge(AP_1, [{ name: 'DETECTION', score: 60 }]),
    ];
    const result = buildAttackPatternCoverageMap(edges);

    expect(result.size).toBe(1);
    expect(result.get(AP_1)!.averages).toEqual([{ coverage_name: 'DETECTION', coverage_score: 70 }]);
  });

  it('rounds the average to the nearest integer', () => {
    // (80 + 61) / 2 = 70.5 → rounds to 71
    const edges = [
      makeEdge(AP_1, [{ name: 'DETECTION', score: 80 }]),
      makeEdge(AP_1, [{ name: 'DETECTION', score: 61 }]),
    ];
    const result = buildAttackPatternCoverageMap(edges);
    expect(result.get(AP_1)!.averages[0].coverage_score).toBe(71);
  });

  it('averages scores across three edges for the same AP', () => {
    // (80 + 90 + 70) / 3 = 80
    const edges = [
      makeEdge(AP_1, [{ name: 'DETECTION', score: 80 }]),
      makeEdge(AP_1, [{ name: 'DETECTION', score: 90 }]),
      makeEdge(AP_1, [{ name: 'DETECTION', score: 70 }]),
    ];
    const result = buildAttackPatternCoverageMap(edges);
    expect(result.get(AP_1)!.averages[0].coverage_score).toBe(80);
  });

  it('keeps different coverage_names separate for the same AP', () => {
    // Edge 1: DETECTION=80; Edge 2: PREVENTION=90 — no averaging needed, names differ
    const edges = [
      makeEdge(AP_1, [{ name: 'DETECTION', score: 80 }]),
      makeEdge(AP_1, [{ name: 'PREVENTION', score: 90 }]),
    ];
    const { averages } = buildAttackPatternCoverageMap(edges).get(AP_1)!;

    expect(averages.find((e) => e.coverage_name === 'DETECTION')?.coverage_score).toBe(80);
    expect(averages.find((e) => e.coverage_name === 'PREVENTION')?.coverage_score).toBe(90);
  });

  it('handles mixed case: same AP with 2 DETECTION scores and 1 PREVENTION score', () => {
    // DETECTION: (80 + 60) / 2 = 70  |  PREVENTION: 90 / 1 = 90
    const edges = [
      makeEdge(AP_1, [{ name: 'DETECTION', score: 80 }]),
      makeEdge(AP_1, [{ name: 'DETECTION', score: 60 }]),
      makeEdge(AP_1, [{ name: 'PREVENTION', score: 90 }]),
    ];
    const { averages } = buildAttackPatternCoverageMap(edges).get(AP_1)!;

    expect(averages.find((e) => e.coverage_name === 'DETECTION')?.coverage_score).toBe(70);
    expect(averages.find((e) => e.coverage_name === 'PREVENTION')?.coverage_score).toBe(90);
  });

  it('handles multiple distinct APs independently', () => {
    const edges = [
      makeEdge(AP_1, [{ name: 'DETECTION', score: 80 }]),
      makeEdge(AP_2, [{ name: 'DETECTION', score: 40 }]),
      makeEdge(AP_3, [{ name: 'PREVENTION', score: 100 }]),
    ];
    const result = buildAttackPatternCoverageMap(edges);

    expect(result.size).toBe(3);
    expect(result.get(AP_1)!.averages[0].coverage_score).toBe(80);
    expect(result.get(AP_2)!.averages[0].coverage_score).toBe(40);
    expect(result.get(AP_3)!.averages[0].coverage_score).toBe(100);
  });

  it('deduplicates: result has one entry per AP even with many edges for the same AP', () => {
    const edges = Array.from({ length: 10 }, (_, i) =>
      makeEdge(AP_1, [{ name: 'DETECTION', score: i * 10 }]),
    );
    const result = buildAttackPatternCoverageMap(edges);
    expect(result.size).toBe(1);
    // average of 0,10,20,30,40,50,60,70,80,90 = 450/10 = 45
    expect(result.get(AP_1)!.averages[0].coverage_score).toBe(45);
  });

  it('preserves the AP name from the first edge', () => {
    const edges = [
      makeEdge(AP_1, [{ name: 'DETECTION', score: 80 }], 'Command and Scripting Interpreter'),
      makeEdge(AP_1, [{ name: 'DETECTION', score: 60 }], 'Command and Scripting Interpreter'),
    ];
    expect(buildAttackPatternCoverageMap(edges).get(AP_1)!.name).toBe('Command and Scripting Interpreter');
  });

  it('falls back to id when AP name is missing', () => {
    const edges: CoverageRelationEdge[] = [
      { node: { coverage_information: [{ coverage_name: 'DETECTION', coverage_score: 80 }], to: { id: AP_1 } } },
    ];
    expect(buildAttackPatternCoverageMap(edges).get(AP_1)!.name).toBe(AP_1);
  });
});

// ---------------------------------------------------------------------------
// Performance: 1000 edges × 5 coverage categories × 200 APs
// ---------------------------------------------------------------------------

describe('performance', () => {
  it('processes 1000 edges across 200 APs with 5 coverage categories in under 50ms', () => {
    const categories = ['DETECTION', 'PREVENTION', 'VULNERABILITY', 'MANUAL', 'EXPOSURE'];
    const edges: CoverageRelationEdge[] = Array.from({ length: 1000 }, (_, i) => ({
      node: {
        to: { id: `attack-pattern-${i % 200}`, name: `Attack Pattern ${i % 200}` },
        coverage_information: categories.map((name) => ({
          coverage_name: name,
          coverage_score: Math.floor(Math.random() * 100),
        })),
      },
    }));

    const start = performance.now();
    const coverageMap = buildAttackPatternCoverageMap(edges);
    const elapsed = performance.now() - start;

    expect(coverageMap.size).toBe(200);
    expect(elapsed).toBeLessThan(50);
  });
});
