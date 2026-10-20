// Shared helpers for the ingestion benchmark scenarios (benchmarks/ingestion/README.md).
import { writeFileSync } from 'node:fs';
import { ADMIN_USER, testContext } from '../utils/testQuery';
import { createEntity } from '../../src/database/middleware';
import { elRawGet } from '../../src/database/engine';
import { benchTimingsReset, benchTimingsSnapshot, isBenchTimingEnabled } from '../../src/utils/bench-timing';

// Unique per run, so that every run creates new objects instead of upserting old ones
export const RUN_ID = `${Date.now()}`;

export const benchParam = (name: string, fallback: number): number => {
  const raw = process.env[`BENCH_${name}`];
  return raw ? Number(raw) : fallback;
};

export const now = () => performance.now();
export const round = (value: number) => Math.round(value * 100) / 100;
export const mean = (values: number[]) => round(values.reduce((a, b) => a + b, 0) / Math.max(1, values.length));
export const percentile = (values: number[], p: number) => {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  return round(sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))]);
};
export const summarize = (values: number[]) => ({
  n: values.length,
  mean: mean(values),
  p50: percentile(values, 50),
  p95: percentile(values, 95),
  p99: percentile(values, 99),
  max: round(values.length ? Math.max(...values) : 0),
});

// Run fn over items with at most `concurrency` calls in flight, in item order
export const pool = async <T>(items: T[], concurrency: number, fn: (item: T, index: number) => Promise<void>) => {
  let next = 0;
  const runners = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (next < items.length) {
      const index = next;
      next += 1;
      await fn(items[index], index);
    }
  });
  await Promise.all(runners);
};

// Mean (and p95) of every phase recorded by the platform timers since the last reset
export const resetPhases = () => benchTimingsReset();
export const phaseSummary = () => {
  const snapshot = benchTimingsSnapshot();
  return Object.fromEntries(Object.keys(snapshot).sort().map((key) => [key, { n: snapshot[key].length, mean: mean(snapshot[key]), p95: percentile(snapshot[key], 95) }]));
};

export interface MeasureResult {
  count: number;
  concurrency: number;
  wall_ms: number;
  throughput_per_s: number;
  latency_ms: ReturnType<typeof summarize>;
  errors: Record<string, number>;
  latency_mean_by_decile_ms: (number | null)[];
  phases_ms: ReturnType<typeof phaseSummary>;
}

// Call fn once per item, `concurrency` at a time, and report throughput, latency and platform phases
export const measure = async <T>(items: T[], concurrency: number, fn: (item: T, index: number) => Promise<void>): Promise<MeasureResult> => {
  resetPhases();
  const latencies: number[] = [];
  const byPosition: number[] = new Array(items.length);
  const errors: Record<string, number> = {};
  const start = now();
  await pool(items, concurrency, async (item, index) => {
    const t = now();
    try {
      await fn(item, index);
    } catch (err: any) {
      const key = err?.extensions?.code ?? err?.name ?? 'unknown';
      errors[key] = (errors[key] ?? 0) + 1;
    }
    const elapsed = now() - t;
    latencies.push(elapsed);
    byPosition[index] = elapsed;
  });
  const wall = now() - start;
  // Mean latency along the run, in ten slices: shows a cost that grows with the data already written
  const slice = Math.ceil(items.length / 10);
  const deciles = [...Array(10).keys()].map((d) => {
    const values = byPosition.slice(d * slice, (d + 1) * slice).filter((v) => v !== undefined);
    return values.length ? mean(values) : null;
  });
  return {
    count: items.length,
    concurrency,
    wall_ms: round(wall),
    throughput_per_s: round((items.length / wall) * 1000),
    latency_ms: summarize(latencies),
    errors,
    latency_mean_by_decile_ms: deciles,
    phases_ms: phaseSummary(),
  };
};

// Create `count` entities named after the run, 8 at a time (setup, not measured)
export const createEntities = async (type: string, prefix: string, count: number, extra: Record<string, any> = {}) => {
  const ids: string[] = new Array(count);
  await pool([...Array(count).keys()], 8, async (i) => {
    const entity = await createEntity(testContext, ADMIN_USER, { name: `bench-${RUN_ID}-${prefix}-${i}`, description: 'benchmark', ...extra }, type);
    ids[i] = entity.internal_id;
  });
  return ids;
};

export const createOne = async (type: string, name: string, extra: Record<string, any> = {}) => {
  return createEntity(testContext, ADMIN_USER, { name: `bench-${RUN_ID}-${name}`, description: 'benchmark', ...extra }, type);
};

// Number of ids denormalized on a document for a relationship type (rel_<type>.internal_id)
export const denormalizedCount = async (internalId: string, index: string, relationshipType: string) => {
  const doc: any = await elRawGet({ id: internalId, index });
  return (doc?._source?.[`rel_${relationshipType}.internal_id`] ?? []).length;
};

export const writeResults = (scenario: string, results: Record<string, any>) => {
  const output = process.env.BENCH_OUT ?? `bench-${scenario}-${RUN_ID}.json`;
  const payload = { scenario, timing_enabled: isBenchTimingEnabled(), results };
  writeFileSync(output, JSON.stringify(payload, null, 1));
};
