// Phase timers for the ingestion benchmarks (benchmarks/ingestion/README.md).
// Disabled unless OPENCTI_BENCH_TIMING=true: every call is then a no-op and nothing is stored.

const ENABLED = process.env.OPENCTI_BENCH_TIMING === 'true';
const store: Record<string, number[]> = {};

const record = (key: string, value: number) => {
  if (!store[key]) {
    store[key] = [];
  }
  store[key].push(value);
};

export interface BenchTimer {
  // Current time, to be given back to since()
  now: () => number;
  // Record the time elapsed since the previous step (or the timer creation) as <scope>.<phase>
  step: (phase: string) => void;
  // Record the time elapsed since a given instant as <scope>.<phase>
  since: (phase: string, start: number) => void;
  // Record the time elapsed since the timer creation as <scope>.total
  total: () => void;
}

const NOOP_TIMER: BenchTimer = { now: () => 0, step: () => {}, since: () => {}, total: () => {} };

export const benchTimer = (scope: string): BenchTimer => {
  if (!ENABLED) {
    return NOOP_TIMER;
  }
  const start = performance.now();
  let last = start;
  return {
    now: () => performance.now(),
    step: (phase) => {
      const current = performance.now();
      record(`${scope}.${phase}`, current - last);
      last = current;
    },
    since: (phase, from) => record(`${scope}.${phase}`, performance.now() - from),
    total: () => record(`${scope}.total`, performance.now() - start),
  };
};

export const isBenchTimingEnabled = () => ENABLED;

export const benchTimingsReset = () => {
  Object.keys(store).forEach((key) => delete store[key]);
};

export const benchTimingsSnapshot = (): Record<string, number[]> => store;
