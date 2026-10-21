// Counters shared by the lock-free modules, reported by every run
export interface Counters {
  [key: string]: number;
}

export const newCounters = (): Counters => ({});

export const add = (counters: Counters, key: string, value = 1) => {
  counters[key] = (counters[key] ?? 0) + value;
};
