export interface HuntEvidenceItem {
  readonly field: string;
  readonly value_hash: string;
  readonly value_preview?: string | null;
  readonly count: number;
}

export interface HuntEvidenceRun {
  readonly id: string;
  readonly completed_at?: string | null;
  readonly created_at?: string | null;
  readonly platform?: string | null;
  readonly evidence_sample?: ReadonlyArray<HuntEvidenceItem> | null;
}

export interface HuntEvidenceRow {
  /** Stable key of a value: the same hashed value seen by several runs is one row */
  id: string;
  field: string;
  value_hash: string;
  value_preview: string | null;
  count: number;
  runs_count: number;
  run_ids: string[];
  platforms: string[];
  first_seen_at: string | null;
  last_seen_at: string | null;
}

export interface HuntEvidenceFilters {
  runIds?: string[];
  field?: string | null;
  search?: string | null;
}

const runDate = (run: HuntEvidenceRun) => run.completed_at ?? run.created_at ?? null;

const minDate = (a: string | null, b: string | null) => {
  if (!a) return b;
  if (!b) return a;
  return new Date(a).getTime() <= new Date(b).getTime() ? a : b;
};

const maxDate = (a: string | null, b: string | null) => {
  if (!a) return b;
  if (!b) return a;
  return new Date(a).getTime() >= new Date(b).getTime() ? a : b;
};

/**
 * Aggregates the (hashed, truncated) evidence samples of hunt runs: one row per field and value hash,
 * counts summed over the runs, sorted by decreasing count. Values never leave their hash and preview.
 */
export const aggregateHuntEvidence = (runs: ReadonlyArray<HuntEvidenceRun>, filters: HuntEvidenceFilters = {}): HuntEvidenceRow[] => {
  const runIds = filters.runIds && filters.runIds.length > 0 ? new Set(filters.runIds) : null;
  const search = (filters.search ?? '').trim().toLowerCase();
  const rows = new Map<string, HuntEvidenceRow>();
  runs
    .filter((run) => !runIds || runIds.has(run.id))
    .forEach((run) => {
      const date = runDate(run);
      (run.evidence_sample ?? []).forEach((item) => {
        if (filters.field && item.field !== filters.field) {
          return;
        }
        const id = `${item.field}::${item.value_hash}`;
        const existing = rows.get(id);
        if (existing) {
          existing.count += item.count;
          if (!existing.run_ids.includes(run.id)) {
            existing.run_ids.push(run.id);
            existing.runs_count += 1;
          }
          if (run.platform && !existing.platforms.includes(run.platform)) {
            existing.platforms.push(run.platform);
          }
          existing.value_preview = existing.value_preview ?? item.value_preview ?? null;
          existing.first_seen_at = minDate(existing.first_seen_at, date);
          existing.last_seen_at = maxDate(existing.last_seen_at, date);
        } else {
          rows.set(id, {
            id,
            field: item.field,
            value_hash: item.value_hash,
            value_preview: item.value_preview ?? null,
            count: item.count,
            runs_count: 1,
            run_ids: [run.id],
            platforms: run.platform ? [run.platform] : [],
            first_seen_at: date,
            last_seen_at: date,
          });
        }
      });
    });
  return Array.from(rows.values())
    .filter((row) => search.length === 0
      || row.field.toLowerCase().includes(search)
      || (row.value_preview ?? '').toLowerCase().includes(search)
      || row.value_hash.toLowerCase().startsWith(search))
    .sort((a, b) => b.count - a.count || a.field.localeCompare(b.field) || a.value_hash.localeCompare(b.value_hash));
};

export interface HuntEvidenceWindow {
  /** Completed runs of the hunt, the loaded ones included */
  completedRunsCount: number;
  /** True when older completed runs exist beyond the loaded ones */
  isWindowed: boolean;
  /** Date of the oldest loaded run, the start of the window */
  since: string | null;
}

/** Window of the loaded runs (most recent first) within every completed run of the hunt. */
export const huntEvidenceWindow = (runs: ReadonlyArray<HuntEvidenceRun>, globalCount?: number | null): HuntEvidenceWindow => {
  const completedRunsCount = Math.max(globalCount ?? 0, runs.length);
  const oldest = runs.length > 0 ? runs[runs.length - 1] : null;
  return {
    completedRunsCount,
    isWindowed: completedRunsCount > runs.length,
    since: oldest ? runDate(oldest) : null,
  };
};

/** Distinct evidence fields of the runs, sorted alphabetically. */
export const huntEvidenceFields = (runs: ReadonlyArray<HuntEvidenceRun>): string[] => {
  const fields = new Set<string>();
  runs.forEach((run) => (run.evidence_sample ?? []).forEach((item) => fields.add(item.field)));
  return Array.from(fields).sort((a, b) => a.localeCompare(b));
};

/** Short form of a sha256 for display, the full hash stays available for copy. */
export const shortHash = (hash: string, length = 12) => (hash.length > length ? `${hash.substring(0, length)}...` : hash);
