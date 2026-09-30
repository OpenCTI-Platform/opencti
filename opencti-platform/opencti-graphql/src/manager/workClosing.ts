// What the connector manager does with an open work of a finished run (ADR 0007). A multipart
// work whose gate is still down is released: `to_processed` was never called (a connector with
// its own loop, a crash), and the work completes as soon as its objects are all reported. A
// released or single-part work that makes no progress for `staleMinutes` is forced complete,
// with the number of objects that never came.
export type AbandonedWorkAction = 'release' | 'force' | 'none';

export interface WorkRedisState {
  is_multipart?: string;
  is_processed?: string;
  import_last_processed?: string;
}

export const abandonedWorkAction = (workState: WorkRedisState | null | undefined, nowMs: number, staleMinutes: number): AbandonedWorkAction => {
  if (!workState) return 'none';
  if (workState.is_multipart === 'true' && workState.is_processed !== 'true') return 'release';
  const lastProgress = Date.parse(workState.import_last_processed ?? '');
  const idleMinutes = Number.isNaN(lastProgress) ? Infinity : (nowMs - lastProgress) / 60000;
  return idleMinutes >= staleMinutes ? 'force' : 'none';
};
