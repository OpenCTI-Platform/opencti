import conf, { booleanConf } from '../../config/conf';

export const CURATION_MANAGER_ENABLED = booleanConf('curation_manager:enabled', true);
export const CURATION_SCAN_INTERVAL_MS = Number(conf.get('curation_manager:scan_interval') ?? 24 * 3600 * 1000);
export const CURATION_SNAPSHOT_INTERVAL_MS = Number(conf.get('curation_manager:snapshot_interval') ?? 24 * 3600 * 1000);

export const isOlderThan = (date: string | null | undefined, intervalMs: number, now = Date.now()) => {
  return !date || now - new Date(date).getTime() >= intervalMs;
};

/** When a run that happens once the last one is older than the interval is due: now when it is already due. */
export const nextRunDate = (lastRun: string | null | undefined, intervalMs: number, now = Date.now()) => {
  const due = lastRun ? new Date(lastRun).getTime() + intervalMs : now;
  return new Date(Math.max(due, now)).toISOString();
};
