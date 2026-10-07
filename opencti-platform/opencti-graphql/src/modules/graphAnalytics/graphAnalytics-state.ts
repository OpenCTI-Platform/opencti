import conf from '../../config/conf';

// Fields of the graph analytics state hash stored in Redis
export const GRAPH_STATE_LAST_INCREMENTAL_RUN = 'last_incremental_run';
export const GRAPH_STATE_FULL_PASS_STARTED_AT = 'full_pass_started_at';
// end of the last pass that reached the last entity
export const GRAPH_STATE_FULL_PASS_COMPLETED_AT = 'full_pass_completed_at';
// end of the last pass, completed or stopped at its entity cap: the next pass is scheduled from it
export const GRAPH_STATE_FULL_PASS_ENDED_AT = 'full_pass_ended_at';
export const GRAPH_STATE_FULL_PASS_CURSOR = 'full_pass_cursor';
export const GRAPH_STATE_FULL_PASS_PROCESSED = 'full_pass_processed';
export const GRAPH_STATE_CLUSTERING_LAST_RUN = 'clustering_last_run';
export const GRAPH_STATE_ANALYTICS_LAST_RUN_AT = 'analytics_last_run_at';
export const GRAPH_STATE_ANALYTICS_LAST_RUN_ID = 'analytics_last_run_id';
export const GRAPH_STATE_ANALYTICS_VERSION = 'analytics_version';

export const GRAPH_ANALYTICS_MANAGER_NAME = 'graph_analytics_manager';

const ANALYTICS_PROCESS_GRACE_HOURS: number = conf.get('graph_analytics_manager:analytics_process_grace_hours') ?? 48;

/**
 * The opencti-analytics process is considered active when it wrote results within the grace period.
 * While it is active, the platform leaves cluster computation to it.
 */
export const isAnalyticsProcessActive = (state: Record<string, string>, now = Date.now()): boolean => {
  const lastRun = state[GRAPH_STATE_ANALYTICS_LAST_RUN_AT];
  if (!lastRun) return false;
  const lastRunTime = new Date(lastRun).getTime();
  if (Number.isNaN(lastRunTime)) return false;
  return now - lastRunTime <= ANALYTICS_PROCESS_GRACE_HOURS * 3600 * 1000;
};

export const parseStateDate = (value: string | undefined): Date | null => {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
};
