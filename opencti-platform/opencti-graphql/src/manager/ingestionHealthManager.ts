import conf, { booleanConf, INGESTION_HEALTH_FEATURE_FLAG, isFeatureEnabled, logApp } from '../config/conf';
import { elReplace } from '../database/engine';
import { closePingsBoundSeconds, computeIngestionHealth } from '../modules/ingestionHealth/ingestionHealth-checks';
import { collectIngestionSources, type IngestionSourceSnapshot } from '../modules/ingestionHealth/ingestionHealth-domain';
import { redisGetIngestionHealthLastRun, redisSetIngestionHealthLastRun, redisSetIngestionHealthObservation } from '../modules/ingestionHealth/ingestionHealth-redis';
import type { AuthContext } from '../types/user';
import { executionContext } from '../utils/access';
import { type ManagerDefinition, registerManager } from './managerModule';

const INGESTION_HEALTH_MANAGER_ID = 'INGESTION_HEALTH_MANAGER';
const INGESTION_HEALTH_MANAGER_CONTEXT = 'ingestion_health_manager';

const INGESTION_HEALTH_MANAGER_ENABLED = booleanConf('ingestion_health_manager:enabled', true);
const INGESTION_HEALTH_MANAGER_KEY = conf.get('ingestion_health_manager:lock_key') || 'ingestion_health_manager_lock';
const SCHEDULE_TIME = conf.get('ingestion_health_manager:interval') || 60000; // 1 minute
// Two pings seen by the manager count as close within 2 periods (never below 120 seconds):
// a longer period must not leave a connector pinging every 40 seconds unable to qualify
const CLOSE_PINGS_BOUND_SECONDS = closePingsBoundSeconds(SCHEDULE_TIME / 1000);

// Evaluate one source: remember its heartbeat, then, on a change only, refresh its cached health (RFC 0001 §4.4).
// This is the only place the health is evaluated: the UI reads this cache.
// The cache is written directly in the index on purpose (elReplace, not an entity update):
// an update would emit a stream event for every health change, and move updated_at of the connector.
export const evaluateIngestionSource = async (context: AuthContext, source: IngestionSourceSnapshot, now: Date): Promise<boolean> => {
  const { connector, input, previous_heartbeat: previousHeartbeat, heartbeat } = source;
  if (JSON.stringify(previousHeartbeat) !== JSON.stringify(heartbeat)) {
    await redisSetIngestionHealthObservation(connector.internal_id, heartbeat);
  }
  const health = computeIngestionHealth(input, now);
  const checks = JSON.stringify(health.checks);
  const isStatusChanged = connector.ingestion_health_status !== health.status;
  if (!isStatusChanged && connector.ingestion_health_summary === health.summary && connector.ingestion_health_checks === checks) {
    return false;
  }
  const doc = {
    ingestion_health_status: health.status,
    // since tells when the status began, not when its explanation last changed
    ingestion_health_since: isStatusChanged ? now.toISOString() : (connector.ingestion_health_since ?? now.toISOString()),
    ingestion_health_summary: health.summary,
    ingestion_health_checks: checks,
  };
  await elReplace(context, connector._index, connector.internal_id, { doc });
  if (isStatusChanged) {
    logApp.info(`[OPENCTI-MODULE] Ingestion health of ${connector.name} is now ${health.status}`, {
      manager: INGESTION_HEALTH_MANAGER_ID,
      id: connector.internal_id,
      previous_status: connector.ingestion_health_status,
      summary: health.summary,
    });
  }
  return true;
};

export const ingestionHealthHandler = async () => {
  const context = executionContext(INGESTION_HEALTH_MANAGER_CONTEXT);
  const now = new Date();
  // Blind for a while (platform restart, lost lock...), or never run: a wide gap between two pings
  // is then the manager not looking, not the connector being irregular
  const lastRun = await redisGetIngestionHealthLastRun();
  const managerWasBlind = !lastRun || (now.getTime() - lastRun.getTime()) / 1000 > CLOSE_PINGS_BOUND_SECONDS;
  const sources = await collectIngestionSources(context, { boundSeconds: CLOSE_PINGS_BOUND_SECONDS, managerWasBlind });
  for (let i = 0; i < sources.length; i += 1) {
    try {
      await evaluateIngestionSource(context, sources[i], now);
    } catch (e) {
      logApp.warn('[OPENCTI-MODULE] Ingestion health evaluation error', { cause: e, manager: INGESTION_HEALTH_MANAGER_ID, id: sources[i].connector.internal_id });
    }
  }
  // Only a cycle that listed the connectors counts as a look. Its start time is recorded,
  // so the next cycle compares start with start
  await redisSetIngestionHealthLastRun(now);
};

const INGESTION_HEALTH_MANAGER_DEFINITION: ManagerDefinition = {
  id: INGESTION_HEALTH_MANAGER_ID,
  label: 'Ingestion health manager',
  executionContext: INGESTION_HEALTH_MANAGER_CONTEXT,
  cronSchedulerHandler: {
    handler: ingestionHealthHandler,
    interval: SCHEDULE_TIME,
    lockKey: INGESTION_HEALTH_MANAGER_KEY,
  },
  enabledByConfig: INGESTION_HEALTH_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

// Own lock and own manager on purpose: a watchdog must not share a lock with what it watches (RFC 0001 §11.1)
if (isFeatureEnabled(INGESTION_HEALTH_FEATURE_FLAG)) {
  registerManager(INGESTION_HEALTH_MANAGER_DEFINITION);
}
