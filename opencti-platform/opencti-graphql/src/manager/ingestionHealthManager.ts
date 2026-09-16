// Ingestion health manager.
//
// Evaluates every ingestion source on a fixed cadence and emits an activity
// event when a source *transitions* into or out of trouble. It deliberately
// does not share a lock or a cadence with the managers it watches: a watchdog
// starved by the thing it is watching is worse than no watchdog.
//
// Emission is edge-triggered with hysteresis, a startup grace period and a
// storm breaker — at a 60s interval, level-triggered emission would send 4,320
// notifications for one source critical over three days.

import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { publishUserAction } from '../listener/UserActionListener';
import {
  redisGetIngestionHealthObservation,
  redisSetIngestionHealthLastRun,
  redisSetIngestionHealthObservation,
} from '../database/redis';
import {
  collectIngestionSources,
  type IngestionSourceSnapshot,
} from '../modules/ingestionHealth/ingestionHealth-domain';
import { advanceProductivityCounters, computeIngestionHealth } from '../modules/ingestionHealth/ingestionHealth-checks';
import type {
  IngestionHealth,
  IngestionHealthInput,
  IngestionHealthObservation,
  IngestionHealthStatus,
} from '../modules/ingestionHealth/ingestionHealth-types';

const INGESTION_HEALTH_MANAGER_ENABLED = booleanConf('ingestion_health_manager:enabled', true);
const INGESTION_HEALTH_MANAGER_KEY = conf.get('ingestion_health_manager:lock_key') || 'ingestion_health_manager_lock';
const SCHEDULE_TIME = conf.get('ingestion_health_manager:interval') || 60000;
const MISSED_PERIODS_BEFORE_ALERT = conf.get('ingestion_health_manager:missed_periods_before_alert') ?? 2;
const GOOD_PERIODS_BEFORE_RECOVERY = conf.get('ingestion_health_manager:good_periods_before_recovery') ?? 3;
const MIN_ALERT_DWELL_SECONDS = conf.get('ingestion_health_manager:min_alert_dwell_seconds') ?? 900;
const STARTUP_GRACE_SECONDS = conf.get('ingestion_health_manager:startup_grace_seconds') ?? 300;
const STORM_THRESHOLD = conf.get('ingestion_health_manager:storm_threshold') ?? 10;

// When the manager process started. Emission is suppressed until the grace
// period has passed: on a platform restart nothing has re-pinged yet, so
// without this every restart pages everyone about every source.
const startedAt = new Date();

const SEVERITY_ORDER: Record<IngestionHealthStatus, number> = {
  healthy: 0,
  idle: 0,
  unknown: 0,
  stopped: 1,
  degraded: 2,
  critical: 3,
};

const isBad = (status: IngestionHealthStatus) => status === 'degraded' || status === 'critical';
const worsens = (from: IngestionHealthStatus, to: IngestionHealthStatus) => SEVERITY_ORDER[to] > SEVERITY_ORDER[from];

type Transition = { kind: 'alert' | 'recovery'; scope: 'degraded' | 'critical' | 'recovered' };

// Decides whether this evaluation is a publishable transition, and returns the
// observation to persist. Pure apart from its inputs so the hysteresis is
// testable without Redis.
export const resolveTransition = (
  input: IngestionHealthInput,
  health: IngestionHealth,
  previous: IngestionHealthObservation | null,
  now: Date,
): { transition: Transition | null; observation: IngestionHealthObservation } => {
  const publishedStatus = previous?.status ?? 'unknown';
  const candidate = health.status;

  // Count how many consecutive evaluations have agreed on a status that has
  // not been published yet. This is the flap guard: a source oscillating on a
  // threshold must not emit an alert/recovery pair every cycle.
  const agreeing = previous?.pending_status === candidate ? (previous.pending_count ?? 0) + 1 : 1;

  const observation: IngestionHealthObservation = {
    status: publishedStatus,
    since: previous?.since ?? now.toISOString(),
    last_productive_at: health.last_productive_at?.toISOString() ?? previous?.last_productive_at,
    ...advanceProductivityCounters(input, previous),
    last_alert_at: previous?.last_alert_at,
    pending_status: candidate,
    pending_count: agreeing,
  };

  if (candidate === publishedStatus) {
    return { transition: null, observation };
  }

  // `stopped` is a deliberate user action, never an incident.
  if (candidate === 'stopped' || publishedStatus === 'stopped') {
    return { transition: null, observation: { ...observation, status: candidate, since: now.toISOString() } };
  }

  const becomingBad = isBad(candidate) && worsens(publishedStatus, candidate);
  const becomingGood = !isBad(candidate) && isBad(publishedStatus);

  if (becomingBad && agreeing >= MISSED_PERIODS_BEFORE_ALERT) {
    return {
      transition: { kind: 'alert', scope: candidate as 'degraded' | 'critical' },
      observation: { ...observation, status: candidate, since: now.toISOString(), last_alert_at: now.toISOString() },
    };
  }

  if (becomingGood && agreeing >= GOOD_PERIODS_BEFORE_RECOVERY) {
    // Do not announce a recovery before the incident has had time to be real;
    // this collapses brief self-healing blips into silence.
    const alertedAt = previous?.last_alert_at ? new Date(previous.last_alert_at) : null;
    const dwell = alertedAt ? (now.getTime() - alertedAt.getTime()) / 1000 : Number.MAX_SAFE_INTEGER;
    if (dwell < MIN_ALERT_DWELL_SECONDS) {
      return { transition: null, observation };
    }
    return {
      transition: { kind: 'recovery', scope: 'recovered' },
      observation: { ...observation, status: candidate, since: now.toISOString() },
    };
  }

  // An improvement that is still bad (critical → degraded) updates the state
  // without notifying: the incident is already open.
  if (!becomingBad && !becomingGood) {
    return { transition: null, observation: { ...observation, status: candidate, since: now.toISOString() } };
  }

  return { transition: null, observation };
};

const emit = async (source: IngestionSourceSnapshot, health: IngestionHealth, transition: Transition) => {
  await publishUserAction({
    user: SYSTEM_USER,
    event_type: 'health',
    event_scope: transition.scope,
    event_access: 'administration',
    status: transition.kind === 'recovery' ? 'success' : 'error',
    // Transitions are indexed into the audit trail on purpose: edge-triggering
    // keeps the volume trivial, and it is the only place incident history lives.
    prevent_indexing: false,
    message: health.summary,
    context_data: {
      // Also the key publisherManager buffers on — one field, two reasons.
      id: source.id,
      entity_type: source.entity_type,
      source_kind: source.source_kind,
      source_name: source.name,
      source_route: source.route,
      status: health.status,
      since: health.since?.toISOString(),
      checks: health.checks.map((check) => ({
        code: check.code,
        severity: check.severity,
        message: check.message,
      })),
    },
  });
};

export const ingestionHealthHandler = async () => {
  const context = executionContext('ingestion_health_manager');
  const now = new Date();
  const sources = await collectIngestionSources(context, SYSTEM_USER);

  const withinStartupGrace = (now.getTime() - startedAt.getTime()) / 1000 < STARTUP_GRACE_SECONDS;
  const pending: Array<{ source: IngestionSourceSnapshot; health: IngestionHealth; transition: Transition }> = [];

  for (let i = 0; i < sources.length; i += 1) {
    const source = sources[i];
    try {
      const previous = await redisGetIngestionHealthObservation(source.id);
      const input = { ...source.input, previous: previous ?? undefined };
      const health = computeIngestionHealth(input, now);
      const { transition, observation } = resolveTransition(input, health, previous, now);
      await redisSetIngestionHealthObservation(source.id, observation);
      if (transition) {
        pending.push({ source, health, transition });
      }
    } catch (e) {
      logApp.error('[OPENCTI-MODULE] Ingestion health evaluation error', { cause: e, manager: 'INGESTION_HEALTH_MANAGER', id: source.id });
    }
  }

  await redisSetIngestionHealthLastRun(now);

  if (withinStartupGrace) {
    logApp.debug('[OPENCTI-MODULE] Ingestion health transitions suppressed during startup grace', { count: pending.length });
    return;
  }

  // Storm breaker: RabbitMQ dropping takes every source down at once. That is
  // one platform incident, not N source incidents.
  const alerts = pending.filter((entry) => entry.transition.kind === 'alert');
  if (alerts.length > STORM_THRESHOLD) {
    logApp.warn('[OPENCTI-MODULE] Ingestion health storm detected, individual notifications suppressed', {
      manager: 'INGESTION_HEALTH_MANAGER',
      affected: alerts.length,
    });
    const worst = alerts.some((entry) => entry.transition.scope === 'critical') ? 'critical' : 'degraded';
    await publishUserAction({
      user: SYSTEM_USER,
      event_type: 'health',
      event_scope: worst,
      event_access: 'administration',
      status: 'error',
      prevent_indexing: false,
      message: `Ingestion degraded — ${alerts.length} sources affected`,
      context_data: {
        id: 'ingestion-platform',
        entity_type: 'Platform',
        source_kind: 'connector',
        source_name: 'Ingestion',
        source_route: 'deployed',
        status: worst,
        checks: alerts.slice(0, 20).map((entry) => ({
          code: 'STORM',
          severity: 'blocking',
          message: `${entry.source.name}: ${entry.health.summary}`,
        })),
      },
    });
    // Recoveries still go out individually — they are never a storm.
    for (const entry of pending.filter((e) => e.transition.kind === 'recovery')) {
      await emit(entry.source, entry.health, entry.transition);
    }
    return;
  }

  for (const entry of pending) {
    await emit(entry.source, entry.health, entry.transition);
  }
};

const INGESTION_HEALTH_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'INGESTION_HEALTH_MANAGER',
  label: 'Ingestion health manager',
  executionContext: 'ingestion_health_manager',
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
  // NB: no `enterpriseEditionOnly` — the status is CE; only the activity
  // triggers that turn these events into notifications are EE.
};

registerManager(INGESTION_HEALTH_MANAGER_DEFINITION);
