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
import conf, { booleanConf, INGESTION_HEALTH_FEATURE_FLAG, isFeatureEnabled, logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import type { AuthContext } from '../types/user';
import {
  type ConfigurationEventScope,
  EVENT_SCOPE_ADVISORY,
  EVENT_SCOPE_BLOCKING,
  EVENT_SCOPE_CRITICAL,
  EVENT_SCOPE_DEGRADED,
  EVENT_SCOPE_INVENTORY,
  EVENT_SCOPE_RECOVERED,
  EVENT_SCOPE_RESOLVED,
  EVENT_TYPE_CONFIGURATION,
  EVENT_TYPE_HEALTH,
  type HealthEventScope,
  type IngestionEventType,
  publishUserAction,
} from '../listener/UserActionListener';
import {
  redisGetIngestionHealthObservation,
  redisSetIngestionHealthLastRun,
  redisSetIngestionHealthObservation,
} from '../database/redis';
import {
  collectIngestionSources,
  type IngestionSourceSnapshot,
} from '../modules/ingestionHealth/ingestionHealth-domain';
import { patchAttribute } from '../database/middleware';
import {
  advanceProductivityCounters,
  computeIngestionHealth,
  isConfigurationWorse,
} from '../modules/ingestionHealth/ingestionHealth-checks';
import { INGESTION_HEALTH_THRESHOLDS } from '../modules/ingestionHealth/ingestionHealth-config';
import type {
  IngestionConfigurationStatus,
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
const INVENTORY_ENABLED = booleanConf('ingestion_health_manager:configuration_inventory_enabled', true);
const INVENTORY_INTERVAL_SECONDS = conf.get('ingestion_health_manager:configuration_inventory_interval_seconds') ?? 86400;

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

type Transition = { kind: 'alert' | 'recovery'; scope: HealthEventScope };

// Configuration is its own edge, with its own rules. It does not flap — a user
// either is a service account or is not — so it fires on first detection rather
// than waiting for agreement, and it is never re-notified, because these never
// self-recover and a reminder is just nagging.
type ConfigurationTransition = { scope: ConfigurationEventScope };

export const resolveConfigurationTransition = (
  status: IngestionConfigurationStatus,
  previous: IngestionHealthObservation | null,
  now: Date,
): { transition: ConfigurationTransition | null; since: string; alertAt?: string } => {
  const published = previous?.configuration_status ?? 'ok';
  const since = previous?.configuration_since ?? now.toISOString();
  if (status === published) {
    return { transition: null, since, alertAt: previous?.configuration_alert_at };
  }
  if (status === 'ok') {
    return { transition: { scope: EVENT_SCOPE_RESOLVED }, since: now.toISOString(), alertAt: previous?.configuration_alert_at };
  }
  // Only announce a worsening. advisory -> blocking is worth saying; blocking ->
  // advisory means somebody is already fixing it, so record it and stay quiet.
  if (!isConfigurationWorse(published, status)) {
    return { transition: null, since: now.toISOString(), alertAt: previous?.configuration_alert_at };
  }
  // `advisory` / `blocking` are both a configuration status and an event scope:
  // the same two words on purpose, so a subscriber filters on what they read.
  const scope = status === 'blocking' ? EVENT_SCOPE_BLOCKING : EVENT_SCOPE_ADVISORY;
  return { transition: { scope }, since: now.toISOString(), alertAt: now.toISOString() };
};

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
    ...advanceProductivityCounters(input, previous, now, INGESTION_HEALTH_THRESHOLDS),
    last_alert_at: previous?.last_alert_at,
    pending_status: candidate,
    pending_count: agreeing,
    // The configuration axis rides the same record — same key, same write — but
    // its own fields, so neither edge can clobber the other's state.
    configuration_status: previous?.configuration_status,
    configuration_since: previous?.configuration_since,
    configuration_alert_at: previous?.configuration_alert_at,
    last_inventory_at: previous?.last_inventory_at,
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
      transition: { kind: 'alert', scope: candidate as HealthEventScope },
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
      transition: { kind: 'recovery', scope: EVENT_SCOPE_RECOVERED },
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

// `event_type` is what splits "live alert on bad health" from "daily digest of
// misconfiguration" using the filter keys AlertLiveCreation already offers, so
// the two axes emit under different types rather than different scopes.
const emit = async (
  source: IngestionSourceSnapshot,
  health: IngestionHealth,
  transition: { kind: 'alert' | 'recovery' | 'inventory'; scope: HealthEventScope | ConfigurationEventScope },
  eventType: IngestionEventType = EVENT_TYPE_HEALTH,
) => {
  await publishUserAction({
    user: SYSTEM_USER,
    event_type: eventType,
    event_scope: transition.scope,
    event_access: 'administration',
    status: transition.kind === 'recovery' ? 'success' : 'error',
    // Transitions are indexed into the audit trail on purpose: edge-triggering
    // keeps the volume trivial, and it is the only place incident history lives.
    // The daily inventory is not: one event per misconfigured source per day
    // would drown that trail.
    prevent_indexing: transition.kind === 'inventory',
    message: health.summary,
    context_data: {
      // Also the key publisherManager buffers on — one field, two reasons.
      id: source.id,
      entity_type: source.entity_type,
      source_kind: source.source_kind,
      source_name: source.name,
      source_route: source.route,
      status: health.status,
      configuration_status: health.configuration_status,
      since: health.since?.toISOString(),
      // A configuration event carries only its own findings, so an email about
      // a personal account does not also recite why the feed is late.
      checks: health.checks
        .filter((check) => (eventType === EVENT_TYPE_CONFIGURATION ? check.kind === 'configuration' : check.kind === 'runtime'))
        .map((check) => ({
          code: check.code,
          kind: check.kind,
          severity: check.severity,
          message: check.message,
        })),
    },
  });
};

// Mirrors the computed status onto the source so the fleet can be filtered and
// sorted server-side. Written on change only — a 60s patch of every source would
// be a write storm for no gain — and never load-bearing: the resolver recomputes
// from live facts regardless, so a stale cached value can only affect a filter,
// never an answer.
const cacheStatus = async (
  context: AuthContext,
  source: IngestionSourceSnapshot,
  health: IngestionHealth,
  previous: IngestionHealthObservation | null,
) => {
  const statusChanged = previous?.status !== health.status;
  const configurationChanged = previous?.configuration_status !== health.configuration_status;
  if (!statusChanged && !configurationChanged) {
    return;
  }
  try {
    await patchAttribute(context, SYSTEM_USER, source.id, source.entity_type, {
      ingestion_health_status: health.status,
      ingestion_health_since: health.since?.toISOString(),
      ingestion_last_productive_at: health.last_productive_at?.toISOString(),
      ingestion_configuration_status: health.configuration_status,
    });
  } catch (e) {
    // A failed cache write must never stop the evaluation or the notification.
    logApp.warn('[OPENCTI-MODULE] Unable to cache ingestion health status', { cause: e, id: source.id });
  }
};

export const ingestionHealthHandler = async () => {
  const context = executionContext('ingestion_health_manager');
  const now = new Date();
  const sources = await collectIngestionSources(context, SYSTEM_USER);

  const withinStartupGrace = (now.getTime() - startedAt.getTime()) / 1000 < STARTUP_GRACE_SECONDS;
  const pending: Array<{ source: IngestionSourceSnapshot; health: IngestionHealth; transition: Transition }> = [];
  const configurationPending: Array<{
    source: IngestionSourceSnapshot;
    health: IngestionHealth;
    transition: ConfigurationTransition;
  }> = [];
  const inventory: Array<{ source: IngestionSourceSnapshot; health: IngestionHealth }> = [];

  for (let i = 0; i < sources.length; i += 1) {
    const source = sources[i];
    try {
      const previous = await redisGetIngestionHealthObservation(source.id);
      const input = { ...source.input, previous: previous ?? undefined };
      const health = computeIngestionHealth(input, now, INGESTION_HEALTH_THRESHOLDS);
      const { transition, observation } = resolveTransition(input, health, previous, now);

      // Two independent edges, one pass, one write.
      const configuration = resolveConfigurationTransition(health.configuration_status, previous, now);
      observation.configuration_status = health.configuration_status;
      observation.configuration_since = configuration.since;
      observation.configuration_alert_at = configuration.alertAt;

      // A digest replays events from the last period, so a source misconfigured
      // since March emits nothing today and never appears in one. Re-stating the
      // still-misconfigured sources once a day is what turns that changelog into
      // an inventory.
      const lastInventory = previous?.last_inventory_at ? new Date(previous.last_inventory_at) : null;
      const inventoryDue = INVENTORY_ENABLED
        && health.configuration_status !== 'ok'
        && (!lastInventory || (now.getTime() - lastInventory.getTime()) / 1000 >= INVENTORY_INTERVAL_SECONDS);
      if (inventoryDue) {
        observation.last_inventory_at = now.toISOString();
      }

      await redisSetIngestionHealthObservation(source.id, observation);
      await cacheStatus(context, source, health, previous);
      if (transition) {
        pending.push({ source, health, transition });
      }
      if (configuration.transition) {
        configurationPending.push({ source, health, transition: configuration.transition });
      }
      if (inventoryDue) {
        inventory.push({ source, health });
      }
    } catch (e) {
      logApp.error('[OPENCTI-MODULE] Ingestion health evaluation error', { cause: e, manager: 'INGESTION_HEALTH_MANAGER', id: source.id });
    }
  }

  await redisSetIngestionHealthLastRun(now);

  if (withinStartupGrace) {
    // Configuration respects the grace period too: nothing has re-reported yet,
    // so a restart would otherwise announce the whole fleet's configuration.
    logApp.debug('[OPENCTI-MODULE] Ingestion health transitions suppressed during startup grace', {
      runtime: pending.length,
      configuration: configurationPending.length,
    });
    return;
  }

  // Configuration findings never flap and never self-recover, so they are not
  // subject to the hysteresis above — but they are subject to the storm breaker,
  // because one bad change can misconfigure everything at once.
  if (configurationPending.length > STORM_THRESHOLD) {
    logApp.warn('[OPENCTI-MODULE] Ingestion configuration storm detected, individual notifications suppressed', {
      manager: 'INGESTION_HEALTH_MANAGER',
      affected: configurationPending.length,
    });
  } else {
    for (const entry of configurationPending) {
      await emit(entry.source, entry.health, { kind: 'alert', scope: entry.transition.scope }, EVENT_TYPE_CONFIGURATION);
    }
  }

  for (const entry of inventory) {
    await emit(entry.source, entry.health, { kind: 'inventory', scope: EVENT_SCOPE_INVENTORY }, EVENT_TYPE_CONFIGURATION);
  }

  // Storm breaker: RabbitMQ dropping takes every source down at once. That is
  // one platform incident, not N source incidents.
  const alerts = pending.filter((entry) => entry.transition.kind === 'alert');
  if (alerts.length > STORM_THRESHOLD) {
    logApp.warn('[OPENCTI-MODULE] Ingestion health storm detected, individual notifications suppressed', {
      manager: 'INGESTION_HEALTH_MANAGER',
      affected: alerts.length,
    });
    const worst = alerts.some((entry) => entry.transition.scope === EVENT_SCOPE_CRITICAL) ? EVENT_SCOPE_CRITICAL : EVENT_SCOPE_DEGRADED;
    await publishUserAction({
      user: SYSTEM_USER,
      event_type: EVENT_TYPE_HEALTH,
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

// Gated at registration rather than inside enabled(), matching
// workflowStatusCleanupManager: with the flag off the manager is absent from the
// registry entirely, so it does not show up in the UI's module list as a thing
// an administrator could turn on.
if (isFeatureEnabled(INGESTION_HEALTH_FEATURE_FLAG)) {
  registerManager(INGESTION_HEALTH_MANAGER_DEFINITION);
}
