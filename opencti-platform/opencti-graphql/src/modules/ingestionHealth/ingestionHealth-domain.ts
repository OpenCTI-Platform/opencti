// Ingestion health — the I/O layer.
//
// Gathers the facts a source can offer, maps them onto the normalized
// `IngestionHealthInput`, and hands them to the pure evaluator. The mapping is
// exported separately from the fetching so it can be unit-tested without a
// platform.
//
// MVP scope: connectors. Feeds and synchronizers follow the same shape — a
// `buildFeedHealthInput` / `buildSyncHealthInput` alongside the connector one.

import { worksForConnector } from '../../domain/work';
import { queueDetails } from '../../domain/connector';
import {
  type IngestionLogEntry,
  redisGetConnectorHealthMetrics,
  redisGetIngestionHealthObservation,
  redisGetIngestionLogHistory,
} from '../../database/redis';
import { getEntitiesMapFromCache } from '../../database/cache';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { computeIngestionHealth } from './ingestionHealth-checks';
import { INGESTION_HEALTH_THRESHOLDS } from './ingestionHealth-config';
import type {
  IngestionHealth,
  IngestionHealthInput,
  IngestionHealthObservation,
} from './ingestionHealth-types';
import { fullEntitiesList } from '../../database/middleware-loader';
import { connectors } from '../../database/repository';
import {
  ENTITY_TYPE_INGESTION_CSV,
  ENTITY_TYPE_INGESTION_JSON,
  ENTITY_TYPE_INGESTION_RSS,
  ENTITY_TYPE_INGESTION_TAXII,
  ENTITY_TYPE_INGESTION_TAXII_COLLECTION,
} from '../ingestion/ingestion-types';
import { ENTITY_TYPE_SYNC } from '../../schema/internalObject';
import type { AuthContext, AuthUser } from '../../types/user';
import { SYSTEM_USER } from '../../utils/access';
import { logApp } from '../../config/conf';

// How many recent works are enough to answer "has it produced anything, and
// have the last few runs been empty". Kept small: the answer is always in the
// most recent handful, and `connectorManager` deletes works after 7 days.
const WORKS_LOOKBACK = 10;

interface WorkLike {
  status?: string;
  completed_time?: string | Date | null;
  completed_number?: number | null;
  errors?: Array<{ message?: string }> | null;
  timestamp?: string | Date | null;
}

// Every optional field here also accepts `null`: the resolver passes the raw
// GraphQL-codegen `Connector` object straight through, and generated types
// model every nullable schema field as `T | null`, never `T | undefined`.
interface ConnectorLike {
  id: string;
  internal_id?: string | null;
  name?: string | null;
  active?: boolean | null;
  connector_type?: string | null;
  auto?: boolean | null;
  updated_at?: string | Date | null;
  created_at?: string | Date | null;
  connector_state_timestamp?: string | Date | null;
  manager_requested_status?: string | null;
  is_managed?: boolean | null;
  built_in?: boolean | null;
  connector_user_id?: string | null;
  connector_scope?: string[] | null;
  connector_contract_configuration?: Array<{ key?: string; value?: string | null }> | null;
  connector_info?: {
    run_and_terminate?: boolean | null;
    buffering?: boolean | null;
    queue_threshold?: number | null;
    queue_messages_size?: number | null;
    next_run_datetime?: string | Date | null;
    last_run_datetime?: string | Date | null;
  } | null;
}

const asDate = (value: string | Date | null | undefined): Date | undefined => {
  if (!value) {
    return undefined;
  }
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date;
};

const isComplete = (work: WorkLike) => work.status === 'complete';

// A work counts as productive when it actually imported something. Work status
// alone is not proof of success: `connectorManager.closeOldWorks()` force-sets
// stale works to `complete`, so a completed work can represent a run that never
// finished.
const isProductive = (work: WorkLike) => (work.completed_number ?? 0) > 0;

export const summarizeWorks = (works: WorkLike[]) => {
  const completed = works.filter(isComplete);
  const lastProductive = completed.find(isProductive);
  const lastCompleted = completed[0];

  // Consecutive empty runs, counted from the most recent backwards. Stops at
  // the first productive run rather than counting empties across the window.
  let consecutiveEmptyRuns = 0;
  for (let i = 0; i < completed.length; i += 1) {
    if (isProductive(completed[i])) {
      break;
    }
    consecutiveEmptyRuns += 1;
  }

  const lastError = lastCompleted?.errors?.find((e) => e?.message)?.message;
  return {
    last_productive_at: asDate(lastProductive?.completed_time),
    last_completed_at: asDate(lastCompleted?.completed_time),
    consecutive_empty_runs: consecutiveEmptyRuns,
    last_run_failed: Boolean(lastCompleted?.errors?.length),
    last_run_error: lastError,
  };
};

// region configuration inputs
//
// Every source kind has a user_id, so the configuration axis applies to all
// seven — a TAXII feed ingesting as a personal account is the same problem as a
// connector doing it.

export interface IngestionUserFacts {
  name?: string;
  service_account?: boolean;
  account_status?: string;
  api_token_expiration?: string;
  effective_confidence_level?: number | null;
}

export type IngestionUserLookup = (userId: string | undefined) => IngestionUserFacts | undefined;

// Resolving the user per source per cycle must not hit Elastic each time. The
// users cache is what activityManager already uses for exactly this.
export const buildUserLookup = async (context: AuthContext, user: AuthUser): Promise<IngestionUserLookup> => {
  const platformUsers = await getEntitiesMapFromCache<any>(context, user ?? SYSTEM_USER, ENTITY_TYPE_USER)
    .catch(() => new Map());
  return (userId) => {
    if (!userId) {
      return undefined;
    }
    const found = platformUsers.get(userId);
    if (!found) {
      return undefined;
    }
    return {
      name: found.name ?? found.user_email,
      service_account: found.user_service_account,
      account_status: found.account_status,
      api_token_expiration: found.api_token_expiration,
      effective_confidence_level: found.effective_confidence_level?.max_confidence
        ?? found.user_confidence_level?.max_confidence
        ?? null,
    };
  };
};

// A managed connector declares its required fields through its contract; an
// empty value on a required one means it cannot start.
export const missingContractFields = (connector: ConnectorLike): string[] => {
  if (!connector.is_managed) {
    return [];
  }
  return (connector.connector_contract_configuration ?? [])
    .filter((field) => field.key && (field.value === null || field.value === undefined || field.value === ''))
    .map((field) => field.key as string);
};

// endregion

// Which connectors this feature is about.
//
// `built_in: true` covers two very different things, and neither belongs here:
//
//   - platform plumbing — `[DRAFT] Draft validation`, `[FILE] CSV Mapper
//     import`, the `[TASK]` / `[PLAYBOOK]` / `[SYNC]` queue connectors. These
//     are static objects that never ping, never carry a user (their TS
//     interface has no `connector_user_id` field at all) and are forced
//     `active: true` by `completeConnector`. Evaluated as ingestion they report
//     NO_HEARTBEAT and USER_MISSING and land on critical, permanently, which is
//     exactly the false positive that makes a health column stop being read.
//
//   - the technical twin every feed registers, `[FEED - CSV] <name>`. That one
//     is a real connector with a real user, but the feed it mirrors is already
//     evaluated in its own right — keeping both would double every feed's
//     health record and send two notifications for one incident.
//
// Composer-managed and self-registered connectors are `built_in: false`, so
// nothing an operator actually deployed is excluded by this.
export const isIngestionConnector = (connector: ConnectorLike): boolean => {
  if (connector.built_in) {
    return false;
  }
  // The queue-backed internal connectors use a lowercase literal that is not in
  // the ConnectorType enum.
  return connector.connector_type !== 'internal';
};

export const buildConnectorHealthInput = (
  connector: ConnectorLike,
  works: WorkLike[],
  // `queueDetails()` returns the full RabbitMQ metric shape — push_* included
  // — but only the listen queue answers "is this connector picking up its own
  // work"; the push queue is drained by workers and says nothing about that.
  queue?: {
    messages_number?: number;
    listen_messages?: number;
    listen_consumers?: number;
    push_messages?: number;
    push_consumers?: number;
  },
  previous?: IngestionHealthObservation,
  // Composer metrics. `null` means the key was absent, which is two different
  // situations — not supervised, or supervised and no longer reporting — told
  // apart by `is_managed` rather than guessed at here.
  stability?: { restart_count: number; is_in_reboot_loop: boolean } | null,
  userLookup?: IngestionUserLookup,
): IngestionHealthInput => {
  const info = connector.connector_info ?? undefined;
  const workFacts = summarizeWorks(works ?? []);
  const lastRunAt = asDate(info?.last_run_datetime) ?? workFacts.last_completed_at;
  const nextExpectedAt = asDate(info?.next_run_datetime);

  // Prefer the declared schedule over anything inferred: it survives the 7-day
  // work retention and it is what the connector itself claims it will do.
  const expectedPeriodSeconds = lastRunAt && nextExpectedAt && nextExpectedAt > lastRunAt
    ? Math.floor((nextExpectedAt.getTime() - lastRunAt.getTime()) / 1000)
    : undefined;

  return {
    id: connector.internal_id ?? connector.id,
    name: connector.name ?? '',
    source_kind: 'connector',
    connector_type: connector.connector_type ?? undefined,
    auto: connector.auto ?? undefined,
    run_and_terminate: info?.run_and_terminate ?? undefined,

    enabled: connector.active !== false,
    manually_stopped: connector.manager_requested_status === 'stopped',
    last_seen_at: asDate(connector.updated_at) ?? asDate(connector.connector_state_timestamp),

    // The listen queue is the one the connector itself consumes from, so it is
    // the queue that answers "work is waiting and nobody is taking it". The
    // push queue is drained by workers and says nothing about this connector.
    // Both counts are undefined when RabbitMQ could not be read, and the
    // evaluator skips NO_CONSUMER in that case rather than reporting an outage
    // as a fleet of broken connectors.
    queue: queue?.listen_messages === undefined ? undefined : {
      messages_ready: queue.listen_messages,
      consumers: queue.listen_consumers,
    },

    created_at: asDate(connector.created_at),
    last_run_at: lastRunAt,
    next_expected_at: nextExpectedAt,
    expected_period_seconds: expectedPeriodSeconds,
    last_productive_at: workFacts.last_productive_at,
    consecutive_empty_runs: workFacts.consecutive_empty_runs,
    last_run_failed: workFacts.last_run_failed,
    last_run_error: workFacts.last_run_error,

    is_managed: connector.is_managed === true,
    restart_count: stability?.restart_count,
    is_in_reboot_loop: stability?.is_in_reboot_loop,
    stability_metrics_present: Boolean(stability),

    configuration_checked: Boolean(userLookup),
    user_id: connector.connector_user_id ?? undefined,
    user: userLookup?.(connector.connector_user_id ?? undefined),
    connector_scope: connector.connector_scope ?? undefined,
    contract_missing_fields: missingContractFields(connector),

    previous,
  };
};

export const resolveConnectorIngestionHealth = async (
  context: AuthContext,
  user: AuthUser,
  connector: ConnectorLike,
): Promise<IngestionHealth | null> => {
  if (!isIngestionConnector(connector)) {
    // Not an ingestion source: report nothing rather than a verdict we have no
    // basis for. The field is nullable, and every surface already handles null.
    return null;
  }
  try {
    const connectorId = connector.internal_id ?? connector.id;
    const [works, queue, stability, previous, userLookup] = await Promise.all([
      worksForConnector(context, user, connectorId, { first: WORKS_LOOKBACK }),
      // RabbitMQ may be unreachable; health must still resolve without it.
      queueDetails(connector.id).catch(() => undefined),
      // Composer metrics, written with a 300s TTL and only by xtm-composer.
      redisGetConnectorHealthMetrics(connectorId).catch(() => null),
      // Read the manager's observation so the chip in the UI and the alert in an
      // email are the same answer: without it the API would evaluate every source
      // as if it had no history, and the cursor check could never fire at read
      // time. One Redis GET next to the works query and the RabbitMQ call.
      redisGetIngestionHealthObservation(connectorId).catch(() => null),
      buildUserLookup(context, user),
    ]);
    const input = buildConnectorHealthInput(
      connector,
      // `worksForConnector` is untyped legacy JS wrapping `elPaginate`'s
      // generic overloads — with `connectionFormat: false` it always returns
      // a plain array of work entities, which is exactly `WorkLike[]`'s
      // shape, but nothing here lets TS narrow that statically.
      (works ?? []) as WorkLike[],
      queue ?? undefined,
      previous ?? undefined,
      stability,
      userLookup,
    );
    return computeIngestionHealth(input, new Date(), INGESTION_HEALTH_THRESHOLDS);
  } catch (e) {
    // A health field must never break the query that asked for it.
    logApp.warn('[OPENCTI-MODULE] Unable to resolve ingestion health', { cause: e, id: connector.id });
    return null;
  }
};

// region feeds and synchronizers
//
// Feeds and synchronizers have no works and no queue: everything they can tell
// us is on the entity itself. They are scheduled, so the expectation comes from
// the declared `scheduling_period` rather than from anything inferred.

interface FeedLike {
  id: string;
  internal_id?: string;
  name?: string;
  created_at?: string | Date;
  ingestion_running?: boolean;
  scheduling_period?: string | null;
  last_execution_date?: string | Date | null;
  last_execution_status?: string | null;
  current_state_cursor?: string | null;
  current_state_hash?: string | null;
  current_state_date?: string | Date | null;
  user_id?: string;
}

interface SyncLike {
  id: string;
  internal_id?: string;
  name?: string;
  created_at?: string | Date;
  running?: boolean;
  current_state_date?: string | Date | null;
  last_execution_date?: string | Date | null;
  last_execution_status?: string | null;
  user_id?: string;
}

// `scheduling_period` is an ISO-8601 duration ("PT1H", "PT6H", "P1D"), or the
// literal "auto" / empty when the feed runs on the manager's own cadence — in
// which case there is no declared period to hold it to.
export const parseSchedulingPeriodSeconds = (period: string | null | undefined): number | undefined => {
  if (!period || period === 'auto') {
    return undefined;
  }
  const match = /^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/.exec(period.trim());
  if (!match) {
    return undefined;
  }
  const [, days, hours, minutes, seconds] = match;
  const total = (Number(days ?? 0) * 86400)
    + (Number(hours ?? 0) * 3600)
    + (Number(minutes ?? 0) * 60)
    + Number(seconds ?? 0);
  return total > 0 ? total : undefined;
};

// A feed reports its own outcome, so we trust `last_execution_status` rather
// than trying to infer failure from the absence of data.
export const isFailedExecution = (status: string | null | undefined) => status === 'error';

// The readable cause behind a failed feed run.
//
// Two sources, on purpose. `last_execution_status` is an Elastic attribute:
// durable, filterable, and the only thing the *status* is ever allowed to
// depend on. The sentence a human needs is not there — the entity stores the
// literal 'error' and nothing else — so it comes from the feed's Redis log
// ring, which is capped at 20 entries, cleared by a flush and gated behind the
// INGESTION_FEED_LOGS flag. Good enough to explain an incident, nowhere near
// good enough to decide one, so this only ever fills `detail`.
export const formatIngestionLogDetail = (entry: IngestionLogEntry): string => {
  const meta = (entry.meta ?? {}) as Record<string, unknown>;
  const parts: string[] = [];
  if (meta.http_status) {
    parts.push(`HTTP ${meta.http_status}${meta.http_status_text ? ` ${meta.http_status_text}` : ''}`);
  }
  if (meta.error_code) {
    parts.push(String(meta.error_code));
  }
  if (meta.cloudflare) {
    parts.push(String(meta.cloudflare));
  }
  // `buildIngestionErrorMeta` puts the raw message here for anything that is not
  // an AxiosError — a parse failure, a mapper failure, a bad payload.
  if (meta.error) {
    parts.push(String(meta.error));
  }
  return parts.length > 0 ? `${entry.message}: ${parts.join(' — ')}` : entry.message;
};

const readFeedFailureDetail = async (feedId: string): Promise<string | undefined> => {
  const entries = await redisGetIngestionLogHistory(feedId).catch(() => [] as IngestionLogEntry[]);
  // The ring is newest-first. Walk back only as far as the last success: an
  // older error from a run that has since succeeded would be a lie, and the
  // `info` entry each run writes when it starts must not hide the failure
  // underneath it.
  for (let i = 0; i < entries.length; i += 1) {
    const entry = entries[i];
    if (entry.level === 'success') {
      return undefined;
    }
    if (entry.level === 'error') {
      return formatIngestionLogDetail(entry);
    }
  }
  return undefined;
};

export const buildFeedHealthInput = (
  feed: FeedLike,
  previous?: IngestionHealthObservation,
  // Best-effort, from `readFeedFailureDetail`. Absent is normal — the flag may
  // be off, Redis may have been flushed, the entry may have aged out of the
  // ring — and the check still fires on the persisted status either way.
  lastRunError?: string,
  userLookup?: IngestionUserLookup,
): IngestionHealthInput => {
  const lastRunAt = asDate(feed.last_execution_date);
  const periodSeconds = parseSchedulingPeriodSeconds(feed.scheduling_period);
  const failed = isFailedExecution(feed.last_execution_status);
  return {
    id: feed.internal_id ?? feed.id,
    name: feed.name ?? '',
    source_kind: 'feed',
    enabled: feed.ingestion_running !== false,
    manually_stopped: feed.ingestion_running === false,
    created_at: asDate(feed.created_at),
    last_run_at: lastRunAt,
    next_expected_at: lastRunAt && periodSeconds
      ? new Date(lastRunAt.getTime() + periodSeconds * 1000)
      : undefined,
    expected_period_seconds: periodSeconds,
    last_run_failed: failed,
    // Left undefined when the log could not be read: the message renderer says
    // "Last run failed: unknown", which is honest. Echoing the literal status
    // here would produce "Last run failed: error", which is not.
    last_run_error: failed ? lastRunError : undefined,
    last_productive_at: asDate(feed.current_state_date) ?? lastRunAt,
    // A feed has no per-run object count, so "empty runs" is not observable from
    // the entity alone. The manager counts unchanged cursors across runs and
    // keeps the total in the observation; CURSOR_STALLED reads it back here.
    consecutive_empty_runs: previous?.consecutive_empty_runs ?? 0,
    cursor_hash: feed.current_state_cursor ?? feed.current_state_hash ?? undefined,

    configuration_checked: Boolean(userLookup),
    user_id: feed.user_id,
    user: userLookup?.(feed.user_id),

    previous,
  };
};

export const buildSyncHealthInput = (
  sync: SyncLike,
  previous?: IngestionHealthObservation,
  userLookup?: IngestionUserLookup,
): IngestionHealthInput => {
  const lastRunAt = asDate(sync.last_execution_date);
  return {
    id: sync.internal_id ?? sync.id,
    name: sync.name ?? '',
    source_kind: 'sync',
    enabled: sync.running !== false,
    manually_stopped: sync.running === false,
    created_at: asDate(sync.created_at),
    last_run_at: lastRunAt,
    last_run_failed: isFailedExecution(sync.last_execution_status),
    // `syncManager` writes no ingestion log entries — only the four scheduled
    // feed types do — so there is no readable cause to attach, and the message
    // renders "Last run failed: unknown" rather than the useless "…: error".
    last_run_error: undefined,
    // A synchronizer is productive when its stream cursor advances, so the
    // cursor date is the closest thing it has to "it brought something in".
    last_productive_at: asDate(sync.current_state_date),
    consecutive_empty_runs: previous?.consecutive_empty_runs ?? 0,
    cursor_hash: asDate(sync.current_state_date)?.toISOString(),

    configuration_checked: Boolean(userLookup),
    user_id: sync.user_id,
    user: userLookup?.(sync.user_id),

    previous,
  };
};

// The entity carries every fact the evaluator reads; the only fetch is the
// manager's observation, which is what the cursor check needs and what keeps the
// API's answer identical to the one that was notified on.
export const resolveFeedIngestionHealth = async (
  feed: FeedLike,
  context?: AuthContext,
  user?: AuthUser,
): Promise<IngestionHealth> => {
  const feedId = feed.internal_id ?? feed.id;
  const [previous, failureDetail, userLookup] = await Promise.all([
    redisGetIngestionHealthObservation(feedId).catch(() => null),
    // Only read the log ring when the entity already says the run failed, so a
    // healthy platform pays nothing for it.
    isFailedExecution(feed.last_execution_status) ? readFeedFailureDetail(feedId) : undefined,
    context ? buildUserLookup(context, user as AuthUser) : undefined,
  ]);
  return computeIngestionHealth(
    buildFeedHealthInput(feed, previous ?? undefined, failureDetail, userLookup),
    new Date(),
    INGESTION_HEALTH_THRESHOLDS,
  );
};

export const resolveSyncIngestionHealth = async (
  sync: SyncLike,
  context?: AuthContext,
  user?: AuthUser,
): Promise<IngestionHealth> => {
  const syncId = sync.internal_id ?? sync.id;
  const [previous, userLookup] = await Promise.all([
    redisGetIngestionHealthObservation(syncId).catch(() => null),
    context ? buildUserLookup(context, user as AuthUser) : undefined,
  ]);
  return computeIngestionHealth(buildSyncHealthInput(sync, previous ?? undefined, userLookup), new Date(), INGESTION_HEALTH_THRESHOLDS);
};
// endregion

// region source collection (used by the health manager)
//
// One normalized snapshot per ingestion source, so the manager iterates a
// single list instead of knowing about seven entity types.

export interface IngestionSourceSnapshot {
  id: string;
  name: string;
  entity_type: string;
  source_kind: 'connector' | 'feed' | 'sync';
  // Deep-link suffix under /dashboard/integrations/ — only connectors have a
  // per-id detail route, the rest link to their list.
  route: string;
  input: IngestionHealthInput;
}

// `route` is what the email template turns into a link; only connectors have a
// per-id page, so everything else points at its list.
const FEED_SOURCES: Array<{ type: string; route: string }> = [
  { type: ENTITY_TYPE_INGESTION_RSS, route: 'feeds/rss' },
  { type: ENTITY_TYPE_INGESTION_TAXII, route: 'feeds/taxii' },
  { type: ENTITY_TYPE_INGESTION_TAXII_COLLECTION, route: 'feeds/taxii-push' },
  { type: ENTITY_TYPE_INGESTION_CSV, route: 'feeds/csv' },
  { type: ENTITY_TYPE_INGESTION_JSON, route: 'feeds/json' },
];

export const collectIngestionSources = async (
  context: AuthContext,
  user: AuthUser,
): Promise<IngestionSourceSnapshot[]> => {
  const snapshots: IngestionSourceSnapshot[] = [];

  // Built once for the whole pass: the users cache is shared, so resolving the
  // ingesting user for forty sources costs one lookup, not forty.
  const userLookup = await buildUserLookup(context, user);

  const platformConnectors = await connectors(context, user);
  for (const connector of platformConnectors) {
    if (!isIngestionConnector(connector)) {
      continue;
    }
    const connectorId = connector.internal_id ?? connector.id;
    const [works, queue, stability] = await Promise.all([
      worksForConnector(context, user, connectorId, { first: WORKS_LOOKBACK }).catch(() => []),
      // RabbitMQ may be unreachable; health must still evaluate without it.
      queueDetails(connector.id).catch(() => undefined),
      redisGetConnectorHealthMetrics(connectorId).catch(() => null),
    ]);
    snapshots.push({
      id: connectorId,
      name: connector.name ?? '',
      entity_type: 'Connector',
      source_kind: 'connector',
      route: `connectors/${connectorId}`,
      input: buildConnectorHealthInput(connector, (works ?? []) as WorkLike[], queue ?? undefined, undefined, stability, userLookup),
    });
  }

  for (const feedSource of FEED_SOURCES) {
    const feeds = await fullEntitiesList<any>(context, user, [feedSource.type], {}).catch(() => []);
    for (const feed of feeds) {
      const feedId = feed.internal_id ?? feed.id;
      // This is the path the notification is built from, so the readable cause
      // has to be resolved here too — otherwise the email says "Last run
      // failed: unknown" while the UI, which resolves it, says why.
      const failureDetail = isFailedExecution(feed.last_execution_status)
        ? await readFeedFailureDetail(feedId)
        : undefined;
      snapshots.push({
        id: feedId,
        name: feed.name ?? '',
        entity_type: feedSource.type,
        source_kind: 'feed',
        route: feedSource.route,
        input: buildFeedHealthInput(feed, undefined, failureDetail, userLookup),
      });
    }
  }

  const syncs = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_SYNC], {}).catch(() => []);
  for (const sync of syncs) {
    snapshots.push({
      id: sync.internal_id ?? sync.id,
      name: sync.name ?? '',
      entity_type: ENTITY_TYPE_SYNC,
      source_kind: 'sync',
      route: 'feeds/sync',
      input: buildSyncHealthInput(sync, undefined, userLookup),
    });
  }

  return snapshots;
};
// endregion
