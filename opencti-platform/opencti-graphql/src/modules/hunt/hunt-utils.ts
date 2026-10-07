import { createHash } from 'node:crypto';
import conf, { booleanConf } from '../../config/conf';
import { ValidationError } from '../../config/errors';
import { type FilterGroup, FilterMode, FilterOperator, HuntTechniqueValidationStatus } from '../../generated/graphql';
import { checkFiltersValidity, isFilterGroupNotEmpty } from '../../utils/filtering/filtering-utils';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { HUNT_PLATFORMS, HUNT_SCHEDULE_STANDING, type HuntNativeQuery } from './hunt-types';
import type { HuntEvidence, HuntHit } from './huntRun/huntRun-types';
import { isCronSchedule } from './hunt-schedule';

const numberConf = (key: string, fallback: number): number => {
  const value = Number(conf.get(key));
  return Number.isFinite(value) && value > 0 ? value : fallback;
};

// Counts bound loops, pages, batches, slices and retries: a decimal is floored, a blank value or a count below the
// minimum (one, zero where none is meaningful) falls back to the default
export const huntCountSetting = (setting: unknown, fallback: number, min = 1): number => {
  if (setting === undefined || setting === null || (typeof setting === 'string' && setting.trim() === '')) {
    return fallback;
  }
  const value = Math.floor(Number(setting));
  return Number.isFinite(value) && value >= min ? value : fallback;
};
const countConf = (key: string, fallback: number, min = 1): number => huntCountSetting(conf.get(key), fallback, min);

export const HUNT_CONFIG = {
  enabled: booleanConf('hunt_manager:enabled', true),
  lockKey: conf.get('hunt_manager:lock_key') || 'hunt_manager_lock',
  interval: numberConf('hunt_manager:interval', 30000),
  streamBatchSize: countConf('hunt_manager:stream_batch_size', 5000),
  maxRunsPerTick: countConf('hunt_manager:max_runs_per_tick', 50),
  automationPageSize: countConf('hunt_manager:automation_page_size', 500),
  automationMaxPagesPerTick: countConf('hunt_manager:automation_max_pages_per_tick', 4),
  maxConcurrentRunsPerConnector: countConf('hunt_manager:max_concurrent_runs_per_connector', 2),
  dailyRunsPerConnector: countConf('hunt_manager:daily_runs_per_connector', 200),
  runTimeoutMinutes: numberConf('hunt_manager:run_timeout_minutes', 60),
  previewTimeoutMinutes: numberConf('hunt_manager:preview_timeout_minutes', 5),
  maxRetries: countConf('hunt_manager:max_retries', 2, 0),
  retryBackoffMinutes: numberConf('hunt_manager:retry_backoff_minutes', 10),
  standingDebounceMinutes: numberConf('hunt_manager:standing_debounce_minutes', 15),
  standingFilterEvaluationsPerTick: countConf('hunt_manager:standing_filter_evaluations_per_tick', 20000),
  minScheduleIntervalMinutes: numberConf('hunt_manager:min_schedule_interval_minutes', 15),
  maxTimeWindowHours: numberConf('hunt_manager:max_time_window_hours', 720),
  maxResultsPerRun: countConf('hunt_manager:max_results_per_run', 10000),
  maxIocsPerRun: countConf('hunt_manager:max_iocs_per_run', 1000),
  iocBatchSize: countConf('hunt_manager:ioc_batch_size', 50),
  evidenceMaxItems: countConf('hunt_manager:evidence_max_items', 20),
  evidenceMaxValueLength: countConf('hunt_manager:evidence_max_value_length', 256),
  hitSampleMaxItems: countConf('hunt_manager:hit_sample_max_items', 50),
  hitMaxValueLength: countConf('hunt_manager:hit_max_value_length', 1024),
  hitObservedDataMaxItems: countConf('hunt_manager:hit_observed_data_max_items', 20),
  queueExpiryHours: numberConf('hunt_manager:queue_expiry_hours', 24),
  dispatchRecoveryMinutes: numberConf('hunt_manager:dispatch_recovery_minutes', 5),
  runRetentionDays: numberConf('hunt_manager:run_retention_days', 365),
  previewRetentionDays: numberConf('hunt_manager:preview_retention_days', 7),
  maxHitRecordsPurgedPerTick: countConf('hunt_manager:max_hit_records_purged_per_tick', 10000),
  scheduleLookbackMinutes: Number.isFinite(Number(conf.get('hunt_manager:schedule_lookback_minutes')))
    ? Math.max(0, Number(conf.get('hunt_manager:schedule_lookback_minutes')))
    : 15,
};

// What a run reports as observables when its hunt names none: what a hit commonly involves. Each connector keeps the
// types it can extract
export const HUNT_DEFAULT_EXPECTED_OBSERVABLES = ['IPv4-Addr', 'IPv6-Addr', 'Domain-Name', 'Url', 'StixFile', 'Email-Addr', 'Hostname', 'User-Account', 'X509-Certificate'];

export const huntExpectedObservables = (hunt: { expected_observables?: string[] | null }) => {
  const expected = (hunt.expected_observables ?? []).filter((type) => typeof type === 'string' && type.trim().length > 0);
  return expected.length > 0 ? expected : HUNT_DEFAULT_EXPECTED_OBSERVABLES;
};

export const HUNT_DEFAULT_TIME_WINDOW_HOURS = 24;
export const HUNT_DEFAULT_ESCALATION_THRESHOLD = 10;
export const HUNT_DEFAULT_MAX_RESULTS = 1000;
export const HUNT_MAX_ESCALATION_THRESHOLD = 1000000;
const NATIVE_QUERY_MAX_LENGTH = 65536;
const NATIVE_QUERY_LANGUAGE_MAX_LENGTH = 64;
const NATIVE_QUERY_PIPELINE_MAX_LENGTH = 256;
const EVIDENCE_FIELD_MAX_LENGTH = 256;

/**
 * A hunt is autonomous when it runs without a human action: cron schedule, standing hunt or PIR activation.
 * Autonomous hunts are an Enterprise Edition capability.
 */
export const isAutonomousHunt = (hunt: { hunt_schedule?: string | null; hunt_pir_activation?: boolean | null }) => {
  return isCronSchedule(hunt.hunt_schedule) || hunt.hunt_schedule === HUNT_SCHEDULE_STANDING || hunt.hunt_pir_activation === true;
};

export const sha256 = (value: string) => createHash('sha256').update(value, 'utf8').digest('hex');

export const truncate = (value: string, maxLength: number) => {
  if (value.length <= maxLength) {
    return value;
  }
  return `${value.substring(0, Math.max(0, maxLength - 3))}...`;
};

/** Status of a technique from the counts of its emulation runs: one completed run with hits proves the detection. */
export const techniqueValidationStatus = (counts: { runs: number; detected: number; active: number; completed: number }): HuntTechniqueValidationStatus => {
  if (counts.runs === 0) {
    return HuntTechniqueValidationStatus.NotValidated;
  }
  if (counts.detected > 0) {
    return HuntTechniqueValidationStatus.Validated;
  }
  if (counts.active > 0) {
    return HuntTechniqueValidationStatus.InProgress;
  }
  return counts.completed > 0 ? HuntTechniqueValidationStatus.NotDetected : HuntTechniqueValidationStatus.NotValidated;
};

// Secrets and personal data a telemetry value can carry, masked before a preview is stored whatever the connector sent.
// Indicators (addresses, domains, hashes, command lines) stay readable: they are what an analyst triages.
const SECRET_MASKS: { pattern: RegExp; replacement: string }[] = [
  { pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g, replacement: '[masked private key]' },
  { pattern: /\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}/g, replacement: '[masked token]' },
  { pattern: /\b(bearer|basic)\s+[\w~+/.-]{8,}=*/gi, replacement: '$1 [masked]' },
  { pattern: /\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|authorization)(["']?\s*[:=]\s*["']?)(?!(?:bearer|basic)\s)[^\s"'&;,]+/gi, replacement: '$1$2[masked]' },
  { pattern: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, replacement: '[masked key]' },
  // Credentials in a URL (scheme://user:password@host) and on a command line (curl -u user:password, --password value),
  // masked before the e-mail rule reads "password@host" as an address
  { pattern: /\b([a-z][a-z\d+.-]*:\/\/[^\s/:@]+):[^\s/@]+@/gi, replacement: '$1:[masked]@' },
  { pattern: /(^|\s)(-u|--user|--proxy-user)(\s+|=)(["']?)([^\s:"']+):("[^"]*"|'[^']*'|[^\s"']+)/gi, replacement: '$1$2$3$4$5:[masked]' },
  { pattern: /(^|\s)(--?(?:password|passwd|pass|pwd|secret|token|api[_-]?key|client[_-]?secret))(\s+)("[^"]*"|'[^']*'|(?!-)[^\s"']+)/gi, replacement: '$1$2$3[masked]' },
];
const EVIDENCE_MASKS: { pattern: RegExp; replacement: string }[] = [
  ...SECRET_MASKS,
  { pattern: /\b[\w.%+-]+@((?:[\w-]+\.)+[a-z]{2,})\b/gi, replacement: '[masked]@$1' },
  { pattern: /\b\d{9,}\b/g, replacement: '[masked number]' },
];

const applyMasks = (masks: { pattern: RegExp; replacement: string }[], value: string) => {
  return masks.reduce((masked, { pattern, replacement }) => masked.replace(pattern, replacement), value);
};

/** Masks the secrets and personal data of a telemetry value preview (credentials, tokens, keys, e-mail users, long numbers). */
export const maskEvidencePreview = (value: string) => applyMasks(EVIDENCE_MASKS, value);

export interface HuntEvidenceInputLike {
  field?: string | null;
  value_hash?: string | null;
  value_preview?: string | null;
  count?: number | null;
  matched?: boolean | null;
}

export interface HuntHitInputLike {
  event_id?: string | null;
  timestamp?: string | Date | null;
  detection?: string | null;
  matched?: { field?: string | null; value_hash?: string | null; value_preview?: string | null }[] | null;
  host?: string | null;
  user?: string | null;
  process?: string | null;
}

const HIT_MATCHED_FIELDS_MAX = 10;
const HIT_EVENT_ID_MAX_LENGTH = 256;
const HIT_DETECTION_MAX_LENGTH = 512;

const toIsoDate = (value: unknown): string | null => {
  if (!(typeof value === 'string' && value.trim().length > 0) && !(value instanceof Date)) {
    return null;
  }
  const date = new Date(value as string | Date);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
};

// The event id, detection, host, account and process of a hit name what the event involved: an analyst reads them to
// triage the hit and the platform extracts observables from them, so only their secrets are masked
const hitEntityValue = (value: unknown, maxLength: number): string | null => {
  if (typeof value !== 'string' || value.trim().length === 0) {
    return null;
  }
  return truncate(applyMasks(SECRET_MASKS, value.trim()), maxLength);
};

export const HUNT_HIT_KEY_VERSION = 'v1';

const hitKeyValue = (value: unknown): string => (typeof value === 'string' ? value : '');

/**
 * The stable key of a hit, computed over the hit as the connector reported it (before the platform masks or truncates
 * anything), the rule the connectors SDK applies to every hit it reads (analysis.hit_key): the SHA-256 hex digest of a
 * compact JSON array, ["v1", "detection", detection] for a hit grouped into a detection, else ["v1", "event", event id],
 * else ["v1", "fields", timestamp to the second in UTC ("YYYY-MM-DDTHH:MM:SSZ" or ""), host, user, process,
 * [[field, value hash in lower case], ...] sorted]. An empty string counts as absent. The security platform is not part
 * of the key: the known hits of a hunt are kept per security platform.
 */
export const huntHitKey = (hit: HuntHitInputLike): string => {
  const detection = hitKeyValue(hit?.detection);
  const eventId = hitKeyValue(hit?.event_id);
  let parts: unknown[];
  if (detection.length > 0) {
    parts = [HUNT_HIT_KEY_VERSION, 'detection', detection];
  } else if (eventId.length > 0) {
    parts = [HUNT_HIT_KEY_VERSION, 'event', eventId];
  } else {
    const timestamp = toIsoDate(hit?.timestamp);
    const matched = (Array.isArray(hit?.matched) ? hit.matched : [])
      .map((match) => [hitKeyValue(match?.field), hitKeyValue(match?.value_hash).toLowerCase()])
      .sort(([fieldA, hashA], [fieldB, hashB]) => {
        if (fieldA !== fieldB) {
          return fieldA < fieldB ? -1 : 1;
        }
        if (hashA !== hashB) {
          return hashA < hashB ? -1 : 1;
        }
        return 0;
      });
    parts = [
      HUNT_HIT_KEY_VERSION,
      'fields',
      timestamp ? `${timestamp.substring(0, 19)}Z` : '',
      hitKeyValue(hit?.host),
      hitKeyValue(hit?.user),
      hitKeyValue(hit?.process),
      matched,
    ];
  }
  return sha256(JSON.stringify(parts));
};

const HIT_KEY_PATTERN = /^[0-9a-f]{64}$/;

/** The hit keys a connector reported, distinct and well formed, at most as many as the results a run may read. */
export const sanitizeHitKeys = (keys: unknown, maxItems = HUNT_CONFIG.maxResultsPerRun): string[] | null => {
  if (!Array.isArray(keys)) {
    return null;
  }
  const valid = keys.filter((key): key is string => typeof key === 'string').map((key) => key.trim().toLowerCase()).filter((key) => HIT_KEY_PATTERN.test(key));
  return Array.from(new Set(valid)).slice(0, maxItems);
};

/**
 * The hit keys of a report when they identify its hits, null when they cannot: no list, an entry that is not a hit key,
 * no key for a report with hits, more distinct keys than hits, or a sampled hit whose key is not listed. A connector
 * reports one key per hit it read, distinct and bounded by the maximum results, so fewer keys than hits is expected
 * (hits of one detection, truncated results) and more is not (see splitHitsByKeys); a sampled hit is one of the hits
 * read, so its key is always listed. `extraKeys` are the keys an indicator hunt reports per value, hits of the report
 * as well.
 */
export const identifyingHitKeys = (
  keys: unknown,
  report: { hitsCount: number; sampledKeys?: ReadonlyArray<string | null | undefined>; extraKeys?: ReadonlyArray<string> },
  maxItems = HUNT_CONFIG.maxResultsPerRun,
): string[] | null => {
  if (!Array.isArray(keys)) {
    return null;
  }
  const normalized = keys.map((key) => (typeof key === 'string' ? key.trim().toLowerCase() : ''));
  if (normalized.some((key) => !HIT_KEY_PATTERN.test(key))) {
    return null;
  }
  const distinct = Array.from(new Set([...normalized, ...(report.extraKeys ?? [])]));
  if ((report.hitsCount > 0 && distinct.length === 0) || distinct.length > report.hitsCount) {
    return null;
  }
  const listed = new Set(distinct);
  if ((report.sampledKeys ?? []).some((key) => !!key && !listed.has(key))) {
    return null;
  }
  return distinct.slice(0, maxItems);
};

/**
 * The new and recurring hits of a report or evidence, from the new and known keys among its identifying keys. A key can
 * stand for several hits (the events of one detection), so the hits without a key of their own are split like the keyed
 * ones: the new and recurring hits always add up to the hits counted, and new keys never stand for fewer new hits.
 */
export const splitHitsByKeys = (hitsCount: number, newKeys: number, recurringKeys: number) => {
  const keyed = newKeys + recurringKeys;
  if (keyed === 0 || hitsCount <= keyed) {
    return { newHits: newKeys, recurringHits: recurringKeys };
  }
  const newHits = Math.round((hitsCount * newKeys) / keyed);
  return { newHits, recurringHits: hitsCount - newHits };
};

/**
 * One evidence item per hit, as the platform stores it: when, where, who, the process and the fields the hunt logic
 * matched, so that a single hit can be read next to the per-field aggregation of the evidence sample. Matched values
 * get the treatment of the evidence sample (hashed again, previews masked and truncated); a preview is complete when
 * it is the whole value the connector hashed and the platform did not alter it. Each hit keeps the key of the hit as
 * reported (huntHitKey). Hits are kept in time order, at most `maxItems`, a hit without any value is dropped.
 */
export const sanitizeHits = (
  hits: HuntHitInputLike[] | null | undefined,
  maxItems = HUNT_CONFIG.hitSampleMaxItems,
  maxValueLength = HUNT_CONFIG.hitMaxValueLength,
): HuntHit[] => {
  const sanitized = (hits ?? []).flatMap((item): HuntHit[] => {
    const matched = (Array.isArray(item?.matched) ? item.matched : []).flatMap((match) => {
      const field = typeof match?.field === 'string' ? truncate(match.field.trim(), EVIDENCE_FIELD_MAX_LENGTH) : '';
      const value = typeof match?.value_hash === 'string' ? match.value_hash.trim().toLowerCase() : '';
      if (field.length === 0 || value.length === 0) {
        return [];
      }
      const raw = typeof match.value_preview === 'string' && match.value_preview.length > 0 ? match.value_preview : null;
      const preview = raw ? truncate(maskEvidencePreview(raw), maxValueLength) : null;
      return [{ field, value_hash: sha256(value), value_preview: preview, value_complete: raw !== null && preview === raw && sha256(raw) === value }];
    }).slice(0, HIT_MATCHED_FIELDS_MAX);
    const hit: HuntHit = {
      hit_key: huntHitKey(item),
      event_id: hitEntityValue(item?.event_id, HIT_EVENT_ID_MAX_LENGTH),
      timestamp: toIsoDate(item?.timestamp),
      detection: hitEntityValue(item?.detection, HIT_DETECTION_MAX_LENGTH),
      matched,
      host: hitEntityValue(item?.host, maxValueLength),
      user: hitEntityValue(item?.user, maxValueLength),
      process: hitEntityValue(item?.process, maxValueLength),
    };
    const filled = matched.length > 0 || [hit.event_id, hit.timestamp, hit.detection, hit.host, hit.user, hit.process].some((value) => value !== null);
    return filled ? [hit] : [];
  });
  return mergeHits([], sanitized, maxItems);
};

/** Stored hits with hits sanitized since, one per event, in time order (undated hits last): the first `maxItems` are kept. */
export const mergeHits = (stored: HuntHit[], added: HuntHit[], maxItems = HUNT_CONFIG.hitSampleMaxItems): HuntHit[] => {
  const seenEvents = new Set<string>();
  const merged = [...stored, ...added].filter((hit) => {
    if (!hit.event_id) {
      return true;
    }
    const known = seenEvents.has(hit.event_id);
    seenEvents.add(hit.event_id);
    return !known;
  });
  return merged
    .map((hit, index) => ({ hit, index }))
    .sort((a, b) => (a.hit.timestamp ?? '\uffff').localeCompare(b.hit.timestamp ?? '\uffff') || a.index - b.index)
    .slice(0, maxItems)
    .map(({ hit }) => hit);
};

/**
 * Dates of the first and last hit of a run: the dates the connector reports for the whole run when it sends them (its
 * sample is capped), widened by the hits of the sample; null when nothing dates a hit.
 */
export const huntHitDates = (
  hits: Pick<HuntHit, 'timestamp'>[],
  reported: { first_hit_at?: string | Date | null; last_hit_at?: string | Date | null } = {},
  stored: { first_hit_at?: string | null; last_hit_at?: string | null } = {},
): { first_hit_at: string | null; last_hit_at: string | null } => {
  const dates = [reported.first_hit_at, reported.last_hit_at, stored.first_hit_at, stored.last_hit_at, ...hits.map((hit) => hit.timestamp)]
    .map(toIsoDate)
    .filter((date): date is string => date !== null)
    .sort();
  return dates.length > 0 ? { first_hit_at: dates[0], last_hit_at: dates[dates.length - 1] } : { first_hit_at: null, last_hit_at: null };
};

/** The evidence of a field a hit matched is matched evidence, whether or not the connector flagged it: it comes first. */
export const markMatchedEvidence = (evidence: HuntEvidence[], hits: Pick<HuntHit, 'matched'>[]): HuntEvidence[] => {
  const matchedFields = new Set(hits.flatMap((hit) => (hit.matched ?? []).map((match) => match.field)));
  const marked = evidence.map((item) => ({ ...item, matched: item.matched === true || matchedFields.has(item.field) }));
  return mergeEvidence([], marked, marked.length);
};

/**
 * Evidence a connector sent, as the platform stores it: never raw telemetry. The platform hashes every submitted value
 * itself, a connector digest included (a 64-character hexadecimal value can as well be a raw key), masks previews and
 * enforces its own caps whatever the connector sent.
 */
export const sanitizeEvidence = (
  evidence: HuntEvidenceInputLike[] | null | undefined,
  maxItems = HUNT_CONFIG.evidenceMaxItems,
  maxValueLength = HUNT_CONFIG.evidenceMaxValueLength,
): HuntEvidence[] => {
  const items = (evidence ?? []).flatMap((item): HuntEvidence[] => {
    const field = typeof item.field === 'string' ? truncate(item.field.trim(), EVIDENCE_FIELD_MAX_LENGTH) : '';
    const value = typeof item.value_hash === 'string' ? item.value_hash.trim().toLowerCase() : '';
    if (field.length === 0 || value.length === 0) {
      return [];
    }
    const count = Number.isInteger(item.count) && (item.count as number) > 0 ? (item.count as number) : 1;
    const preview = typeof item.value_preview === 'string' && item.value_preview.length > 0
      ? truncate(maskEvidencePreview(item.value_preview), maxValueLength)
      : null;
    return [{ field, value_hash: sha256(value), value_preview: preview, count, matched: item.matched === true }];
  });
  return mergeEvidence([], items, maxItems);
};

/**
 * Stored evidence with evidence sanitized since, one item per field and value: hashes are the platform's already and
 * are never hashed again. The values the hunt logic matched come first: by count alone, metadata constant across the
 * hits (labels, categories, enrichment states) would crowd them out of the sample.
 */
export const mergeEvidence = (stored: HuntEvidence[], added: HuntEvidence[], maxItems = HUNT_CONFIG.evidenceMaxItems): HuntEvidence[] => {
  const byKey = new Map<string, HuntEvidence>();
  [...stored, ...added].forEach((item) => {
    const key = `${item.field}:${item.value_hash}`;
    const existing = byKey.get(key);
    if (existing) {
      existing.count += item.count;
      existing.matched = existing.matched || item.matched === true;
    } else {
      byKey.set(key, { field: item.field, value_hash: item.value_hash, value_preview: item.value_preview ?? null, count: item.count, matched: item.matched === true });
    }
  });
  return Array.from(byKey.values())
    .sort((a, b) => Number(b.matched) - Number(a.matched) || b.count - a.count || a.field.localeCompare(b.field))
    .slice(0, maxItems);
};

const parseNativeQueryItem = (rawItem: unknown, index: number): Partial<HuntNativeQuery> => {
  if (typeof rawItem !== 'string') {
    return rawItem as Partial<HuntNativeQuery>;
  }
  try {
    return JSON.parse(rawItem) as Partial<HuntNativeQuery>;
  } catch {
    throw ValidationError(`Native query ${index + 1} must be a JSON object with a platform, a language and a query`, 'native_queries');
  }
};

export const normalizeNativeQueries = (nativeQueries: unknown): HuntNativeQuery[] => {
  if (nativeQueries === null || nativeQueries === undefined || nativeQueries === '') {
    return [];
  }
  const items = Array.isArray(nativeQueries) ? nativeQueries : [nativeQueries];
  const platforms = new Set<string>();
  return items.map((rawItem, index) => {
    const item = parseNativeQueryItem(rawItem, index);
    const platform = typeof item?.platform === 'string' ? item.platform.trim() : '';
    if (!HUNT_PLATFORMS.includes(platform)) {
      throw ValidationError(`Native query ${index + 1}: platform must be one of ${HUNT_PLATFORMS.join(', ')}`, 'native_queries');
    }
    if (platforms.has(platform)) {
      throw ValidationError(`Native query ${index + 1}: only one native query per platform is allowed (${platform})`, 'native_queries');
    }
    platforms.add(platform);
    const language = typeof item.language === 'string' ? item.language.trim() : '';
    if (language.length === 0 || language.length > NATIVE_QUERY_LANGUAGE_MAX_LENGTH) {
      throw ValidationError(`Native query ${index + 1}: a language is required`, 'native_queries');
    }
    const query = typeof item.query === 'string' ? item.query.trim() : '';
    if (query.length === 0 || query.length > NATIVE_QUERY_MAX_LENGTH) {
      throw ValidationError(`Native query ${index + 1}: the query is required and limited to ${NATIVE_QUERY_MAX_LENGTH} characters`, 'native_queries');
    }
    const pipeline = typeof item.pipeline === 'string' && item.pipeline.trim().length > 0 ? item.pipeline.trim() : null;
    if (pipeline && pipeline.length > NATIVE_QUERY_PIPELINE_MAX_LENGTH) {
      throw ValidationError(`Native query ${index + 1}: the pipeline name is too long`, 'native_queries');
    }
    return { platform, language, query, pipeline };
  });
};

const FILTER_GROUP_SHAPE_ERROR = 'Filters must be a filter group (mode, filters, filterGroups)';

/**
 * Parses a stored filter group, empty / blank values meaning "no filter". A non-empty group is checked like every
 * filter group of the platform (format, value syntax, keys of the schema), so that a malformed one is refused when
 * the hunt is saved instead of failing every later readiness, indicator or manager query.
 */
export const parseHuntFilterGroup = (filters: string | null | undefined, field: string): FilterGroup | null => {
  if (filters === null || filters === undefined || filters.trim().length === 0) {
    return null;
  }
  let parsed: FilterGroup;
  try {
    parsed = JSON.parse(filters);
  } catch {
    throw ValidationError('Filters must be a valid JSON filter group', field);
  }
  if (typeof parsed !== 'object' || parsed === null || !Array.isArray(parsed.filters) || !Array.isArray(parsed.filterGroups)) {
    throw ValidationError(FILTER_GROUP_SHAPE_ERROR, field);
  }
  if (!isFilterGroupNotEmpty(parsed)) {
    return null;
  }
  try {
    checkFiltersValidity(parsed);
  } catch (error) {
    // A filter or nested group that is not an object fails inside the format check itself
    throw ValidationError(error instanceof TypeError ? FILTER_GROUP_SHAPE_ERROR : `Invalid filters: ${(error as Error).message}`, field);
  }
  return parsed;
};

/**
 * The hunt scope of explicit Security Platforms, as the hunt form writes and reads it back; empty without platform,
 * an empty scope meaning every platform.
 */
export const buildHuntScopeFilter = (platformIds: string[]): string => {
  if (platformIds.length === 0) {
    return '';
  }
  return JSON.stringify({
    mode: FilterMode.And,
    filters: [{ key: ['id'], values: platformIds, operator: FilterOperator.Eq, mode: FilterMode.Or }],
    filterGroups: [],
  });
};

type AccessRestricted = { [RELATION_OBJECT_MARKING]?: string[]; [RELATION_GRANTED_TO]?: string[] };

/**
 * The organizations an object derived from several others is shared with: those every one of them is shared with.
 * With a platform organization, an object shared with no organization is readable by the platform organization only,
 * so one of them shared with none makes the list empty. Null when those shared with organizations have none in
 * common (nothing can be derived).
 */
export const sharedOrganizations = (restrictions: string[][]): string[] | null => {
  const restricted = restrictions.filter((organizations) => organizations.length > 0);
  if (restricted.length === 0) {
    return [];
  }
  const shared = restricted.reduce((kept, organizations) => kept.filter((id) => organizations.includes(id)));
  if (shared.length === 0) {
    return null;
  }
  return restricted.length < restrictions.length ? [] : Array.from(new Set(shared));
};

/**
 * Access of a run, which discloses both its hunt and its target security platform: the markings of both, and only
 * the organizations both are shared with (sharedOrganizations). Null when the hunt and the platform are shared with
 * disjoint organizations.
 */
export const huntRunRestrictions = (hunt: AccessRestricted, platform?: AccessRestricted | null) => {
  const objectMarking = Array.from(new Set([...(hunt[RELATION_OBJECT_MARKING] ?? []), ...(platform?.[RELATION_OBJECT_MARKING] ?? [])]));
  const objectOrganization = sharedOrganizations([hunt[RELATION_GRANTED_TO] ?? [], ...(platform ? [platform[RELATION_GRANTED_TO] ?? []] : [])]);
  return objectOrganization ? { objectMarking, objectOrganization } : null;
};

export const clampInteger = (value: unknown, min: number, max: number, fallback: number) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, Math.round(numeric)));
};
