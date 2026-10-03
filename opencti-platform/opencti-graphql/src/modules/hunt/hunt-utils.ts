import { createHash } from 'node:crypto';
import conf, { booleanConf } from '../../config/conf';
import { ValidationError } from '../../config/errors';
import type { FilterGroup } from '../../generated/graphql';
import { isFilterGroupNotEmpty } from '../../utils/filtering/filtering-utils';
import { HUNT_PLATFORMS, HUNT_SCHEDULE_STANDING, type HuntNativeQuery } from './hunt-types';
import type { HuntEvidence } from './huntRun/huntRun-types';
import { isCronSchedule } from './hunt-schedule';

const numberConf = (key: string, fallback: number): number => {
  const value = Number(conf.get(key));
  return Number.isFinite(value) && value > 0 ? value : fallback;
};

export const HUNT_CONFIG = {
  enabled: booleanConf('hunt_manager:enabled', true),
  lockKey: conf.get('hunt_manager:lock_key') || 'hunt_manager_lock',
  interval: numberConf('hunt_manager:interval', 30000),
  streamBatchSize: numberConf('hunt_manager:stream_batch_size', 5000),
  maxRunsPerTick: numberConf('hunt_manager:max_runs_per_tick', 50),
  maxConcurrentRunsPerConnector: numberConf('hunt_manager:max_concurrent_runs_per_connector', 2),
  dailyRunsPerConnector: numberConf('hunt_manager:daily_runs_per_connector', 200),
  runTimeoutMinutes: numberConf('hunt_manager:run_timeout_minutes', 60),
  previewTimeoutMinutes: numberConf('hunt_manager:preview_timeout_minutes', 5),
  maxRetries: Number.isFinite(Number(conf.get('hunt_manager:max_retries'))) ? Number(conf.get('hunt_manager:max_retries')) : 2,
  retryBackoffMinutes: numberConf('hunt_manager:retry_backoff_minutes', 10),
  standingDebounceMinutes: numberConf('hunt_manager:standing_debounce_minutes', 15),
  minScheduleIntervalMinutes: numberConf('hunt_manager:min_schedule_interval_minutes', 15),
  maxTimeWindowHours: numberConf('hunt_manager:max_time_window_hours', 720),
  maxResultsPerRun: numberConf('hunt_manager:max_results_per_run', 10000),
  evidenceMaxItems: numberConf('hunt_manager:evidence_max_items', 20),
  evidenceMaxValueLength: numberConf('hunt_manager:evidence_max_value_length', 256),
  queueExpiryHours: numberConf('hunt_manager:queue_expiry_hours', 24),
  runRetentionDays: numberConf('hunt_manager:run_retention_days', 365),
  previewRetentionDays: numberConf('hunt_manager:preview_retention_days', 7),
};

export const HUNT_DEFAULT_TIME_WINDOW_HOURS = 24;
export const HUNT_DEFAULT_ESCALATION_THRESHOLD = 10;
export const HUNT_DEFAULT_MAX_RESULTS = 1000;
export const HUNT_MAX_ESCALATION_THRESHOLD = 1000000;
const NATIVE_QUERY_MAX_LENGTH = 65536;
const NATIVE_QUERY_LANGUAGE_MAX_LENGTH = 64;
const NATIVE_QUERY_PIPELINE_MAX_LENGTH = 256;
const EVIDENCE_FIELD_MAX_LENGTH = 256;
const SHA256_HEX = /^[a-f0-9]{64}$/;

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

export interface HuntEvidenceInputLike {
  field?: string | null;
  value_hash?: string | null;
  value_preview?: string | null;
  count?: number | null;
}

/**
 * Evidence never stores raw telemetry: the platform enforces its own caps whatever the connector sent.
 * A hash that is not a sha256 hexadecimal digest is hashed again so that a raw value can never be stored as a hash.
 */
export const sanitizeEvidence = (
  evidence: HuntEvidenceInputLike[] | null | undefined,
  maxItems = HUNT_CONFIG.evidenceMaxItems,
  maxValueLength = HUNT_CONFIG.evidenceMaxValueLength,
): HuntEvidence[] => {
  const byKey = new Map<string, HuntEvidence>();
  (evidence ?? []).forEach((item) => {
    const field = typeof item.field === 'string' ? truncate(item.field.trim(), EVIDENCE_FIELD_MAX_LENGTH) : '';
    const rawHash = typeof item.value_hash === 'string' ? item.value_hash.trim().toLowerCase() : '';
    if (field.length === 0 || rawHash.length === 0) {
      return;
    }
    const valueHash = SHA256_HEX.test(rawHash) ? rawHash : sha256(rawHash);
    const count = Number.isInteger(item.count) && (item.count as number) > 0 ? (item.count as number) : 1;
    const preview = typeof item.value_preview === 'string' && item.value_preview.length > 0
      ? truncate(item.value_preview, maxValueLength)
      : null;
    const key = `${field}:${valueHash}`;
    const existing = byKey.get(key);
    if (existing) {
      existing.count += count;
    } else {
      byKey.set(key, { field, value_hash: valueHash, value_preview: preview, count });
    }
  });
  return Array.from(byKey.values())
    .sort((a, b) => b.count - a.count || a.field.localeCompare(b.field))
    .slice(0, maxItems);
};

export const normalizeNativeQueries = (nativeQueries: unknown): HuntNativeQuery[] => {
  if (nativeQueries === null || nativeQueries === undefined || nativeQueries === '') {
    return [];
  }
  const items = Array.isArray(nativeQueries) ? nativeQueries : [nativeQueries];
  const platforms = new Set<string>();
  return items.map((rawItem, index) => {
    const item = (typeof rawItem === 'string' ? JSON.parse(rawItem) : rawItem) as Partial<HuntNativeQuery>;
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

/**
 * Parses a stored filter group, empty / blank values meaning "no filter".
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
    throw ValidationError('Filters must be a filter group (mode, filters, filterGroups)', field);
  }
  return isFilterGroupNotEmpty(parsed) ? parsed : null;
};

export const clampInteger = (value: unknown, min: number, max: number, fallback: number) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, Math.round(numeric)));
};
