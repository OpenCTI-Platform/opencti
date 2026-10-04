import type { AuthContext, AuthUser } from '../../types/user';
import { ValidationError } from '../../config/errors';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { validateFilterGroupForStixMatch } from '../../utils/filtering/filtering-stix/stix-filtering';
import { validateSigmaRule } from './hunt-sigma';
import { validateHuntSchedule } from './hunt-schedule';
import {
  ENTITY_TYPE_HUNT,
  HUNT_PLATFORM_INTERNET,
  HUNT_SCHEDULE_MANUAL,
  HUNT_STATUS_ACTIVE,
  HUNT_TYPE_INFRASTRUCTURE,
  HUNT_TYPE_TELEMETRY,
  type HuntNativeQuery,
} from './hunt-types';
import { HUNT_CONFIG, HUNT_MAX_ESCALATION_THRESHOLD, isAutonomousHunt, normalizeNativeQueries, parseHuntFilterGroup } from './hunt-utils';

export interface HuntValidationState {
  hunt_type?: string | null;
  hunt_status?: string | null;
  sigma_rule?: string | null;
  native_queries?: unknown;
  hunt_schedule?: string | null;
  hunt_pir_activation?: boolean | null;
  hunt_scope?: string | null;
  trigger_filters?: string | null;
  time_window_hours?: number | null;
  escalation_threshold?: number | null;
  hunt_max_results?: number | null;
}

const validateInteger = (value: number | null | undefined, field: string, min: number, max: number) => {
  if (value === null || value === undefined) {
    return;
  }
  if (!Number.isInteger(Number(value)) || Number(value) < min || Number(value) > max) {
    throw ValidationError(`${field} must be an integer between ${min} and ${max}`, field);
  }
};

/**
 * What a hunt misses to run, null when it has the logic of its type: a Sigma rule or a telemetry native query for a
 * telemetry hunt, an internet native query for an infrastructure hunt.
 */
export const huntLogicError = (
  state: { hunt_type?: string | null; sigma_rule?: string | null; native_queries?: unknown },
): { message: string; field: string } | null => {
  const huntType = state.hunt_type ?? HUNT_TYPE_TELEMETRY;
  const sigmaRule = typeof state.sigma_rule === 'string' ? state.sigma_rule : '';
  const nativeQueries: HuntNativeQuery[] = normalizeNativeQueries(state.native_queries);
  if (huntType === HUNT_TYPE_TELEMETRY) {
    const hasTelemetryQuery = nativeQueries.some((nativeQuery) => nativeQuery.platform !== HUNT_PLATFORM_INTERNET);
    if (sigmaRule.trim().length === 0 && !hasTelemetryQuery) {
      return { message: 'A telemetry hunt needs a Sigma rule or a native query', field: 'sigma_rule' };
    }
  }
  if (huntType === HUNT_TYPE_INFRASTRUCTURE && !nativeQueries.some((nativeQuery) => nativeQuery.platform === HUNT_PLATFORM_INTERNET)) {
    return { message: 'An infrastructure hunt needs a native query for the internet platform', field: 'native_queries' };
  }
  return null;
};

/**
 * Functional validation of a hunt (the merged state of the stored hunt and the requested change).
 * Logic is only required once the hunt is active: drafts and paused hunts can be saved incomplete, and every
 * executed run checks the logic again.
 */
export const validateHuntState = async (context: AuthContext, state: HuntValidationState) => {
  const sigmaRule = typeof state.sigma_rule === 'string' ? state.sigma_rule : '';
  if (sigmaRule.trim().length > 0) {
    const sigmaValidation = validateSigmaRule(sigmaRule);
    if (!sigmaValidation.valid) {
      throw ValidationError(`Invalid Sigma rule: ${sigmaValidation.errors.join('; ')}`, 'sigma_rule');
    }
  }
  if (state.hunt_status === HUNT_STATUS_ACTIVE) {
    const logicError = huntLogicError(state);
    if (logicError) {
      throw ValidationError(`An active hunt cannot run: ${logicError.message}`, logicError.field);
    }
  }
  const schedule = state.hunt_schedule ?? HUNT_SCHEDULE_MANUAL;
  const scheduleValidation = validateHuntSchedule(schedule, HUNT_CONFIG.minScheduleIntervalMinutes);
  if (!scheduleValidation.valid) {
    throw ValidationError(scheduleValidation.error ?? 'Invalid schedule', 'hunt_schedule');
  }
  validateInteger(state.time_window_hours, 'time_window_hours', 1, HUNT_CONFIG.maxTimeWindowHours);
  validateInteger(state.escalation_threshold, 'escalation_threshold', 1, HUNT_MAX_ESCALATION_THRESHOLD);
  validateInteger(state.hunt_max_results, 'hunt_max_results', 1, HUNT_CONFIG.maxResultsPerRun);
  parseHuntFilterGroup(state.hunt_scope, 'hunt_scope');
  const triggerFilters = parseHuntFilterGroup(state.trigger_filters, 'trigger_filters');
  if (triggerFilters) {
    // Trigger filters are evaluated on stream events, only the keys supported by the stix matching are accepted
    validateFilterGroupForStixMatch(triggerFilters);
  }
  // Autonomous execution (schedule, standing, PIR activation) is an Enterprise Edition capability
  if (state.hunt_status === HUNT_STATUS_ACTIVE && isAutonomousHunt({ hunt_schedule: schedule, hunt_pir_activation: state.hunt_pir_activation })) {
    await checkEnterpriseEdition(context);
  }
};

const singleValue = (key: string, value: unknown) => {
  const attribute = schemaAttributesDefinition.getAttribute(ENTITY_TYPE_HUNT, key);
  if (!attribute || attribute.multiple || !Array.isArray(value)) {
    return value;
  }
  return value.length > 0 ? value[0] : null;
};

export const validateHuntCreation = async (context: AuthContext, _user: AuthUser, instance: Record<string, unknown>) => {
  await validateHuntState(context, instance as HuntValidationState);
  return true;
};

export const validateHuntUpdate = async (
  context: AuthContext,
  _user: AuthUser,
  instance: Record<string, unknown>,
  initial: Record<string, unknown> | undefined,
) => {
  const changes = Object.fromEntries(Object.entries(instance).map(([key, value]) => [key, singleValue(key, value)]));
  await validateHuntState(context, { ...(initial ?? {}), ...changes } as HuntValidationState);
  return true;
};
