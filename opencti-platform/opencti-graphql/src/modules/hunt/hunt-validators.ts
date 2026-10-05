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
  HUNT_TYPE_INDICATORS,
  HUNT_TYPE_INFRASTRUCTURE,
  HUNT_TYPE_TELEMETRY,
  INPUT_HUNT_SOURCES,
  type HuntNativeQuery,
  RELATION_HUNT_SOURCES,
} from './hunt-types';
import { HUNT_CONFIG, HUNT_MAX_ESCALATION_THRESHOLD, isAutonomousHunt, normalizeNativeQueries, parseHuntFilterGroup } from './hunt-utils';
import { HUNT_MESSAGES, renderHuntMessage } from './hunt-messages';
import { hasHuntIocLogic, normalizeHuntIocValues } from './hunt-iocs';

export interface HuntValidationState {
  hunt_type?: string | null;
  hunt_status?: string | null;
  sigma_rule?: string | null;
  native_queries?: unknown;
  hunt_ioc_filters?: string | null;
  hunt_ioc_values?: unknown;
  [RELATION_HUNT_SOURCES]?: unknown;
  [INPUT_HUNT_SOURCES]?: unknown;
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

/** The errors of a Sigma rule, none without a rule. */
export const sigmaRuleErrors = (sigmaRule: string | null | undefined): string[] => {
  if (typeof sigmaRule !== 'string' || sigmaRule.trim().length === 0) {
    return [];
  }
  const sigmaValidation = validateSigmaRule(sigmaRule);
  return sigmaValidation.valid ? [] : sigmaValidation.errors;
};

/** The error of a Sigma rule, as the platform words it. */
export const sigmaRuleError = (sigmaRule: string | null | undefined): string | null => {
  const errors = sigmaRuleErrors(sigmaRule);
  return errors.length > 0 ? renderHuntMessage(HUNT_MESSAGES.sigmaInvalid, { errors: errors.join('; ') }) : null;
};

/**
 * What a hunt misses to run, null when it has the logic of its type: a Sigma rule or a telemetry native query for a
 * telemetry hunt, something to look for for an indicator hunt, an internet native query for an infrastructure hunt.
 */
export const huntLogicError = (state: Omit<HuntValidationState, 'hunt_status'>): { message: string; field: string } | null => {
  const huntType = state.hunt_type ?? HUNT_TYPE_TELEMETRY;
  const sigmaRule = typeof state.sigma_rule === 'string' ? state.sigma_rule : '';
  const nativeQueries: HuntNativeQuery[] = normalizeNativeQueries(state.native_queries);
  if (huntType === HUNT_TYPE_TELEMETRY) {
    const hasTelemetryQuery = nativeQueries.some((nativeQuery) => nativeQuery.platform !== HUNT_PLATFORM_INTERNET);
    if (sigmaRule.trim().length === 0 && !hasTelemetryQuery) {
      return { message: HUNT_MESSAGES.logicTelemetryMissing, field: 'sigma_rule' };
    }
  }
  if (huntType === HUNT_TYPE_INDICATORS && !hasHuntIocLogic(state)) {
    return { message: HUNT_MESSAGES.logicIndicatorsMissing, field: 'hunt_ioc_values' };
  }
  if (huntType === HUNT_TYPE_INFRASTRUCTURE && !nativeQueries.some((nativeQuery) => nativeQuery.platform === HUNT_PLATFORM_INTERNET)) {
    return { message: HUNT_MESSAGES.logicInfrastructureMissing, field: 'native_queries' };
  }
  return null;
};

/**
 * Functional validation of a hunt (the merged state of the stored hunt and the requested change).
 * Logic is only required once the hunt is active: drafts and paused hunts can be saved incomplete, and every
 * executed run checks the logic again.
 */
export const validateHuntState = async (context: AuthContext, state: HuntValidationState) => {
  const sigmaError = sigmaRuleError(state.sigma_rule);
  if (sigmaError) {
    throw ValidationError(sigmaError, 'sigma_rule');
  }
  if (state.hunt_ioc_values !== undefined) {
    normalizeHuntIocValues(state.hunt_ioc_values);
  }
  parseHuntFilterGroup(state.hunt_ioc_filters, 'hunt_ioc_filters');
  if (state.hunt_status === HUNT_STATUS_ACTIVE) {
    const logicError = huntLogicError(state);
    if (logicError) {
      throw ValidationError(`An active hunt cannot run: ${logicError.message}`, logicError.field);
    }
  }
  const schedule = state.hunt_schedule ?? HUNT_SCHEDULE_MANUAL;
  const scheduleValidation = validateHuntSchedule(schedule, HUNT_CONFIG.minScheduleIntervalMinutes);
  if (!scheduleValidation.valid) {
    throw ValidationError(renderHuntMessage(HUNT_MESSAGES.scheduleInvalid, { error: scheduleValidation.error ?? schedule }), 'hunt_schedule');
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

/** A stored hunt with the values of an edit, as the edit would store them. */
export const mergeHuntEdits = <T extends object>(hunt: T, editInputs: { key: string; value: unknown }[]): T => {
  const changes = Object.fromEntries(editInputs.map((editInput) => [editInput.key, singleValue(editInput.key, editInput.value)]));
  return { ...hunt, ...changes };
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
