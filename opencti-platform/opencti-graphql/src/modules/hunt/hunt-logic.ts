import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import { fullEntitiesList, topEntitiesList } from '../../database/middleware-loader';
import { FilterMode, OrderingMode } from '../../generated/graphql';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../schema/stixDomainObject';
import { HUNT_TYPE_INDICATORS, type BasicStoreEntityHunt } from './hunt-types';
import { normalizeNativeQueries, sha256, truncate } from './hunt-utils';
import { validateSigmaRule } from './hunt-sigma';
import { HUNT_MESSAGES, huntMessage, type HuntMessage } from './hunt-messages';
import {
  type BasicStoreEntityHuntRun,
  ENTITY_TYPE_HUNT_RUN,
  HUNT_RUN_ACTIVE_STATUSES,
  HUNT_RUN_MODE_PREVIEW,
  HUNT_RUN_STATUS_COMPLETED,
  HUNT_RUN_STATUS_FAILED,
} from './huntRun/huntRun-types';

/**
 * The logic a connector translates, as a fingerprint stored on every run: the runs of the same fingerprint tell whether
 * the current logic of a hunt translates, so an edit of the rule or of the native queries starts from an unknown state.
 */
export const huntLogicFingerprint = (hunt: Pick<BasicStoreEntityHunt, 'hunt_type' | 'sigma_rule' | 'native_queries'>) => {
  return sha256(JSON.stringify({
    type: hunt.hunt_type ?? null,
    sigma_rule: hunt.sigma_rule?.trim() ?? '',
    native_queries: normalizeNativeQueries(hunt.native_queries).map((query) => [query.platform, query.language, query.pipeline ?? null, query.query]),
  }));
};

// When a connector does not say whether a failure is retryable, the failures the connectors SDK raises the same way at
// every attempt: the translation of the hunt logic, a run message the connector refuses, a field or a log source the
// pipeline of the platform cannot map
const DETERMINISTIC_FAILURE_PREFIXES = ['HuntTranslationError', 'HuntRequestError'];
const DETERMINISTIC_FAILURE_PATTERNS = [/\binvalid (?:\w+ )?field\b/i, /\bunsupported log ?source\b/i, /\blog ?source\b.*\b(?:not supported|unsupported|cannot be mapped)\b/i];
const TRANSLATION_FAILURE_PREFIX = 'HuntTranslationError';
const CHECKLIST_ERROR_MAX_LENGTH = 300;

/**
 * Whether a failure reported by a connector fails again in the same way at every attempt. The connector decides when
 * it says so (`retryable`); otherwise the error it sends is read. A timeout is never deterministic.
 */
export const isDeterministicHuntFailure = (status: string, error: string | null | undefined, retryable: boolean | null | undefined) => {
  if (status !== HUNT_RUN_STATUS_FAILED) {
    return false;
  }
  if (typeof retryable === 'boolean') {
    return !retryable;
  }
  const message = (error ?? '').trim();
  return DETERMINISTIC_FAILURE_PREFIXES.some((prefix) => message.startsWith(prefix))
    || DETERMINISTIC_FAILURE_PATTERNS.some((pattern) => pattern.test(message));
};

/** A run that failed for good: never retried automatically, given no automatic verdict. */
export const isTerminalHuntRunFailure = (run: Pick<BasicStoreEntityHuntRun, 'hunt_run_status' | 'failure_retryable'>) => {
  return run.hunt_run_status === HUNT_RUN_STATUS_FAILED && run.failure_retryable === false;
};

const isTranslationFailure = (error: string | null | undefined) => {
  const message = (error ?? '').trim();
  return message.startsWith(TRANSLATION_FAILURE_PREFIX) || DETERMINISTIC_FAILURE_PATTERNS.some((pattern) => pattern.test(message));
};

/** Why a run failed for good, in the words of the user interface; null for any other run. */
export const huntRunFailureReason = (run: Pick<BasicStoreEntityHuntRun, 'hunt_run_status' | 'failure_retryable' | 'error_message' | 'connector_name'>): HuntMessage | null => {
  if (!isTerminalHuntRunFailure(run)) {
    return null;
  }
  const connector = run.connector_name ?? 'The hunt connector';
  return huntMessage(isTranslationFailure(run.error_message) ? HUNT_MESSAGES.runFailedTranslation : HUNT_MESSAGES.runFailedRejected, { connector });
};

export type HuntTranslationState = 'translated' | 'failed' | 'checking';

export interface HuntTranslation {
  state: HuntTranslationState;
  run: BasicStoreEntityHuntRun;
}

const TRANSLATION_RUNS_READ = 20;

/**
 * What the runs of the current logic of a hunt tell of its translation, the most recent first: translated by a completed
 * run (a preview or an execution), failed for good, or being checked by a translation preview. Retryable failures and
 * executions still running tell nothing. Null when no run of this logic says, or for logic no connector translates
 * (indicator lookups). `securityPlatformIds` narrows to the runs of these platforms, each translating to its language.
 */
export const findHuntTranslation = async (
  context: AuthContext,
  user: AuthUser,
  hunt: BasicStoreEntityHunt,
  securityPlatformIds: string[] = [],
): Promise<HuntTranslation | null> => {
  if (!hunt.internal_id || hunt.hunt_type === HUNT_TYPE_INDICATORS) {
    return null;
  }
  const runs = await topEntitiesList<BasicStoreEntityHuntRun>(context, user, [ENTITY_TYPE_HUNT_RUN], {
    first: TRANSLATION_RUNS_READ,
    orderBy: 'created_at',
    orderMode: OrderingMode.Desc,
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['hunt_id'], values: [hunt.internal_id] },
        { key: ['hunt_logic_fingerprint'], values: [huntLogicFingerprint(hunt)] },
        ...(securityPlatformIds.length > 0 ? [{ key: ['security_platform_id'], values: securityPlatformIds }] : []),
      ],
      filterGroups: [],
    },
    noFiltersChecking: true,
  });
  for (let index = 0; index < runs.length; index += 1) {
    const run = runs[index];
    if (run.hunt_run_status === HUNT_RUN_STATUS_COMPLETED) {
      return { state: 'translated', run };
    }
    if (isTerminalHuntRunFailure(run)) {
      return { state: 'failed', run };
    }
    if (run.hunt_run_mode === HUNT_RUN_MODE_PREVIEW && HUNT_RUN_ACTIVE_STATUSES.includes(run.hunt_run_status)) {
      return { state: 'checking', run };
    }
  }
  return null;
};

/** The sentence of a translation state: the checklist item, and the refusal of a run whose logic fails for good. */
export const huntTranslationMessage = (translation: HuntTranslation): { template: string; values: Record<string, string> } => {
  const connector = translation.run.connector_name ?? 'The hunt connector';
  if (translation.state === 'translated') {
    return { template: HUNT_MESSAGES.translationReady, values: { connector } };
  }
  if (translation.state === 'checking') {
    return { template: HUNT_MESSAGES.translationChecking, values: { connector } };
  }
  const error = truncate(translation.run.error_message ?? 'Unknown error', CHECKLIST_ERROR_MAX_LENGTH);
  return { template: HUNT_MESSAGES.translationFailed, values: { connector, error } };
};

/**
 * The ATT&CK techniques (T1059.001) that match no attack pattern of the knowledge base the user can read: tagged in a
 * Sigma rule, they link the hunt to nothing and are reported rather than dropped silently.
 */
export const findUnresolvedAttackTechniques = async (context: AuthContext, user: AuthUser, attackIds: string[]): Promise<string[]> => {
  const tagged = Array.from(new Set(attackIds.map((attackId) => attackId.toUpperCase())));
  if (tagged.length === 0) {
    return [];
  }
  const known = await fullEntitiesList<BasicStoreEntity & { x_mitre_id?: string }>(context, user, [ENTITY_TYPE_ATTACK_PATTERN], {
    filters: { mode: FilterMode.And, filters: [{ key: ['x_mitre_id'], values: tagged }], filterGroups: [] },
  });
  const knownIds = new Set(known.map((technique) => technique.x_mitre_id?.toUpperCase()));
  return tagged.filter((attackId) => !knownIds.has(attackId));
};

/** The techniques the Sigma rule of a hunt tags that the knowledge base lacks. */
export const findUnresolvedHuntTechniques = async (context: AuthContext, user: AuthUser, sigmaRule: string | null | undefined): Promise<string[]> => {
  if (!sigmaRule?.trim()) {
    return [];
  }
  return findUnresolvedAttackTechniques(context, user, validateSigmaRule(sigmaRule).attack_techniques);
};
