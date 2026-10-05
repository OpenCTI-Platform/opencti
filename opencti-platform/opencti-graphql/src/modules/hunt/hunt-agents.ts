import Ajv, { type JSONSchemaType, type SchemaObject } from 'ajv';
import type { AuthContext } from '../../types/user';
import { logApp } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { AUTOMATION_MANAGER_USER } from '../../utils/access';
import xtmOneClient, { type XtmCallFailure } from '../xtm/one/xtm-one-client';
import { type AgentJwtUser, buildPlaybookAutomationContext, callXtmAgent, isXtmOneConfigured } from '../playbook/components/ai-agent-shared';
import { type SigmaValidation, validateSigmaRule } from './hunt-sigma';
import { HUNT_PLATFORMS, HUNT_TYPE_INFRASTRUCTURE, HUNT_TYPE_TELEMETRY, type HuntNativeQuery } from './hunt-types';
import { huntLogicError } from './hunt-validators';
import { clampInteger, HUNT_CONFIG, HUNT_DEFAULT_ESCALATION_THRESHOLD, HUNT_DEFAULT_TIME_WINDOW_HOURS, HUNT_MAX_ESCALATION_THRESHOLD, normalizeNativeQueries } from './hunt-utils';
import { HUNT_VERDICT_BENIGN, HUNT_VERDICT_INCONCLUSIVE, HUNT_VERDICT_TRUE_POSITIVE } from './huntRun/huntRun-types';

export const HUNT_PLANNER_INTENT = 'cti.hunt_hypothesis';
export const HUNT_SIGMA_GENERATION_INTENT = 'cti.hunt_sigma_generation';
export const HUNT_TRIAGE_INTENT = 'cti.hunt_triage';

// region failures
/**
 * Why a hunt agent call failed, carried as `failure` in the error data: the forms name the cause and the next step
 * (open the settings, retry, ask an administrator) instead of a bare error.
 */
export const HUNT_AGENT_FAILURE = {
  notConfigured: 'XTM_ONE_NOT_CONFIGURED',
  unreachable: 'XTM_ONE_UNREACHABLE',
  timeout: 'XTM_ONE_TIMEOUT',
  refused: 'XTM_ONE_REFUSED',
  quota: 'XTM_ONE_QUOTA',
  noModel: 'XTM_ONE_NO_MODEL',
  noAgent: 'XTM_ONE_NO_AGENT',
  invalidAnswer: 'XTM_ONE_INVALID_ANSWER',
  incomplete: 'XTM_ONE_INCOMPLETE',
} as const;
export type HuntAgentFailure = typeof HUNT_AGENT_FAILURE[keyof typeof HUNT_AGENT_FAILURE];

export const huntAgentError = (failure: HuntAgentFailure, message: string, data: Record<string, unknown> = {}) => FunctionalError(message, { ...data, failure });

const TIMEOUT_CODES = ['ECONNABORTED', 'ETIMEDOUT', 'ESOCKETTIMEDOUT'];
// XTM One answers a run it could not complete (no model, provider error) with a sentence instead of an HTTP error
const XTM_ONE_RUN_ERROR = /no llm provider|settings > ai models|encountered an error processing your request/i;

/** The cause of a failed XTM One call, from its HTTP status, its network error code and its detail. */
export const classifyXtmCallFailure = (failure: XtmCallFailure): HuntAgentFailure => {
  if (failure.status === 429) {
    return HUNT_AGENT_FAILURE.quota;
  }
  if (failure.status === 401 || failure.status === 403) {
    return HUNT_AGENT_FAILURE.refused;
  }
  if (XTM_ONE_RUN_ERROR.test(failure.detail ?? '')) {
    return HUNT_AGENT_FAILURE.noModel;
  }
  if ((failure.code !== null && TIMEOUT_CODES.includes(failure.code)) || /timeout/i.test(failure.detail ?? '')) {
    return HUNT_AGENT_FAILURE.timeout;
  }
  return HUNT_AGENT_FAILURE.unreachable;
};

const FAILURE_MESSAGES: Record<HuntAgentFailure, string> = {
  XTM_ONE_NOT_CONFIGURED: 'XTM One is not configured on this platform',
  XTM_ONE_UNREACHABLE: 'XTM One cannot be reached: check that it runs and that the platform can reach its address',
  XTM_ONE_TIMEOUT: 'XTM One did not answer in time',
  XTM_ONE_REFUSED: 'XTM One refused the credentials of the platform',
  XTM_ONE_QUOTA: 'The AI quota of XTM One is used up',
  XTM_ONE_NO_MODEL: 'XTM One could not run the agent, most often because no AI model is configured in XTM One',
  XTM_ONE_NO_AGENT: 'No XTM One agent writes hunts',
  XTM_ONE_INVALID_ANSWER: 'The answer of the XTM One agent could not be used',
  XTM_ONE_INCOMPLETE: 'The XTM One agent answered without what was asked',
};

const xtmCallError = (failure: XtmCallFailure, data: Record<string, unknown>) => {
  const cause = classifyXtmCallFailure(failure);
  // A network error detail ("connect ECONNREFUSED 10.0.0.1:8000") tells an analyst nothing more than the cause
  const withDetail = failure.detail && failure.status !== null;
  return huntAgentError(cause, withDetail ? `${FAILURE_MESSAGES[cause]}: ${failure.detail}` : FAILURE_MESSAGES[cause], { ...data, status: failure.status, code: failure.code });
};
// endregion

const ATTACK_TECHNIQUE_ID = /^T\d{4}(?:\.\d{3})?$/;
// The planner writes detection logic; an indicator hunt is built from the indicators themselves, never planned
const PLANNABLE_HUNT_TYPES = [HUNT_TYPE_TELEMETRY, HUNT_TYPE_INFRASTRUCTURE];
const ajv = new Ajv({ allErrors: true, coerceTypes: false });

// region planner
export interface HuntPlanSpec {
  name: string;
  description: string;
  hypothesis: string;
  hunt_type: string;
  sigma_rule: string;
  native_queries: HuntNativeQuery[];
  expected_observables: string[];
  benign_patterns: string[];
  escalation_threshold: number;
  time_window_hours: number;
  technique_ids: string[];
  target_ids: string[];
  rationale: string;
}

interface RawHuntPlanSpec {
  name: string;
  description?: string;
  hypothesis: string;
  hunt_type: string;
  sigma_rule?: string;
  native_queries?: { platform: string; language: string; query: string; pipeline?: string | null }[];
  expected_observables?: string[];
  benign_patterns?: string[];
  escalation_threshold?: number;
  time_window_hours?: number;
  technique_ids?: string[];
  target_ids?: string[];
  rationale?: string;
}

const HUNT_PLAN_SCHEMA: JSONSchemaType<RawHuntPlanSpec> = {
  type: 'object',
  properties: {
    name: { type: 'string', minLength: 3, maxLength: 128 },
    description: { type: 'string', nullable: true, maxLength: 10000 },
    hypothesis: { type: 'string', minLength: 3, maxLength: 5000 },
    hunt_type: { type: 'string', enum: PLANNABLE_HUNT_TYPES },
    sigma_rule: { type: 'string', nullable: true, maxLength: 65536 },
    native_queries: {
      type: 'array',
      nullable: true,
      maxItems: 20,
      items: {
        type: 'object',
        properties: {
          platform: { type: 'string' },
          language: { type: 'string' },
          query: { type: 'string' },
          pipeline: { type: 'string', nullable: true },
        },
        required: ['platform', 'language', 'query'],
      },
    },
    expected_observables: { type: 'array', nullable: true, maxItems: 50, items: { type: 'string', maxLength: 128 } },
    benign_patterns: { type: 'array', nullable: true, maxItems: 50, items: { type: 'string', maxLength: 2000 } },
    escalation_threshold: { type: 'integer', nullable: true },
    time_window_hours: { type: 'integer', nullable: true },
    technique_ids: { type: 'array', nullable: true, maxItems: 100, items: { type: 'string' } },
    target_ids: { type: 'array', nullable: true, maxItems: 100, items: { type: 'string' } },
    rationale: { type: 'string', nullable: true, maxLength: 10000 },
  },
  required: ['name', 'hypothesis', 'hunt_type'],
  additionalProperties: true,
};
const validatePlanSchema = ajv.compile(HUNT_PLAN_SCHEMA);
// endregion

// region triage
export interface HuntTriageResult {
  verdict: string;
  // Null when the triage cannot weigh the evidence: shown as not assessed, never replaced by a number
  confidence: number | null;
  rationale: string;
  incident: { name: string; description: string; severity: string } | null;
}

interface RawHuntTriageResult {
  verdict: string;
  confidence: number | null;
  rationale: string;
  incident?: { name: string; description: string; severity: string } | null;
}

// JSONSchemaType cannot type a property that is both required and nullable, hence the plain SchemaObject
const HUNT_TRIAGE_SCHEMA: SchemaObject = {
  type: 'object',
  properties: {
    verdict: { type: 'string', enum: [HUNT_VERDICT_TRUE_POSITIVE, HUNT_VERDICT_BENIGN, HUNT_VERDICT_INCONCLUSIVE] },
    confidence: { type: 'integer', minimum: 0, maximum: 100, nullable: true },
    rationale: { type: 'string', minLength: 1, maxLength: 10000 },
    incident: {
      type: 'object',
      nullable: true,
      properties: {
        name: { type: 'string', minLength: 1, maxLength: 250 },
        description: { type: 'string', maxLength: 10000 },
        severity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] },
      },
      required: ['name', 'description', 'severity'],
    },
  },
  required: ['verdict', 'confidence', 'rationale'],
  additionalProperties: true,
};
const validateTriageSchema = ajv.compile<RawHuntTriageResult>(HUNT_TRIAGE_SCHEMA);
// endregion

/**
 * Agents answer with a JSON object, sometimes wrapped in a markdown fence: the outermost object is extracted.
 */
export const extractJsonObject = (content: string | null): unknown => {
  if (!content) {
    return null;
  }
  const start = content.indexOf('{');
  const end = content.lastIndexOf('}');
  if (start < 0 || end <= start) {
    return null;
  }
  try {
    return JSON.parse(content.substring(start, end + 1));
  } catch {
    return null;
  }
};

const AGENT_REFUSAL_MAX_ERRORS = 10;
const AGENT_REFUSAL_MAX_ERROR_LENGTH = 300;

/**
 * Reasons of an agent whose own contract check refused its answer: XTM One then answers `{"valid": false, "errors":
 * [...]}` instead of the result. Null for any other answer.
 */
export const huntAgentRefusalErrors = (answer: unknown): string[] | null => {
  if (!answer || typeof answer !== 'object' || Array.isArray(answer)) {
    return null;
  }
  const { valid, errors } = answer as { valid?: unknown; errors?: unknown };
  if (valid !== false || !Array.isArray(errors)) {
    return null;
  }
  return errors
    .filter((error): error is string => typeof error === 'string' && error.trim().length > 0)
    .slice(0, AGENT_REFUSAL_MAX_ERRORS)
    .map((error) => error.trim().substring(0, AGENT_REFUSAL_MAX_ERROR_LENGTH));
};

/**
 * Deterministic validation of a planner answer, the platform never trusts the model output:
 * strict schema, Sigma structure, bounded numbers, ATT&CK ids format and targets grounded on the input.
 */
export const validateHuntPlanSpec = (raw: unknown, allowedTargetIds: string[]): HuntPlanSpec => {
  if (!validatePlanSchema(raw)) {
    throw huntAgentError(HUNT_AGENT_FAILURE.invalidAnswer, 'The hunt planner answer does not match the hunt spec schema', { errors: ajv.errorsText(validatePlanSchema.errors) });
  }
  const spec = raw as RawHuntPlanSpec;
  const sigmaRule = (spec.sigma_rule ?? '').trim();
  let nativeQueries: HuntNativeQuery[];
  try {
    nativeQueries = normalizeNativeQueries(spec.native_queries ?? []);
  } catch (error) {
    throw huntAgentError(HUNT_AGENT_FAILURE.invalidAnswer, `The hunt planner answer contains an invalid native query: ${(error as Error).message}`);
  }
  // A plan is proposed only if it can be activated: the logic rules of an active hunt apply
  const logicError = huntLogicError({ hunt_type: spec.hunt_type, sigma_rule: sigmaRule, native_queries: nativeQueries });
  if (logicError) {
    throw huntAgentError(HUNT_AGENT_FAILURE.invalidAnswer, `The hunt planner answer cannot run: ${logicError.message}`, { field: logicError.field });
  }
  if (sigmaRule.length > 0) {
    const sigma = validateSigmaRule(sigmaRule);
    if (!sigma.valid) {
      throw huntAgentError(HUNT_AGENT_FAILURE.invalidAnswer, 'The hunt planner answer contains an invalid Sigma rule', { errors: sigma.errors });
    }
  }
  const allowedTargets = new Set(allowedTargetIds);
  return {
    name: spec.name.trim(),
    description: (spec.description ?? '').trim(),
    hypothesis: spec.hypothesis.trim(),
    hunt_type: spec.hunt_type,
    sigma_rule: sigmaRule,
    native_queries: nativeQueries,
    expected_observables: Array.from(new Set((spec.expected_observables ?? []).map((item) => item.trim()).filter((item) => item.length > 0))),
    benign_patterns: Array.from(new Set((spec.benign_patterns ?? []).map((item) => item.trim()).filter((item) => item.length > 0))),
    escalation_threshold: clampInteger(spec.escalation_threshold, 1, HUNT_MAX_ESCALATION_THRESHOLD, HUNT_DEFAULT_ESCALATION_THRESHOLD),
    time_window_hours: clampInteger(spec.time_window_hours, 1, HUNT_CONFIG.maxTimeWindowHours, HUNT_DEFAULT_TIME_WINDOW_HOURS),
    // ATT&CK ids are normalized and kept only when well-formed
    technique_ids: Array.from(new Set((spec.technique_ids ?? []).map((id) => id.trim().toUpperCase()).filter((id) => ATTACK_TECHNIQUE_ID.test(id)))),
    // Tool-result grounding: an agent can only target the threats it was given
    target_ids: Array.from(new Set((spec.target_ids ?? []).filter((id) => allowedTargets.has(id)))),
    rationale: (spec.rationale ?? '').trim(),
  };
};

// region assistance of a hunt being written
/** The fields of a hunt the planner can write; asking for none of them asks for the whole plan. */
export const HUNT_ASSIST_FIELDS = ['name', 'hypothesis', 'description', 'sigma_rule', 'native_queries', 'expected_observables', 'benign_patterns', 'techniques'] as const;
export type HuntAssistFieldName = typeof HUNT_ASSIST_FIELDS[number];

const HUNT_ASSIST_LIMITS = { prompt: 2000, name: 512, hypothesis: 5000, description: 10000, sigma_rule: 65536, list: 50, listItem: 2000 };
const NATIVE_QUERY_LANGUAGE = /^[a-z0-9_-]{1,64}$/i;

/** The hunt as the analyst is writing it, merged over the saved hunt when there is one. */
export interface HuntAssistDraft {
  name: string;
  hunt_type: string;
  hypothesis: string;
  description: string;
  sigma_rule: string;
  native_queries: HuntNativeQuery[];
  expected_observables: string[];
  benign_patterns: string[];
  /** What the analyst wants to hunt, in their words, when the form says little */
  prompt: string;
}

export interface HuntAssistTarget {
  fields: HuntAssistFieldName[];
  /** The native query asked for, by its platform and query language */
  native_query: { platform: string; language: string } | null;
}

export interface HuntAssistProposal {
  fields: HuntAssistFieldName[];
  name: string;
  hypothesis: string;
  description: string;
  sigma_rule: string;
  sigma_validation: SigmaValidation | null;
  native_queries: HuntNativeQuery[];
  expected_observables: string[];
  benign_patterns: string[];
  technique_ids: string[];
  rationale: string;
}

const boundedText = (value: string, limit: number, label: string) => {
  if (value.length > limit) {
    throw FunctionalError(`The ${label} is limited to ${limit} characters`, { field: label });
  }
  return value;
};

const boundedList = (values: string[], label: string) => {
  const items = Array.from(new Set(values.map((value) => value.trim()).filter((value) => value.length > 0)));
  if (items.length > HUNT_ASSIST_LIMITS.list || items.some((item) => item.length > HUNT_ASSIST_LIMITS.listItem)) {
    throw FunctionalError(`The ${label} are limited to ${HUNT_ASSIST_LIMITS.list} items of ${HUNT_ASSIST_LIMITS.listItem} characters`, { field: label });
  }
  return items;
};

/** The complete native queries of a form, one per platform: rows still being written are left out, never refused. */
export const draftNativeQueries = (rows: { platform?: string | null; language?: string | null; query?: string | null; pipeline?: string | null }[]): HuntNativeQuery[] => {
  const byPlatform = new Map<string, HuntNativeQuery>();
  rows.forEach((row) => {
    const platform = (row.platform ?? '').trim();
    const language = (row.language ?? '').trim();
    const query = (row.query ?? '').trim();
    if (HUNT_PLATFORMS.includes(platform) && NATIVE_QUERY_LANGUAGE.test(language) && query.length > 0 && !byPlatform.has(platform)) {
      byPlatform.set(platform, { platform, language, query, pipeline: (row.pipeline ?? '').trim() || null });
    }
  });
  return normalizeNativeQueries(Array.from(byPlatform.values()));
};

/** Checks the bounds of a draft: the agent receives it verbatim. */
export const validateHuntAssistDraft = (draft: HuntAssistDraft): HuntAssistDraft => ({
  ...draft,
  prompt: boundedText(draft.prompt, HUNT_ASSIST_LIMITS.prompt, 'description of what to hunt'),
  name: boundedText(draft.name, HUNT_ASSIST_LIMITS.name, 'name'),
  hypothesis: boundedText(draft.hypothesis, HUNT_ASSIST_LIMITS.hypothesis, 'hypothesis'),
  description: boundedText(draft.description, HUNT_ASSIST_LIMITS.description, 'description'),
  sigma_rule: boundedText(draft.sigma_rule, HUNT_ASSIST_LIMITS.sigma_rule, 'Sigma rule'),
  expected_observables: boundedList(draft.expected_observables, 'expected observables'),
  benign_patterns: boundedList(draft.benign_patterns, 'benign patterns'),
});

/** The fields asked, deduplicated, and the native query asked for, checked against the platforms hunts run on. */
export const resolveHuntAssistTarget = (fields: string[], nativeQuery: { platform?: string | null; language?: string | null }): HuntAssistTarget => {
  const asked = Array.from(new Set(fields)) as HuntAssistFieldName[];
  const unknown = asked.filter((field) => !HUNT_ASSIST_FIELDS.includes(field));
  if (unknown.length > 0) {
    throw FunctionalError(`Unknown hunt fields: ${unknown.join(', ')}`, { fields: unknown });
  }
  if (!asked.includes('native_queries')) {
    return { fields: asked, native_query: null };
  }
  const platform = (nativeQuery.platform ?? '').trim();
  const language = (nativeQuery.language ?? '').trim().toLowerCase();
  if (!HUNT_PLATFORMS.includes(platform) || !NATIVE_QUERY_LANGUAGE.test(language)) {
    throw FunctionalError('A native query is written for a platform and a query language: choose them first', { platform, language });
  }
  return { fields: asked, native_query: { platform, language } };
};

/** Whether the draft gives the agent anything to start from: a name, a few words, a field or the knowledge of the hunt. */
export const huntAssistHasSubject = (draft: HuntAssistDraft, entityCount: number) => entityCount > 0
  || [draft.name, draft.prompt, draft.hypothesis, draft.description, draft.sigma_rule].some((value) => value.length > 0)
  || draft.native_queries.length > 0;

type RequestPlatform = { platform?: string | null; languages?: string[] } & Record<string, unknown>;

const withRequestedPlatform = (platforms: RequestPlatform[], { platform, language }: { platform: string; language: string }): RequestPlatform[] => {
  // The planner may only write native queries for the platforms and languages of its request
  if (platforms.some((entry) => entry.platform === platform)) {
    return platforms.map((entry) => (entry.platform === platform ? { ...entry, languages: Array.from(new Set([...(entry.languages ?? []), language])) } : entry));
  }
  return [...platforms, { id: null, name: platform, security_platform_type: null, platform, languages: [language] }];
};

/**
 * The planner request for the hunt being written: the knowledge of the hunt and its platforms, plus the draft itself,
 * the fields asked and the analyst's own words. Asking for the Sigma rule alone is a cti.hunt_sigma_generation request
 * (a rule being edited is refined rather than replaced); anything else is a cti.hunt_hypothesis request.
 */
export const buildHuntAssistRequest = <T extends { security_platforms: RequestPlatform[] }>(plannerRequest: T, draft: HuntAssistDraft, target: HuntAssistTarget) => {
  const sigmaOnly = target.fields.length === 1 && target.fields[0] === 'sigma_rule';
  let huntType: { hunt_type?: string } = {};
  if (sigmaOnly) {
    huntType = { hunt_type: HUNT_TYPE_TELEMETRY };
  } else if (PLANNABLE_HUNT_TYPES.includes(draft.hunt_type)) {
    huntType = { hunt_type: draft.hunt_type };
  }
  return {
    ...plannerRequest,
    task: sigmaOnly ? 'hunt_sigma_generation' : 'hunt_hypothesis',
    ...huntType,
    security_platforms: target.native_query ? withRequestedPlatform(plannerRequest.security_platforms, target.native_query) : plannerRequest.security_platforms,
    hunt: {
      name: draft.name,
      hunt_type: draft.hunt_type,
      hypothesis: draft.hypothesis,
      description: draft.description,
      current_sigma_rule: draft.sigma_rule.length > 0 ? draft.sigma_rule : null,
      native_queries: draft.native_queries,
      expected_observables: draft.expected_observables,
      benign_patterns: draft.benign_patterns,
      analyst_request: draft.prompt.length > 0 ? draft.prompt : null,
      // Empty: the whole plan
      requested_fields: target.fields,
      requested_native_query: target.native_query,
    },
  };
};

const proposalHas = (spec: HuntPlanSpec, field: HuntAssistFieldName, nativeQueries: HuntNativeQuery[]) => {
  switch (field) {
    case 'name':
    case 'hypothesis':
    case 'description':
      return spec[field].length > 0;
    case 'sigma_rule':
      return spec.hunt_type === HUNT_TYPE_TELEMETRY && spec.sigma_rule.length > 0;
    case 'native_queries':
      return nativeQueries.length > 0;
    case 'techniques':
      return spec.technique_ids.length > 0;
    default:
      return spec[field].length > 0;
  }
};

/**
 * The proposal of a checked planner answer: every asked field must be in it, and a native query asked for keeps only
 * the query of its platform and language. Nothing is written: the analyst accepts each field into the form.
 */
export const pickHuntAssistance = (spec: HuntPlanSpec, target: HuntAssistTarget): HuntAssistProposal => {
  const nativeQueries = target.native_query
    ? spec.native_queries.filter((query) => query.platform === target.native_query?.platform && query.language.toLowerCase() === target.native_query?.language)
    : spec.native_queries;
  const missing = target.fields.filter((field) => !proposalHas(spec, field, nativeQueries));
  if (missing.length > 0) {
    throw huntAgentError(HUNT_AGENT_FAILURE.incomplete, `The XTM One agent answered without: ${missing.join(', ')}`, { fields: missing });
  }
  const sigmaRule = spec.hunt_type === HUNT_TYPE_TELEMETRY ? spec.sigma_rule : '';
  return {
    fields: target.fields.length > 0 ? target.fields : [...HUNT_ASSIST_FIELDS],
    name: spec.name,
    hypothesis: spec.hypothesis,
    description: spec.description,
    sigma_rule: sigmaRule,
    sigma_validation: sigmaRule.length > 0 ? validateSigmaRule(sigmaRule) : null,
    native_queries: nativeQueries,
    expected_observables: spec.expected_observables,
    benign_patterns: spec.benign_patterns,
    technique_ids: spec.technique_ids,
    rationale: spec.rationale,
  };
};
// endregion

export const validateHuntTriageResult = (raw: unknown): HuntTriageResult => {
  if (!validateTriageSchema(raw)) {
    throw FunctionalError('The hunt triage answer does not match the triage schema', { errors: ajv.errorsText(validateTriageSchema.errors) });
  }
  const result = raw as RawHuntTriageResult;
  return {
    verdict: result.verdict,
    confidence: result.confidence,
    rationale: result.rationale.trim(),
    // An incident is only proposed for a true positive
    incident: result.verdict === HUNT_VERDICT_TRUE_POSITIVE && result.incident ? result.incident : null,
  };
};

/**
 * Agent bound to the intent: the requested slug when it is bound, else the highest priority agent of the intent catalog.
 * The catalog lookup runs as the same identity as the agent call (XTM One catalogs are scoped per user).
 */
export const resolveIntentAgentSlug = async (
  intent: string,
  jwtUser: AgentJwtUser,
  requestedSlug?: string | null,
  onFailure?: (failure: XtmCallFailure) => void,
): Promise<string | null> => {
  const context: AuthContext = {
    ...buildPlaybookAutomationContext(),
    user: { ...AUTOMATION_MANAGER_USER, id: jwtUser.id, user_email: jwtUser.user_email },
  };
  const agents = await xtmOneClient.listAgentsForIntent(context, intent, onFailure);
  const bound = agents.filter((agent) => !!agent.agent_slug);
  if (requestedSlug) {
    return bound.some((agent) => agent.agent_slug === requestedSlug) ? requestedSlug : null;
  }
  const sorted = [...bound].sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
  return sorted.length > 0 ? sorted[0].agent_slug : null;
};

export const callHuntAgent = async (intent: string, jwtUser: AgentJwtUser | null, payload: object, requestedSlug?: string | null) => {
  if (!isXtmOneConfigured()) {
    throw huntAgentError(HUNT_AGENT_FAILURE.notConfigured, FAILURE_MESSAGES.XTM_ONE_NOT_CONFIGURED);
  }
  if (!jwtUser) {
    throw huntAgentError(HUNT_AGENT_FAILURE.refused, 'No identity can be used to call XTM One');
  }
  const failures: { catalog?: XtmCallFailure; call?: XtmCallFailure } = {};
  const slug = await resolveIntentAgentSlug(intent, jwtUser, requestedSlug, (failure) => {
    failures.catalog = failure;
  });
  if (!slug) {
    if (failures.catalog) {
      throw xtmCallError(failures.catalog, { intent });
    }
    throw huntAgentError(HUNT_AGENT_FAILURE.noAgent, `No XTM One agent is bound to the intent ${intent}`, { intent, requestedSlug });
  }
  const content = await callXtmAgent(slug, JSON.stringify(payload), jwtUser, {
    countAsPlaybookRun: false,
    onFailure: (failure) => {
      failures.call = failure;
    },
  });
  if (content === null) {
    if (failures.call) {
      throw xtmCallError(failures.call, { intent, slug });
    }
    throw huntAgentError(HUNT_AGENT_FAILURE.invalidAnswer, `The XTM One agent ${slug} did not answer`, { intent });
  }
  const parsed = extractJsonObject(content);
  if (parsed === null) {
    logApp.warn('[OPENCTI-MODULE] Hunt agent answer is not JSON', { intent, slug });
    if (XTM_ONE_RUN_ERROR.test(content)) {
      throw huntAgentError(HUNT_AGENT_FAILURE.noModel, FAILURE_MESSAGES.XTM_ONE_NO_MODEL, { intent, slug });
    }
    throw huntAgentError(HUNT_AGENT_FAILURE.invalidAnswer, `The XTM One agent ${slug} did not answer with a JSON object`, { intent });
  }
  const refusal = huntAgentRefusalErrors(parsed);
  if (refusal) {
    logApp.warn('[OPENCTI-MODULE] Hunt agent refused its own answer', { intent, slug, errors: refusal });
    const reasons = refusal.length > 0 ? refusal.join('; ') : 'no reason given';
    throw huntAgentError(HUNT_AGENT_FAILURE.invalidAnswer, `The XTM One agent ${slug} could not produce a valid answer: ${reasons}`, { intent, errors: refusal });
  }
  return { slug, answer: parsed };
};
