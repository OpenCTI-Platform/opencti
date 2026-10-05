import Ajv, { type JSONSchemaType, type SchemaObject } from 'ajv';
import type { AuthContext } from '../../types/user';
import { logApp } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { AUTOMATION_MANAGER_USER } from '../../utils/access';
import xtmOneClient from '../xtm/one/xtm-one-client';
import { type AgentJwtUser, buildPlaybookAutomationContext, callXtmAgent, isXtmOneConfigured } from '../playbook/components/ai-agent-shared';
import { validateSigmaRule } from './hunt-sigma';
import { HUNT_TYPE_INFRASTRUCTURE, HUNT_TYPE_TELEMETRY, type HuntNativeQuery } from './hunt-types';
import { huntLogicError } from './hunt-validators';
import { clampInteger, HUNT_CONFIG, HUNT_DEFAULT_ESCALATION_THRESHOLD, HUNT_DEFAULT_TIME_WINDOW_HOURS, HUNT_MAX_ESCALATION_THRESHOLD, normalizeNativeQueries } from './hunt-utils';
import { HUNT_VERDICT_BENIGN, HUNT_VERDICT_INCONCLUSIVE, HUNT_VERDICT_TRUE_POSITIVE } from './huntRun/huntRun-types';

export const HUNT_PLANNER_INTENT = 'cti.hunt_hypothesis';
export const HUNT_TRIAGE_INTENT = 'cti.hunt_triage';

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
    throw FunctionalError('The hunt planner answer does not match the hunt spec schema', { errors: ajv.errorsText(validatePlanSchema.errors) });
  }
  const spec = raw as RawHuntPlanSpec;
  const sigmaRule = (spec.sigma_rule ?? '').trim();
  const nativeQueries = normalizeNativeQueries(spec.native_queries ?? []);
  // A plan is proposed only if it can be activated: the logic rules of an active hunt apply
  const logicError = huntLogicError({ hunt_type: spec.hunt_type, sigma_rule: sigmaRule, native_queries: nativeQueries });
  if (logicError) {
    throw FunctionalError(`The hunt planner answer cannot run: ${logicError.message}`, { field: logicError.field });
  }
  if (sigmaRule.length > 0) {
    const sigma = validateSigmaRule(sigmaRule);
    if (!sigma.valid) {
      throw FunctionalError('The hunt planner answer contains an invalid Sigma rule', { errors: sigma.errors });
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
export const resolveIntentAgentSlug = async (intent: string, jwtUser: AgentJwtUser, requestedSlug?: string | null): Promise<string | null> => {
  const context: AuthContext = {
    ...buildPlaybookAutomationContext(),
    user: { ...AUTOMATION_MANAGER_USER, id: jwtUser.id, user_email: jwtUser.user_email },
  };
  const agents = await xtmOneClient.listAgentsForIntent(context, intent);
  const bound = agents.filter((agent) => !!agent.agent_slug);
  if (requestedSlug) {
    return bound.some((agent) => agent.agent_slug === requestedSlug) ? requestedSlug : null;
  }
  const sorted = [...bound].sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
  return sorted.length > 0 ? sorted[0].agent_slug : null;
};

export const callHuntAgent = async (intent: string, jwtUser: AgentJwtUser | null, payload: object, requestedSlug?: string | null) => {
  if (!isXtmOneConfigured()) {
    throw FunctionalError('XTM One is not configured on this platform');
  }
  if (!jwtUser) {
    throw FunctionalError('No identity can be used to call XTM One');
  }
  const slug = await resolveIntentAgentSlug(intent, jwtUser, requestedSlug);
  if (!slug) {
    throw FunctionalError(`No XTM One agent is bound to the intent ${intent}`, { intent, requestedSlug });
  }
  const content = await callXtmAgent(slug, JSON.stringify(payload), jwtUser, { countAsPlaybookRun: false });
  if (content === null) {
    throw FunctionalError(`The XTM One agent ${slug} did not answer`, { intent });
  }
  const parsed = extractJsonObject(content);
  if (parsed === null) {
    logApp.warn('[OPENCTI-MODULE] Hunt agent answer is not JSON', { intent, slug });
    throw FunctionalError(`The XTM One agent ${slug} did not answer with a JSON object`, { intent });
  }
  const refusal = huntAgentRefusalErrors(parsed);
  if (refusal) {
    logApp.warn('[OPENCTI-MODULE] Hunt agent refused its own answer', { intent, slug, errors: refusal });
    const reasons = refusal.length > 0 ? refusal.join('; ') : 'no reason given';
    throw FunctionalError(`The XTM One agent ${slug} could not produce a valid answer: ${reasons}`, { intent, errors: refusal });
  }
  return { slug, answer: parsed };
};
