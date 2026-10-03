/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import type { ChipSeverity } from '@filigran/design-system';
import { APP_BASE_PATH } from '../../../relay/environment';
import { resolveLink } from '../../../utils/Entity';

export type InvestigationRunStatusValue = 'planned' | 'running' | 'awaiting_approval' | 'completed' | 'failed' | 'cancelled';

export const ACTIVE_RUN_STATUSES: readonly string[] = ['planned', 'running', 'awaiting_approval'];

export const isRunActive = (status: string | null | undefined) => !!status && ACTIVE_RUN_STATUSES.includes(status);

export const RUN_STATUS_LABELS: Record<InvestigationRunStatusValue, string> = {
  planned: 'Planned',
  running: 'Running',
  awaiting_approval: 'Awaiting approval',
  completed: 'Completed',
  failed: 'Failed',
  cancelled: 'Cancelled',
};

const RUN_STATUS_SEVERITIES: Record<InvestigationRunStatusValue, ChipSeverity> = {
  planned: 'neutral',
  running: 'info',
  awaiting_approval: 'medium',
  completed: 'low',
  failed: 'high',
  cancelled: 'neutral',
};

export const runStatusLabel = (status: string) => RUN_STATUS_LABELS[status as InvestigationRunStatusValue] ?? status;

export const runStatusSeverity = (status: string): ChipSeverity => RUN_STATUS_SEVERITIES[status as InvestigationRunStatusValue] ?? 'neutral';

export const RUN_PHASE_LABELS: Record<string, string> = {
  initializing: 'Collecting the context',
  starting: 'Starting the investigation',
  investigating: 'Investigating',
  ingesting: 'Writing the results to the draft',
  awaiting_validation: 'Waiting for the draft approval',
  validating: 'Validating the draft',
  done: 'Done',
};

export const runPhaseLabel = (phase: string) => RUN_PHASE_LABELS[phase] ?? phase;

// The built-in pack of the investigation engine for OpenCTI cases.
export const DEFAULT_PACK = 'opencti-case-investigation';

export const RUN_TRIGGER_LABELS: Record<string, string> = {
  manual: 'Manual',
  playbook: 'Playbook',
  case_rfi_creation: 'Request for information creation',
};

// The seven step states of the investigation engine, with the labels every
// product renders. Only a step that found something is a success.
export type InvestigationStepStatusValue = 'pending' | 'active' | 'completed' | 'empty' | 'degraded' | 'error' | 'skipped';

export const STEP_STATUS_LABELS: Record<InvestigationStepStatusValue, string> = {
  pending: 'Planned step',
  active: 'Querying',
  completed: 'Found',
  empty: 'Nothing found',
  degraded: 'Partial',
  error: 'Failed',
  skipped: 'Not reached',
};

const STEP_STATUS_SEVERITIES: Record<InvestigationStepStatusValue, ChipSeverity> = {
  pending: 'neutral',
  active: 'info',
  completed: 'low',
  empty: 'neutral',
  degraded: 'medium',
  error: 'high',
  skipped: 'neutral',
};

export const stepStatusLabel = (status: string) => STEP_STATUS_LABELS[status as InvestigationStepStatusValue] ?? STEP_STATUS_LABELS.pending;

export const stepStatusSeverity = (status: string): ChipSeverity => STEP_STATUS_SEVERITIES[status as InvestigationStepStatusValue] ?? 'neutral';

// Why a run ended without the engine, by end_reason_code.
export const ENGINE_REASON_LABELS: Record<string, string> = {
  engine_not_configured: 'XTM One is not connected to this platform: Case Autopilot runs on the XTM One investigation engine.',
  engine_disabled: 'The connected XTM One does not run investigations. Ask your XTM One administrator to turn on Deep Investigation.',
  engine_unavailable: 'The connected XTM One does not provide the investigation engine. Upgrade XTM One to run Case Autopilot.',
  engine_no_agent: 'No agent of the connected XTM One answers the autonomous investigation intent.',
  engine_unreachable: 'The XTM One investigation engine cannot be reached.',
};

export const engineReasonLabel = (code: string | null | undefined) => (code ? ENGINE_REASON_LABELS[code] ?? null : null);

// Machine-readable step details of the engine, rendered in the reader's
// language; a code without a label here falls back to its parameters.
export const STEP_DETAIL_LABELS: Record<string, string> = {
  'run.all_sources_queried': 'Every source was queried',
  'run.budget_spent': 'The budget of the investigation was spent',
  'run.no_covering_source': 'No source of the pack covers this subject',
  'run.cancelled': 'The investigation was cancelled',
  'run.interrupted': 'The investigation was interrupted',
  'source.timed_out': 'The source did not answer in time',
  'source.http_status': 'The source answered with an error',
  'source.truncated': 'The answer was truncated',
  'source.thin_response': 'The source answered with very little content',
  'source.querier_error': 'The source could not be queried',
  'source.opencti_unavailable': 'OpenCTI could not be read',
  'source.opencti_known': 'Known in OpenCTI',
  'source.opencti_none_known': 'Nothing known in OpenCTI',
  'source.case_context': 'Case context read',
  'source.case_context_empty': 'The case holds no context yet',
  'source.case_run_missing': 'The investigation of this case is not available',
  'source.enrichment_wave': 'Enrichment jobs ran through the connectors',
  'source.enrichment_nothing_to_enrich': 'Nothing to enrich',
  'source.enrichment_awaiting_approval': 'Enrichment jobs are waiting for an approval',
  'source.enrichment_refused': 'Enrichment jobs were refused by the policy',
  'source.enrichment_timed_out': 'The enrichment jobs did not end in time',
};

/** The detail of a step in the reader's language: its label and its parameters. */
export const stepDetail = (code: string | null | undefined, params: unknown, translate: (text: string) => string) => {
  if (!code) return null;
  const label = STEP_DETAIL_LABELS[code];
  const values = params && typeof params === 'object' && !Array.isArray(params)
    ? Object.entries(params as Record<string, unknown>)
        .filter(([, value]) => typeof value === 'string' || typeof value === 'number')
        .map(([key, value]) => `${key.replace(/_/g, ' ')}: ${value}`)
    : [];
  const text = label ? translate(label) : code.replace(/^(run|source)\./, '').replace(/_/g, ' ');
  return values.length > 0 ? `${text} (${values.join(', ')})` : text;
};

// Analysis of Competing Hypotheses notation, from strongly inconsistent to
// strongly consistent.
export const CONSISTENCY_SCALE: Record<number, { code: string; label: string }> = {
  [-2]: { code: 'II', label: 'Strongly inconsistent' },
  [-1]: { code: 'I', label: 'Inconsistent' },
  0: { code: 'N', label: 'Neutral' },
  1: { code: 'C', label: 'Consistent' },
  2: { code: 'CC', label: 'Strongly consistent' },
};

export const consistencyOf = (value: number) => {
  const clamped = Math.max(-2, Math.min(2, Math.round(value)));
  return CONSISTENCY_SCALE[clamped];
};

export const EVIDENCE_CATEGORY_LABELS: Record<string, string> = {
  infrastructure_overlap: 'Infrastructure overlap',
  tooling: 'Tooling',
  ttp_overlap: 'TTP overlap',
  victimology: 'Victimology',
  temporal: 'Temporal plausibility',
  source_reliability: 'Source reliability',
  language_timezone: 'Language and timezone',
};

export const EVIDENCE_KIND_LABELS: Record<string, string> = {
  url: 'Web page',
  document: 'Document',
  tool_result: 'Tool result',
  opencti_object: 'OpenCTI object',
};

export const CONFIDENCE_LABELS: Record<string, string> = {
  almost_certain: 'Almost certain',
  very_likely: 'Very likely',
  likely: 'Likely',
  roughly_even: 'Roughly even chance',
  unlikely: 'Unlikely',
  very_unlikely: 'Very unlikely',
  remote: 'Remote chance',
};

export const RECOMMENDATION_ACTION_LABELS: Record<string, string> = {
  task: 'Task',
  course_of_action: 'Course of action',
  severity_change: 'Severity change',
  sharing: 'Sharing',
  notification: 'Notification',
  case_closure: 'Case closure',
  other: 'Other',
};

export const RECOMMENDATION_STATUS_LABELS: Record<string, string> = {
  proposed: 'Proposed',
  awaiting_approval: 'Awaiting approval',
  task_created: 'Task created',
  applied: 'Applied',
  dismissed: 'Dismissed',
};

const PRIORITY_SEVERITIES: Record<string, ChipSeverity> = {
  P1: 'critical',
  P2: 'high',
  P3: 'medium',
  P4: 'low',
};

export const prioritySeverity = (priority: string): ChipSeverity => PRIORITY_SEVERITIES[priority] ?? 'neutral';

export const APPROVAL_KIND_LABELS: Record<string, string> = {
  enrichment: 'Paid or restricted enrichment',
  recommendation: 'Sensitive recommendation',
  draft_validation: 'Investigation draft',
};

export const ENRICHMENT_STATUS_LABELS: Record<string, string> = {
  queued: 'Queued',
  awaiting_approval: 'Awaiting approval',
  dispatched: 'Dispatched',
  completed: 'Completed',
  failed: 'Failed',
  rejected: 'Rejected',
  timeout: 'Timed out',
  skipped: 'Skipped',
};

const ENRICHMENT_STATUS_SEVERITIES: Record<string, ChipSeverity> = {
  dispatched: 'info',
  completed: 'low',
  awaiting_approval: 'medium',
  timeout: 'medium',
  failed: 'high',
  rejected: 'high',
};

export const enrichmentStatusSeverity = (status: string): ChipSeverity => ENRICHMENT_STATUS_SEVERITIES[status] ?? 'neutral';

/** Share of a budget used, as the 0-100 percentage the progress bar expects. */
export const budgetPercent = (used: number, max: number) => {
  if (!max || max <= 0) return used > 0 ? 100 : 0;
  return Math.max(0, Math.min(100, Math.round((used / max) * 100)));
};

export const formatProbability = (probability: number) => `${Math.round(Math.max(0, Math.min(1, probability)) * 100)}%`;

interface FeedbackEntry {
  readonly item_type: string;
  readonly item_ref: string;
  readonly decision: string;
}

/** The latest decision recorded on a hypothesis or a recommendation, if any. */
export const feedbackDecisionFor = <T extends FeedbackEntry>(feedback: readonly T[], itemType: string, itemRef: string) => {
  const entry = feedback.find((item) => item.item_type === itemType && item.item_ref === itemRef);
  return entry?.decision ?? null;
};

export type InvestigationApprovalDecision = 'approve' | 'approve_always' | 'reject';

export interface InvestigationApprovalDecisionInput {
  tool_call_id: string;
  decision: InvestigationApprovalDecision;
  rejection_reason?: string | null;
}

/**
 * Decide approval gates of a run on the platform approval route, the same
 * route as the assistant's tool approvals: an approval is a person's consent,
 * so it is only accepted from a browser session, never from a token.
 */
export const decideInvestigationApprovals = async (runId: string, decisions: InvestigationApprovalDecisionInput[]) => {
  const response = await fetch(`${APP_BASE_PATH}/chatbot/messages/approve`, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ investigation_run_id: runId, decisions }),
  });
  const payload = await response.json().catch(() => ({})) as { error?: string; decided?: number };
  if (!response.ok) {
    throw new Error(payload.error ?? `HTTP ${response.status}`);
  }
  return payload.decided ?? 0;
};

// A run launched from this browser with "open the investigation graph when it
// completes" is remembered for the session, so the graph opens once, here.
const AUTO_OPEN_PREFIX = 'case-autopilot-open-graph:';

export const rememberGraphAutoOpen = (runId: string) => {
  try {
    window.sessionStorage.setItem(`${AUTO_OPEN_PREFIX}${runId}`, '1');
  } catch {
    // Storage unavailable (private mode quota): the graph simply does not open by itself.
  }
};

export const consumeGraphAutoOpen = (runId: string) => {
  try {
    const key = `${AUTO_OPEN_PREFIX}${runId}`;
    const marked = window.sessionStorage.getItem(key) === '1';
    if (marked) window.sessionStorage.removeItem(key);
    return marked;
  } catch {
    return false;
  }
};

// region goal plan

interface StepLike {
  readonly id: string;
  readonly investigation_id: string;
  readonly position: number;
  readonly action?: string | null;
  readonly status: string;
}

export interface GoalPlanAction<S extends StepLike> {
  slug: string;
  label: string;
  description: string | null;
  producesReport: boolean;
  servable: boolean;
  status: InvestigationStepStatusValue;
  steps: S[];
}

export interface GoalPlanView<S extends StepLike> {
  objective: string | null;
  reachable: boolean;
  actions: GoalPlanAction<S>[];
  // Steps of the engine that serve no action of the plan.
  otherSteps: S[];
}

const MAX_ACTIONS = 50;

const text = (value: unknown): string | null => (typeof value === 'string' && value.trim().length > 0 ? value.trim() : null);

/**
 * The state of an action, derived from its steps the way the engine block
 * does: what holds is never sent, it is read from what the sources answered.
 */
export const actionStatus = (steps: readonly StepLike[]): InvestigationStepStatusValue => {
  if (steps.length === 0) return 'pending';
  const statuses = steps.map((step) => step.status);
  if (statuses.includes('active')) return 'active';
  if (statuses.includes('pending')) return statuses.some((status) => status !== 'pending') ? 'active' : 'pending';
  if (statuses.includes('completed')) return statuses.some((status) => status === 'error' || status === 'degraded') ? 'degraded' : 'completed';
  if (statuses.includes('degraded')) return 'degraded';
  if (statuses.includes('error')) return statuses.every((status) => status === 'error') ? 'error' : 'degraded';
  if (statuses.includes('empty')) return 'empty';
  return 'skipped';
};

/**
 * The goal plan of the latest engine run (`goal_plan` of the run, the shape
 * of the engine's GoalPlanResponse) with the steps that serve each action.
 * Steps of earlier engine runs (continuations) keep their own actions.
 */
export const buildGoalPlanView = <S extends StepLike>(goalPlan: unknown, steps: readonly S[]): GoalPlanView<S> => {
  const plan = goalPlan && typeof goalPlan === 'object' && !Array.isArray(goalPlan) ? goalPlan as Record<string, unknown> : {};
  const rawActions = Array.isArray(plan.actions) ? plan.actions.slice(0, MAX_ACTIONS) : [];
  const ordered = [...steps].sort((a, b) => a.position - b.position);
  const used = new Set<string>();
  const actions: GoalPlanAction<S>[] = [];
  rawActions.forEach((raw) => {
    const action = raw && typeof raw === 'object' ? raw as Record<string, unknown> : null;
    const slug = text(action?.slug);
    if (!action || !slug || actions.some((existing) => existing.slug === slug)) return;
    const actionSteps = ordered.filter((step) => step.action === slug);
    actionSteps.forEach((step) => used.add(step.id));
    actions.push({
      slug,
      label: text(action.label) ?? slug,
      description: text(action.description),
      producesReport: action.produces_report === true,
      servable: action.servable !== false,
      status: 'pending',
      steps: actionSteps,
    });
  });
  // An engine without a declared plan still names the action of each step.
  ordered.forEach((step) => {
    if (used.has(step.id) || !step.action) return;
    const existing = actions.find((action) => action.slug === step.action);
    if (existing) {
      existing.steps.push(step);
    } else {
      actions.push({ slug: step.action, label: step.action.replace(/_/g, ' '), description: null, producesReport: false, servable: true, status: 'pending', steps: [step] });
    }
    used.add(step.id);
  });
  return {
    objective: text(plan.objective),
    reachable: plan.reachable !== false,
    actions: actions.map((action) => ({ ...action, status: actionStatus(action.steps) })),
    otherSteps: ordered.filter((step) => !used.has(step.id)),
  };
};

/** The objective of a goal plan, with its `{value}` placeholder filled with the investigated entity. */
export const goalObjective = (objective: string, subjectName: string | null | undefined) => objective.replace(/\{value\}/g, subjectName ?? '');

// endregion

export const investigationGraphPath = (workspaceId: string) => `/dashboard/workspaces/investigations/${workspaceId}`;

export const elementPath = (id: string) => `/dashboard/id/${id}`;

/** The Autopilot tab of a case, on the investigation it holds. */
export const caseAutopilotPath = (caseItem: { id: string; entity_type: string }, runId?: string | null) => {
  const base = resolveLink(caseItem.entity_type);
  if (!base) return elementPath(caseItem.id);
  const path = `${base}/${caseItem.id}/autopilot`;
  return runId ? `${path}?run=${encodeURIComponent(runId)}` : path;
};

// region evidence

interface EvidenceLike {
  readonly id: string;
  readonly n?: number | null;
  readonly kind: string;
  readonly opencti_id?: string | null;
  readonly entity_type?: string | null;
  readonly href?: string | null;
}

/**
 * Citation number of each piece of evidence: the report's own number when the
 * engine cited it, else the order the run collected it in, after the cited ones.
 */
export const citationNumbers = (evidence: readonly EvidenceLike[]) => {
  const numbers = new Map<string, number>();
  let next = Math.max(0, ...evidence.map((item) => item.n ?? 0));
  evidence.forEach((item) => {
    if (numbers.has(item.id)) return;
    if (item.n && item.n > 0) {
      numbers.set(item.id, item.n);
    } else {
      next += 1;
      numbers.set(item.id, next);
    }
  });
  return numbers;
};

/** Where an OpenCTI object of the evidence opens, by its type when known. */
export const evidenceObjectPath = (item: EvidenceLike) => {
  if (!item.opencti_id) return null;
  const base = item.entity_type ? resolveLink(item.entity_type) : null;
  return base ? `${base}/${item.opencti_id}` : elementPath(item.opencti_id);
};

/** A followable address of a cited passage (web pages only). */
export const evidenceHref = (item: EvidenceLike) => {
  if (item.kind !== 'url' || !item.href) return null;
  try {
    const url = new URL(item.href);
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.toString() : null;
  } catch {
    return null;
  }
};

// endregion
