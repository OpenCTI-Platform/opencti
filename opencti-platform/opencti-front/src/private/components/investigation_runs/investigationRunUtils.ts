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

import { Subject } from 'rxjs';
import type { ChipSeverity } from '@filigran/design-system';
import { APP_BASE_PATH, MESSAGING$ } from '../../../relay/environment';
import { resolveLink } from '../../../utils/Entity';

export type InvestigationRunStatusValue = 'planned' | 'running' | 'awaiting_approval' | 'completed' | 'failed' | 'cancelled';

/** Emits the id of the entity an investigation was just launched on, for the views that list its runs. */
export const INVESTIGATION_LAUNCHED$ = new Subject<string>();

export const ACTIVE_RUN_STATUSES: readonly string[] = ['planned', 'running', 'awaiting_approval'];

export const isRunActive = (status: string | null | undefined) => !!status && ACTIVE_RUN_STATUSES.includes(status);

// Phases during which the engine run is still planning or querying its sources.
const ENGINE_PHASES: readonly string[] = ['initializing', 'starting', 'investigating'];

/** Whether the latest engine run of an investigation is over: nothing it planned can still start. */
export const isEngineRunOver = (run: { run_status: string; run_phase: string }) => !isRunActive(run.run_status) || !ENGINE_PHASES.includes(run.run_phase);

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

export const MEMBER_RESTRICTED_CODE = 'member_restricted';
// Served to a reader who can no longer read an entity of the investigation.
export const SOURCE_INACCESSIBLE_CODE = 'source_inaccessible';
// The investigation concluded, then the platform did not confirm its approved changes written.
export const DRAFT_VALIDATION_FAILED_CODE = 'draft_validation_failed';
export const DRAFT_VALIDATION_UNCONFIRMED_CODE = 'draft_validation_unconfirmed';
export const isDraftValidationFailure = (code: string | null | undefined) => code === DRAFT_VALIDATION_FAILED_CODE || code === DRAFT_VALIDATION_UNCONFIRMED_CODE;

// Why a run ended without the engine or was stopped by OpenCTI, by end_reason_code.
export const ENGINE_REASON_LABELS: Record<string, string> = {
  [MEMBER_RESTRICTED_CODE]: 'An entity of the investigation is now restricted to authorized members: Case Autopilot stopped and withheld what it had found. Remove that entity from the case or ask an administrator for access, then run again.',
  [SOURCE_INACCESSIBLE_CODE]: 'An entity of the investigation is no longer accessible to you: what Case Autopilot found is withheld. Ask an administrator for access to that entity.',
  engine_not_configured: 'XTM One is not connected to this platform: Case Autopilot runs on the XTM One investigation engine.',
  engine_disabled: 'The connected XTM One does not run investigations. Ask your XTM One administrator to turn on Deep Investigation.',
  engine_unavailable: 'The connected XTM One does not provide the investigation engine. Upgrade XTM One to run Case Autopilot.',
  engine_no_agent: 'No agent of the connected XTM One answers the autonomous investigation intent.',
  engine_unreachable: 'The XTM One investigation engine cannot be reached.',
  'run.time_budget_spent': 'The time budget of the investigation was spent before it completed.',
  [DRAFT_VALIDATION_FAILED_CODE]: 'Some approved changes could not be written to the case. Open the draft to see what was approved, then check the case before running Case Autopilot again.',
  [DRAFT_VALIDATION_UNCONFIRMED_CODE]: 'The platform did not confirm in time that the approved changes were written to the case. Open the draft to see what was approved, then check the case.',
};

export const engineReasonLabel = (code: string | null | undefined) => (code ? ENGINE_REASON_LABELS[code] ?? null : null);

// Gates the end of an investigation closed, by their recorded reason: no one decided them.
const CLOSED_BY_THE_RUN_LABELS: Record<string, string> = {
  'Investigation failed': 'Closed when the investigation failed: {subject}',
  'Investigation stopped': 'Closed when the investigation stopped: {subject}',
};

export const closedByTheRunLabel = (rejectionReason: string | null | undefined, hasDecider: boolean) => (
  !hasDecider && rejectionReason ? CLOSED_BY_THE_RUN_LABELS[rejectionReason] ?? null : null
);

/** What became of an approved draft, as far as the platform confirmed it. */
export const approvedDraftOutcome = (run: { run_status: string; run_phase: string; end_reason_code?: string | null }) => {
  if (run.end_reason_code === DRAFT_VALIDATION_FAILED_CODE) return 'some changes could not be written to the case';
  if (run.end_reason_code === DRAFT_VALIDATION_UNCONFIRMED_CODE) return 'the platform did not confirm the changes were written to the case';
  if (isRunActive(run.run_status) && run.run_phase === 'validating') return 'the changes are being written to the case';
  return 'the changes were written to the case';
};

/**
 * Whether the report of a run is read in its draft. A draft is validated as soon
 * as its changes are queued, and the run names the live report only once it
 * completed with the platform's confirmation that they were written.
 */
export const isReportInDraft = (run: { run_status: string; draft?: { draft_status?: string | null } | null }) => (
  !!run.draft && (run.draft.draft_status !== 'validated' || run.run_status !== 'completed')
);

// Investigations stopped at an access boundary, whose findings are withheld: why their sections are empty.
const WITHHELD_SECTION_REASONS: Record<string, string> = {
  [MEMBER_RESTRICTED_CODE]: 'Withheld: an entity of the investigation became restricted to authorized members.',
  subject_inaccessible: 'Withheld: the investigated entity is no longer accessible to the account the investigation runs as.',
  [SOURCE_INACCESSIBLE_CODE]: 'Withheld: an entity of the investigation is no longer accessible to you.',
};

export const withheldSectionReason = (code: string | null | undefined) => (code ? WITHHELD_SECTION_REASONS[code] ?? null : null);

/** The sentence of an empty section: why its findings are withheld, else what to expect while the run is active, else that nothing came. */
export const emptySectionSentence = (
  run: { run_status: string; end_reason_code?: string | null },
  t: (message: string) => string,
  whileActive: string,
  ended: string,
) => {
  const withheld = withheldSectionReason(run.end_reason_code);
  if (withheld) return t(withheld);
  return isRunActive(run.run_status) ? whileActive : ended;
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

export const PRIORITY_LABELS: Record<string, string> = {
  P1: 'Critical priority',
  P2: 'High priority',
  P3: 'Medium priority',
  P4: 'Low priority',
};

export const SEVERITY_LABELS: Record<string, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

// Done is a success, waiting needs attention, the rest is informational.
const RECOMMENDATION_STATUS_SEVERITIES: Record<string, ChipSeverity> = {
  awaiting_approval: 'medium',
  task_created: 'low',
  applied: 'low',
};

export const recommendationStatusSeverity = (status: string): ChipSeverity => RECOMMENDATION_STATUS_SEVERITIES[status] ?? 'neutral';

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
type MutationErrors = readonly { readonly message: string }[] | null | undefined;

/**
 * Report a mutation that completed: GraphQL payload errors reach onCompleted,
 * not onError, so success is only announced without them. True on success.
 */
export const reportMutationOutcome = (errors: MutationErrors, successMessage: string) => {
  if (errors && errors.length > 0) {
    MESSAGING$.notifyError(errors.map((error) => error.message).join(' - '));
    return false;
  }
  MESSAGING$.notifySuccess(successMessage);
  return true;
};

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
 * Once the engine run is over, what is still planned was never reached.
 */
export const actionStatus = (steps: readonly StepLike[], engineOver = false): InvestigationStepStatusValue => {
  if (steps.length === 0) return engineOver ? 'skipped' : 'pending';
  const statuses = steps.map((step) => (engineOver && step.status === 'pending' ? 'skipped' : step.status));
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
 * Steps of earlier engine runs (continuations) keep their own actions. The
 * action that writes the report has no step: the written report is its result.
 */
export const buildGoalPlanView = <S extends StepLike>(goalPlan: unknown, steps: readonly S[], engineOver = false, reportWritten = false): GoalPlanView<S> => {
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
    actions: actions.map((action) => ({
      ...action,
      status: action.producesReport && action.steps.length === 0 && reportWritten ? 'completed' : actionStatus(action.steps, engineOver),
    })),
    otherSteps: ordered.filter((step) => !used.has(step.id)),
  };
};

/** The objective of a goal plan, with its `{value}` placeholder filled with the investigated entity. */
export const goalObjective = (objective: string, subjectName: string | null | undefined) => objective.replace(/\{value\}/g, subjectName ?? '');

// endregion

export const investigationGraphPath = (workspaceId: string) => `/dashboard/workspaces/investigations/${workspaceId}`;

export const elementPath = (id: string) => `/dashboard/id/${id}`;

/** A tab of a case (`observables`, `autopilot`...), or the case itself when its type has no page. */
export const caseTabPath = (caseItem: { id: string; entity_type: string }, tab: string) => {
  const base = resolveLink(caseItem.entity_type);
  return base ? `${base}/${caseItem.id}/${tab}` : elementPath(caseItem.id);
};

/** A launch that would create a case its policy does not allow to create: the server refuses it. */
export const isCaseCreationRefused = (needsCase: boolean, caseMode: 'new' | 'existing', allowedActions?: readonly string[] | null) => {
  return needsCase && caseMode === 'new' && !!allowedActions && !allowedActions.includes('create_case');
};

/** The Autopilot tab of a case, on the investigation it holds. */
export const caseAutopilotPath = (caseItem: { id: string; entity_type: string }, runId?: string | null) => {
  if (!resolveLink(caseItem.entity_type)) return elementPath(caseItem.id);
  const path = caseTabPath(caseItem, 'autopilot');
  return runId ? `${path}?run=${encodeURIComponent(runId)}` : path;
};

// region evidence

interface EvidenceLike {
  readonly id: string;
  readonly investigation_id?: string | null;
  readonly n?: number | null;
  readonly kind: string;
  readonly opencti_id?: string | null;
  readonly entity_type?: string | null;
  readonly href?: string | null;
}

/**
 * Whether a piece of evidence was found by an engine run before the latest
 * one. Every engine run numbers its citations from 1, so only the latest run's
 * evidence (and the case context, found by no engine run) shares the numbers
 * of the report.
 */
export const isEarlierEvidence = (item: EvidenceLike, latestInvestigationId?: string | null) => {
  return !!latestInvestigationId && !!item.investigation_id && item.investigation_id !== latestInvestigationId;
};

/**
 * Citation number of each piece of evidence of the latest engine run: the
 * report's own number when the engine cited it, else the order the run
 * collected it in, after the cited ones. Earlier runs' evidence gets none.
 */
export const citationNumbers = (allEvidence: readonly EvidenceLike[], latestInvestigationId?: string | null) => {
  const numbers = new Map<string, number>();
  const evidence = allEvidence.filter((item) => !isEarlierEvidence(item, latestInvestigationId));
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
