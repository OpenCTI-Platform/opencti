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
  planning: 'Planning',
  enriching: 'Requesting enrichments',
  waiting_enrichment: 'Waiting for enrichments',
  iterating: 'Analyzing new evidence',
  concluding: 'Concluding',
  finalizing: 'Writing the results',
  awaiting_validation: 'Waiting for the draft approval',
  validating: 'Validating the draft',
  done: 'Done',
};

export const runPhaseLabel = (phase: string) => RUN_PHASE_LABELS[phase] ?? phase;

export const RUN_TRIGGER_LABELS: Record<string, string> = {
  manual: 'Manual',
  playbook: 'Playbook',
  case_rfi_creation: 'Request for information creation',
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

export const PLAN_STEP_KIND_LABELS: Record<string, string> = {
  enrichment: 'Enrichment',
  pivot: 'Pivot',
  correlation: 'Correlation',
  timeline: 'Timeline',
  attribution: 'Attribution',
  recommendation: 'Recommendation',
  report: 'Report',
};

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

export const EVIDENCE_ORIGIN_LABELS: Record<string, string> = {
  subject: 'Investigated entity',
  context: 'Knowledge graph',
  enrichment: 'Enrichment',
  agent: 'Agent',
};

/** Share of a budget used, as the 0-100 percentage the progress bar expects. */
export const budgetPercent = (used: number, max: number) => {
  if (!max || max <= 0) return used > 0 ? 100 : 0;
  return Math.max(0, Math.min(100, Math.round((used / max) * 100)));
};

export const formatDuration = (ms: number) => {
  if (!Number.isFinite(ms) || ms < 1000) return `${Math.max(0, Math.round(ms || 0))} ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes} min ${Math.round(seconds % 60)} s`;
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

export type GoalStatus = 'pending' | 'running' | 'done' | 'skipped' | 'failed' | 'awaiting_approval';

export interface GoalPlanItem {
  id: string;
  title: string;
  status: GoalStatus;
  kind: string | null;
  approvalRequired: boolean;
  children: GoalPlanItem[];
}

const GOAL_STATUS_ALIASES: Record<string, GoalStatus> = {
  pending: 'pending',
  planned: 'pending',
  todo: 'pending',
  running: 'running',
  in_progress: 'running',
  active: 'running',
  done: 'done',
  completed: 'done',
  achieved: 'done',
  answered: 'done',
  skipped: 'skipped',
  abandoned: 'skipped',
  failed: 'failed',
  blocked: 'awaiting_approval',
  awaiting_approval: 'awaiting_approval',
};

export const normalizeGoalStatus = (value: unknown): GoalStatus => {
  if (typeof value !== 'string') return 'pending';
  return GOAL_STATUS_ALIASES[value.toLowerCase()] ?? 'pending';
};

const MAX_GOAL_DEPTH = 3;
const MAX_GOALS = 50;

const goalItemFrom = (raw: unknown, path: string, depth: number): GoalPlanItem | null => {
  if (!raw || typeof raw !== 'object') return null;
  const goal = raw as Record<string, unknown>;
  const title = [goal.title, goal.goal, goal.description, goal.question, goal.name].find((value) => typeof value === 'string' && value.trim().length > 0) as string | undefined;
  if (!title) return null;
  const rawChildren = [goal.steps, goal.sub_goals, goal.subgoals, goal.children].find(Array.isArray) as unknown[] | undefined;
  const children = depth < MAX_GOAL_DEPTH && rawChildren
    ? rawChildren.slice(0, MAX_GOALS).map((child, index) => goalItemFrom(child, `${path}.${index + 1}`, depth + 1)).filter((child): child is GoalPlanItem => child !== null)
    : [];
  return {
    id: typeof goal.id === 'string' && goal.id ? goal.id : path,
    title: title.trim(),
    status: normalizeGoalStatus(goal.status),
    kind: typeof goal.kind === 'string' ? goal.kind : null,
    approvalRequired: goal.approval_required === true,
    children,
  };
};

/**
 * Goals of the investigation engine's goal plan, when the run carries one in a
 * shape we can read (`goals` with nested `steps` / `sub_goals`); null otherwise.
 */
export const goalsFromGoalPlan = (goalPlan: unknown): GoalPlanItem[] | null => {
  if (!goalPlan || typeof goalPlan !== 'object' || Array.isArray(goalPlan)) return null;
  const goals = (goalPlan as { goals?: unknown }).goals;
  if (!Array.isArray(goals)) return null;
  const items = goals.slice(0, MAX_GOALS).map((goal, index) => goalItemFrom(goal, String(index + 1), 1)).filter((goal): goal is GoalPlanItem => goal !== null);
  return items.length > 0 ? items : null;
};

interface PlanStepLike {
  readonly id: string;
  readonly kind: string;
  readonly description: string;
  readonly status: string;
  readonly approval_required: boolean;
}

/** The run's own plan as goals, so both representations render the same way. */
export const goalsFromPlan = (plan: readonly PlanStepLike[]): GoalPlanItem[] => plan.map((step) => ({
  id: step.id,
  title: step.description,
  status: normalizeGoalStatus(step.status),
  kind: step.kind,
  approvalRequired: step.approval_required,
  children: [],
}));

/** Citation number of each piece of evidence, in the order the run collected them (1-based). */
export const citationNumbers = (evidence: readonly { readonly id: string }[]) => {
  const numbers = new Map<string, number>();
  evidence.forEach((item) => {
    if (!numbers.has(item.id)) numbers.set(item.id, numbers.size + 1);
  });
  return numbers;
};

export const investigationGraphPath = (workspaceId: string) => `/dashboard/workspaces/investigations/${workspaceId}`;

export const elementPath = (id: string) => `/dashboard/id/${id}`;
