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

// Pure rules of the investigation run state machine: budgets, enrichment
// gates, timeline reconstruction, auto-approval and acceptance accounting.
// The manager and the domain apply them; nothing here touches the database.

import { v4 as uuidv4 } from 'uuid';
import {
  InvestigationAutonomousAction,
  InvestigationEnrichmentRequestStatus,
  InvestigationFeedbackDecision,
  InvestigationFeedbackItemType,
  InvestigationLedgerStatus,
  InvestigationRunPhase,
  InvestigationRunStatus,
} from '../../generated/graphql';
import {
  INVESTIGATION_LIMITS,
  type BasicStoreEntityInvestigationPolicy,
  type BasicStoreEntityInvestigationRun,
  type InvestigationAcceptance,
  type InvestigationBudget,
  type InvestigationFeedback,
  type InvestigationLedgerEntry,
  type InvestigationTimelineEvent,
} from './investigationRun-types';
import { ENTITY_TYPE_CONTAINER_NOTE, ENTITY_TYPE_CONTAINER_OBSERVED_DATA } from '../../schema/stixDomainObject';

// Longest wait for an enrichment wave before the run moves on with what it has.
export const ENRICHMENT_WAVE_TIMEOUT_MS = 10 * 60 * 1000;
// Longest wait for the validation work of an approved draft.
export const VALIDATION_TIMEOUT_MS = 30 * 60 * 1000;

// Object types a policy may let reach the live graph without human approval.
export const LOW_RISK_DRAFT_TYPES = [ENTITY_TYPE_CONTAINER_NOTE, ENTITY_TYPE_CONTAINER_OBSERVED_DATA];

export type EnrichmentRequestRejection = 'budget_exhausted' | 'connector_not_allowed' | 'entity_not_in_scope' | 'duplicate' | 'run_not_running' | 'action_not_allowed';

const toTime = (value: string | null | undefined): number | null => {
  if (!value) return null;
  const time = new Date(value).getTime();
  return Number.isNaN(time) ? null : time;
};

export const computeActiveMs = (run: Pick<BasicStoreEntityInvestigationRun, 'active_ms' | 'running_since'>, now: Date): number => {
  const since = toTime(run.running_since);
  const slice = since === null ? 0 : Math.max(0, now.getTime() - since);
  return (run.active_ms ?? 0) + slice;
};

export const computeUsedMinutes = (run: Pick<BasicStoreEntityInvestigationRun, 'active_ms' | 'running_since'>, now: Date): number => {
  return Math.round((computeActiveMs(run, now) / 60000) * 100) / 100;
};

export const remainingMinutes = (run: BasicStoreEntityInvestigationRun, now: Date): number => {
  return Math.max(0, run.budget.max_minutes - computeUsedMinutes(run, now));
};

export const isBudgetExhausted = (run: BasicStoreEntityInvestigationRun, now: Date): boolean => {
  return run.budget.used_tool_calls >= run.budget.max_tool_calls || remainingMinutes(run, now) <= 0;
};

export const remainingEnrichmentJobs = (run: BasicStoreEntityInvestigationRun): number => {
  const reserved = run.enrichment_requests.filter((request) => request.status === InvestigationEnrichmentRequestStatus.Queued
    || request.status === InvestigationEnrichmentRequestStatus.AwaitingApproval).length;
  return Math.max(0, run.budget.max_enrichment_jobs - run.budget.used_enrichment_jobs - reserved);
};

export const buildBudget = (policy: Pick<BasicStoreEntityInvestigationPolicy, 'max_tool_calls' | 'max_enrichment_jobs' | 'max_minutes'>): InvestigationBudget => ({
  max_tool_calls: policy.max_tool_calls,
  max_enrichment_jobs: policy.max_enrichment_jobs,
  max_minutes: policy.max_minutes,
  used_tool_calls: 0,
  used_enrichment_jobs: 0,
  used_minutes: 0,
});

// Status/phase patch moving a run in or out of the running state, keeping
// the active time accounting consistent.
export const statusTransition = (
  run: BasicStoreEntityInvestigationRun,
  status: InvestigationRunStatus,
  phase: InvestigationRunPhase,
  now: Date,
  reason?: string | null,
): Record<string, unknown> => {
  const wasRunning = run.run_status === InvestigationRunStatus.Running;
  const willRun = status === InvestigationRunStatus.Running;
  const patch: Record<string, unknown> = { run_status: status, run_phase: phase };
  if (reason !== undefined) patch.status_reason = reason;
  if (wasRunning && !willRun) {
    patch.active_ms = computeActiveMs(run, now);
    patch.running_since = null;
  } else if (!wasRunning && willRun) {
    patch.running_since = now.toISOString();
    if (!run.started_at) patch.started_at = now.toISOString();
  }
  if (status === InvestigationRunStatus.Completed || status === InvestigationRunStatus.Failed || status === InvestigationRunStatus.Cancelled) {
    patch.completed_at = now.toISOString();
  }
  const activeMs = (patch.active_ms as number | undefined) ?? computeActiveMs(run, now);
  patch.budget = { ...run.budget, used_minutes: Math.round((activeMs / 60000) * 100) / 100 };
  return patch;
};

export interface EnrichmentGateInput {
  run: BasicStoreEntityInvestigationRun;
  policy: Pick<BasicStoreEntityInvestigationPolicy, 'allowed_actions' | 'approval_connector_ids'>;
  allowedConnectorIds: Set<string>;
  allowedEntityIds: Set<string>;
  entityId: string;
  connectorId: string;
  alreadyAccepted: number;
}

// Decide what happens to one enrichment request, before it is stored.
export const evaluateEnrichmentRequest = (input: EnrichmentGateInput): InvestigationEnrichmentRequestStatus | EnrichmentRequestRejection => {
  const { run, policy, allowedConnectorIds, allowedEntityIds, entityId, connectorId, alreadyAccepted } = input;
  if (run.run_status !== InvestigationRunStatus.Running) return 'run_not_running';
  if (!policy.allowed_actions.includes(InvestigationAutonomousAction.Enrichment)) return 'action_not_allowed';
  if (!allowedConnectorIds.has(connectorId)) return 'connector_not_allowed';
  if (!allowedEntityIds.has(entityId)) return 'entity_not_in_scope';
  const duplicate = run.enrichment_requests.some((request) => request.entity_id === entityId && request.connector_id === connectorId
    && request.status !== InvestigationEnrichmentRequestStatus.Rejected && request.status !== InvestigationEnrichmentRequestStatus.Failed);
  if (duplicate) return 'duplicate';
  if (remainingEnrichmentJobs(run) - alreadyAccepted <= 0) return 'budget_exhausted';
  if (policy.approval_connector_ids.includes(connectorId)) return InvestigationEnrichmentRequestStatus.AwaitingApproval;
  return InvestigationEnrichmentRequestStatus.Queued;
};

export const isEnrichmentRejection = (value: InvestigationEnrichmentRequestStatus | EnrichmentRequestRejection): value is EnrichmentRequestRejection => {
  return !Object.values(InvestigationEnrichmentRequestStatus).includes(value as InvestigationEnrichmentRequestStatus);
};

export const buildLedgerEntry = (
  run: Pick<BasicStoreEntityInvestigationRun, 'iteration'>,
  entry: Partial<InvestigationLedgerEntry> & Pick<InvestigationLedgerEntry, 'tool' | 'description'>,
  now: Date,
): InvestigationLedgerEntry => ({
  id: uuidv4(),
  step_id: entry.step_id ?? null,
  iteration: run.iteration,
  tool: entry.tool,
  description: entry.description.slice(0, INVESTIGATION_LIMITS.textLength),
  input_ref: entry.input_ref ?? null,
  output_ref: entry.output_ref ?? null,
  status: entry.status ?? InvestigationLedgerStatus.Done,
  started_at: entry.started_at ?? now.toISOString(),
  duration_ms: Math.max(0, Math.round(entry.duration_ms ?? 0)),
  cost_units: Math.max(0, Math.round(entry.cost_units ?? 0)),
  work_id: entry.work_id ?? null,
  error: entry.error ? entry.error.slice(0, INVESTIGATION_LIMITS.textLength) : null,
});

// Append ledger entries, keeping the most recent ones within the cap.
export const appendLedger = (steps: InvestigationLedgerEntry[], entries: InvestigationLedgerEntry[]) => {
  const all = [...steps, ...entries];
  return all.length > INVESTIGATION_LIMITS.ledgerEntries ? all.slice(all.length - INVESTIGATION_LIMITS.ledgerEntries) : all;
};

export interface TimelineSource {
  id: string;
  entity_type: string;
  name?: string | null;
  created?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
  start_time?: string | null;
  stop_time?: string | null;
}

// Rebuild the timeline from the dates carried by the evidence: creation,
// first and last observation. Bounded, deduplicated and sorted.
export const buildTimeline = (sources: TimelineSource[]): InvestigationTimelineEvent[] => {
  const events: InvestigationTimelineEvent[] = [];
  const seen = new Set<string>();
  const push = (source: TimelineSource, value: string | null | undefined, event: string) => {
    const time = toTime(value);
    // Placeholder dates (epoch, far future) are not events.
    if (time === null || time <= 0 || time >= new Date('5000-01-01T00:00:00Z').getTime()) return;
    const ts = new Date(time).toISOString();
    const key = `${source.id}::${event}::${ts}`;
    if (seen.has(key)) return;
    seen.add(key);
    events.push({ ts, entity_id: source.id, entity_type: source.entity_type, name: source.name ?? null, event });
  };
  sources.forEach((source) => {
    push(source, source.first_seen ?? source.start_time, 'first_seen');
    push(source, source.last_seen ?? source.stop_time, 'last_seen');
    push(source, source.created, 'created');
  });
  events.sort((a, b) => (a.ts === b.ts ? a.entity_id.localeCompare(b.entity_id) : a.ts.localeCompare(b.ts)));
  return events.length > INVESTIGATION_LIMITS.timeline ? events.slice(events.length - INVESTIGATION_LIMITS.timeline) : events;
};

export const isLowRiskDraft = (draftTypes: string[]): boolean => {
  return draftTypes.length > 0 && draftTypes.every((type) => LOW_RISK_DRAFT_TYPES.includes(type));
};

export const canAutoApproveDraft = (
  policy: Pick<BasicStoreEntityInvestigationPolicy, 'auto_approve_low_risk' | 'auto_approve_min_confidence'>,
  draftTypes: string[],
  leadingConfidence: number | null,
): boolean => {
  if (!policy.auto_approve_low_risk || !isLowRiskDraft(draftTypes)) return false;
  // Without any hypothesis the threshold cannot apply: only notes and observed data are involved.
  return leadingConfidence === null || leadingConfidence >= policy.auto_approve_min_confidence;
};

// Latest decision per analyst and item: an analyst changing their mind replaces their previous decision.
export const upsertFeedback = (feedback: InvestigationFeedback[], entry: InvestigationFeedback) => {
  const previous = feedback.find((item) => item.item_type === entry.item_type && item.item_ref === entry.item_ref && item.user_id === entry.user_id) ?? null;
  const others = feedback.filter((item) => item !== previous);
  const next = [...others, entry];
  return {
    previous,
    feedback: next.length > INVESTIGATION_LIMITS.feedback ? next.slice(next.length - INVESTIGATION_LIMITS.feedback) : next,
  };
};

export const computeAcceptance = (feedback: InvestigationFeedback[]): InvestigationAcceptance => {
  const count = (itemType: InvestigationFeedbackItemType, decision: InvestigationFeedbackDecision) => {
    return feedback.filter((item) => item.item_type === itemType && item.decision === decision).length;
  };
  return {
    hypotheses_accepted: count(InvestigationFeedbackItemType.Hypothesis, InvestigationFeedbackDecision.Accepted),
    hypotheses_rejected: count(InvestigationFeedbackItemType.Hypothesis, InvestigationFeedbackDecision.Rejected),
    recommendations_accepted: count(InvestigationFeedbackItemType.Recommendation, InvestigationFeedbackDecision.Accepted),
    recommendations_rejected: count(InvestigationFeedbackItemType.Recommendation, InvestigationFeedbackDecision.Rejected),
  };
};

export const acceptanceRate = (acceptance: InvestigationAcceptance): number | null => {
  const accepted = acceptance.hypotheses_accepted + acceptance.recommendations_accepted;
  const total = accepted + acceptance.hypotheses_rejected + acceptance.recommendations_rejected;
  return total === 0 ? null : Math.round((accepted / total) * 1000) / 1000;
};

// Counter delta to apply on the policy when a decision is added or changed.
export const feedbackCounterDelta = (previous: InvestigationFeedback | null, next: InvestigationFeedback) => {
  const key = (item: InvestigationFeedback) => {
    const kind = item.item_type === InvestigationFeedbackItemType.Hypothesis ? 'hypotheses' : 'recommendations';
    const decision = item.decision === InvestigationFeedbackDecision.Accepted ? 'accepted' : 'rejected';
    return `${kind}_${decision}` as keyof InvestigationAcceptance;
  };
  const delta: InvestigationAcceptance = { hypotheses_accepted: 0, hypotheses_rejected: 0, recommendations_accepted: 0, recommendations_rejected: 0 };
  if (previous) delta[key(previous)] -= 1;
  delta[key(next)] += 1;
  return delta;
};
