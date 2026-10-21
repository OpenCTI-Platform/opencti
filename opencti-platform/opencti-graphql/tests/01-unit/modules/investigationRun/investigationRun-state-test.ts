import { describe, expect, it } from 'vitest';
import {
  InvestigationAutonomousAction,
  InvestigationEnrichmentRequestStatus,
  InvestigationFeedbackDecision,
  InvestigationFeedbackItemType,
  InvestigationRunPhase,
  InvestigationRunStatus,
} from '../../../../src/generated/graphql';
import {
  acceptanceRate,
  boundApprovals,
  buildTimeline,
  canAutoApproveDraft,
  computeAcceptance,
  computeUsedMinutes,
  computeWaveStatus,
  createRunWindow,
  evaluateEnrichmentRequest,
  feedbackCounterDelta,
  isBudgetExhausted,
  isLowRiskDraft,
  remainingEnrichmentJobs,
  remainingIterations,
  statusTransition,
  upsertFeedback,
} from '../../../../src/modules/investigationRun/investigationRun-state';
import { type InvestigationFeedback } from '../../../../src/modules/investigationRun/investigationRun-types';
import { buildPolicy, buildRun } from './investigationRun-fixtures';

const NOW = new Date('2026-10-01T10:30:00.000Z');

describe('Case Autopilot processing window', () => {
  it('gives every active run its turn, however long the oldest ones stay active', async () => {
    const active = ['r1', 'r2', 'r3', 'r4', 'r5'];
    // A page of two, oldest first, resuming after the cursor (the index of the last run served).
    const page = async (after: string | null) => {
      const start = after ? Number(after) + 1 : 0;
      const items = active.slice(start, start + 2);
      return { items, endCursor: items.length > 0 ? String(start + items.length - 1) : null, hasNextPage: start + 2 < active.length };
    };
    const window = createRunWindow<string>();
    expect(await window(page)).toEqual(['r1', 'r2']);
    expect(await window(page)).toEqual(['r3', 'r4']);
    expect(await window(page)).toEqual(['r5']);
    // The end was reached: the next tick starts again from the oldest.
    expect(await window(page)).toEqual(['r1', 'r2']);
  });

  it('starts again from the oldest when the runs after the cursor are no longer active', async () => {
    let active = ['r1', 'r2', 'r3'];
    const page = async (after: string | null) => {
      const start = after ? active.indexOf(after) + 1 : 0;
      const items = start > 0 && active.indexOf(after as string) < 0 ? [] : active.slice(start, start + 2);
      return { items, endCursor: items[items.length - 1] ?? null, hasNextPage: start + 2 < active.length };
    };
    const window = createRunWindow<string>();
    expect(await window(page)).toEqual(['r1', 'r2']);
    active = ['r1', 'r2'];
    expect(await window(page)).toEqual(['r1', 'r2']);
  });
});

describe('Case Autopilot budgets', () => {
  it('counts only the time spent running', () => {
    const run = buildRun({ active_ms: 10 * 60000, running_since: '2026-10-01T10:20:00.000Z' });
    expect(computeUsedMinutes(run, NOW)).toBe(20);
    expect(computeUsedMinutes(buildRun({ active_ms: 5 * 60000, running_since: null }), NOW)).toBe(5);
  });

  it('is exhausted by time, the engine enforcing the iterations it is given', () => {
    expect(isBudgetExhausted(buildRun(), NOW)).toBe(false);
    expect(isBudgetExhausted(buildRun({ budget: { ...buildRun().budget, used_iterations: 10 } }), NOW)).toBe(false);
    expect(isBudgetExhausted(buildRun({ active_ms: 61 * 60000 }), NOW)).toBe(true);
  });

  it('counts the iterations left to a continuation', () => {
    expect(remainingIterations(buildRun({ budget: { ...buildRun().budget, max_iterations: 10, used_iterations: 3 } }))).toBe(7);
    expect(remainingIterations(buildRun({ budget: { ...buildRun().budget, max_iterations: 10, used_iterations: 10 } }))).toBe(0);
    expect(remainingIterations(buildRun({ budget: { ...buildRun().budget, max_iterations: 10, used_iterations: 12 } }))).toBe(0);
  });

  it('reserves enrichment jobs already queued or awaiting an approval', () => {
    const run = buildRun({
      budget: { ...buildRun().budget, max_enrichment_jobs: 3, used_enrichment_jobs: 1 },
      enrichment_requests: [
        { id: 'q', entity_id: 'a', connector_id: 'c', status: InvestigationEnrichmentRequestStatus.Queued, requested_by: 'engine', created_at: NOW.toISOString() },
        { id: 'd', entity_id: 'b', connector_id: 'c', status: InvestigationEnrichmentRequestStatus.Completed, requested_by: 'engine', created_at: NOW.toISOString() },
      ],
    });
    expect(remainingEnrichmentJobs(run)).toBe(1);
  });
});

describe('Case Autopilot status transitions', () => {
  it('accumulates the active time when a run pauses', () => {
    const run = buildRun({ active_ms: 60000, running_since: '2026-10-01T10:25:00.000Z' });
    const patch = statusTransition(run, InvestigationRunStatus.AwaitingApproval, InvestigationRunPhase.AwaitingValidation, NOW, 'waiting');
    expect(patch).toMatchObject({ run_status: InvestigationRunStatus.AwaitingApproval, active_ms: 6 * 60000, running_since: null, status_reason: 'waiting' });
    expect(patch.completed_at).toBeUndefined();
  });

  it('starts the clock when a run resumes and stamps terminal states', () => {
    const paused = buildRun({ run_status: InvestigationRunStatus.Planned, started_at: null, running_since: null });
    const resumed = statusTransition(paused, InvestigationRunStatus.Running, InvestigationRunPhase.Initializing, NOW);
    expect(resumed).toMatchObject({ running_since: NOW.toISOString(), started_at: NOW.toISOString() });
    const done = statusTransition(buildRun(), InvestigationRunStatus.Completed, InvestigationRunPhase.Done, NOW);
    expect(done.completed_at).toBe(NOW.toISOString());
  });
});

describe('Case Autopilot enrichment gate', () => {
  const base = {
    policy: buildPolicy(),
    allowedConnectorIds: new Set(['connector-free', 'connector-paid']),
    allowedEntityIds: new Set(['ip-1']),
    alreadyAccepted: 0,
  };

  it('queues allowed requests and holds paid connectors for approval', () => {
    expect(evaluateEnrichmentRequest({ ...base, run: buildRun(), entityId: 'ip-1', connectorId: 'connector-free' })).toBe(InvestigationEnrichmentRequestStatus.Queued);
    expect(evaluateEnrichmentRequest({ ...base, run: buildRun(), entityId: 'ip-1', connectorId: 'connector-paid' })).toBe(InvestigationEnrichmentRequestStatus.AwaitingApproval);
  });

  it('rejects requests outside the policy, the scope or the budget', () => {
    expect(evaluateEnrichmentRequest({ ...base, run: buildRun(), entityId: 'ip-1', connectorId: 'connector-vendor' })).toBe('connector_not_allowed');
    expect(evaluateEnrichmentRequest({ ...base, run: buildRun(), entityId: 'ip-9', connectorId: 'connector-free' })).toBe('entity_not_in_scope');
    expect(evaluateEnrichmentRequest({ ...base, run: buildRun({ run_status: InvestigationRunStatus.Completed }), entityId: 'ip-1', connectorId: 'connector-free' })).toBe('run_not_running');
    const noEnrichment = { ...base, policy: buildPolicy({ allowed_actions: [InvestigationAutonomousAction.CreateNote] }) };
    expect(evaluateEnrichmentRequest({ ...noEnrichment, run: buildRun(), entityId: 'ip-1', connectorId: 'connector-free' })).toBe('action_not_allowed');
    const exhausted = buildRun({ budget: { ...buildRun().budget, max_enrichment_jobs: 1, used_enrichment_jobs: 1 } });
    expect(evaluateEnrichmentRequest({ ...base, run: exhausted, entityId: 'ip-1', connectorId: 'connector-free' })).toBe('budget_exhausted');
    const duplicate = buildRun({
      enrichment_requests: [{ id: 'x', entity_id: 'ip-1', connector_id: 'connector-free', status: InvestigationEnrichmentRequestStatus.Completed, requested_by: 'engine', created_at: NOW.toISOString() }],
    });
    expect(evaluateEnrichmentRequest({ ...base, run: duplicate, entityId: 'ip-1', connectorId: 'connector-free' })).toBe('duplicate');
  });
});

describe('Case Autopilot enrichment waves and timeline', () => {
  const request = (status: InvestigationEnrichmentRequestStatus) => ({ status });

  it('derives the status of a wave from its jobs', () => {
    expect(computeWaveStatus([])).toBe('rejected');
    expect(computeWaveStatus([request(InvestigationEnrichmentRequestStatus.Queued)])).toBe('queued');
    expect(computeWaveStatus([request(InvestigationEnrichmentRequestStatus.Queued), request(InvestigationEnrichmentRequestStatus.Dispatched)])).toBe('running');
    expect(computeWaveStatus([request(InvestigationEnrichmentRequestStatus.AwaitingApproval)])).toBe('awaiting_approval');
    expect(computeWaveStatus([request(InvestigationEnrichmentRequestStatus.AwaitingApproval), request(InvestigationEnrichmentRequestStatus.Completed)])).toBe('partial');
    expect(computeWaveStatus([request(InvestigationEnrichmentRequestStatus.Completed), request(InvestigationEnrichmentRequestStatus.Completed)])).toBe('completed');
    expect(computeWaveStatus([request(InvestigationEnrichmentRequestStatus.Completed), request(InvestigationEnrichmentRequestStatus.Timeout)])).toBe('partial');
    expect(computeWaveStatus([request(InvestigationEnrichmentRequestStatus.Rejected)])).toBe('rejected');
    expect(computeWaveStatus([request(InvestigationEnrichmentRequestStatus.Timeout), request(InvestigationEnrichmentRequestStatus.Rejected)])).toBe('timeout');
    expect(computeWaveStatus([request(InvestigationEnrichmentRequestStatus.Failed)])).toBe('partial');
  });

  it('rebuilds a sorted, deduplicated timeline without placeholder dates', () => {
    const timeline = buildTimeline([
      { id: 'ip-1', entity_type: 'IPv4-Addr', created: '2026-09-02T00:00:00Z', first_seen: '2026-08-01T00:00:00Z', last_seen: '5138-11-16T09:46:40.000Z' },
      { id: 'domain-1', entity_type: 'Domain-Name', created: '2026-09-01T00:00:00Z', first_seen: '1970-01-01T00:00:00.000Z' },
      { id: 'ip-1', entity_type: 'IPv4-Addr', created: '2026-09-02T00:00:00Z' },
      { id: 'rel-1', entity_type: 'stix-sighting-relationship', start_time: '2026-08-15T00:00:00Z', stop_time: 'not a date' },
    ]);
    expect(timeline.map((event) => `${event.entity_id}:${event.event}`)).toEqual([
      'ip-1:first_seen',
      'rel-1:first_seen',
      'domain-1:created',
      'ip-1:created',
    ]);
  });
});

describe('Case Autopilot auto-approval', () => {
  it('only lets low-risk drafts through when the policy allows it', () => {
    expect(isLowRiskDraft(['Note', 'Observed-Data'])).toBe(true);
    expect(isLowRiskDraft(['Note', 'Indicator'])).toBe(false);
    expect(isLowRiskDraft([])).toBe(false);
    const notes = { types: ['Note'], complete: true };
    expect(canAutoApproveDraft(buildPolicy(), notes, 90)).toBe(true);
    expect(canAutoApproveDraft(buildPolicy(), notes, 50)).toBe(false);
    // Without an assessed leading hypothesis the threshold is not met: an analyst decides.
    expect(canAutoApproveDraft(buildPolicy(), notes, null)).toBe(false);
    expect(canAutoApproveDraft(buildPolicy({ auto_approve_low_risk: false }), notes, 99)).toBe(false);
    expect(canAutoApproveDraft(buildPolicy(), { types: ['Note', 'stix-core-relationship'], complete: true }, 99)).toBe(false);
  });

  it('leaves a draft read only in part to an analyst', () => {
    expect(canAutoApproveDraft(buildPolicy(), { types: ['Note'], complete: false }, 99)).toBe(false);
  });
});

describe('Case Autopilot feedback accounting', () => {
  const entry = (decision: InvestigationFeedbackDecision, userId = 'user-1'): InvestigationFeedback => ({
    item_type: InvestigationFeedbackItemType.Hypothesis,
    item_ref: 'apt28',
    decision,
    user_id: userId,
    ts: NOW.toISOString(),
  });

  it('keeps the latest decision of each analyst', () => {
    const first = upsertFeedback([], entry(InvestigationFeedbackDecision.Accepted));
    expect(first.previous).toBeNull();
    const second = upsertFeedback(first.feedback, entry(InvestigationFeedbackDecision.Rejected));
    expect(second.previous?.decision).toBe(InvestigationFeedbackDecision.Accepted);
    expect(second.feedback).toHaveLength(1);
    const third = upsertFeedback(second.feedback, entry(InvestigationFeedbackDecision.Accepted, 'user-2'));
    expect(third.feedback).toHaveLength(2);
    expect(computeAcceptance(third.feedback)).toEqual({ hypotheses_accepted: 1, hypotheses_rejected: 1, recommendations_accepted: 0, recommendations_rejected: 0 });
  });

  it('computes deltas and rates for the policy counters', () => {
    const change = feedbackCounterDelta(entry(InvestigationFeedbackDecision.Accepted), entry(InvestigationFeedbackDecision.Rejected));
    expect(change).toEqual({ hypotheses_accepted: -1, hypotheses_rejected: 1, recommendations_accepted: 0, recommendations_rejected: 0 });
    const same = feedbackCounterDelta(entry(InvestigationFeedbackDecision.Accepted), entry(InvestigationFeedbackDecision.Accepted));
    expect(Object.values(same).every((value) => value === 0)).toBe(true);
    expect(acceptanceRate({ hypotheses_accepted: 3, hypotheses_rejected: 1, recommendations_accepted: 0, recommendations_rejected: 0 })).toBe(0.75);
    expect(acceptanceRate({ hypotheses_accepted: 0, hypotheses_rejected: 0, recommendations_accepted: 0, recommendations_rejected: 0 })).toBeNull();
  });
});

describe('Case Autopilot approval history', () => {
  it('drops decided approvals first, oldest first, and never a pending gate', () => {
    const approval = (id: string, status: 'pending' | 'approved' | 'rejected') => ({
      id, kind: 'enrichment', status, description: id, reason: null, connector_id: 'c', entity_id: 'e', recommendation_id: null, created_at: '2026-10-04T00:00:00.000Z',
    }) as never;
    const approvals = [approval('a', 'approved'), approval('b', 'pending'), approval('c', 'rejected'), approval('d', 'pending'), approval('e', 'approved')];
    expect(boundApprovals(approvals, 5)).toBe(approvals);
    expect(boundApprovals(approvals, 3).map((item: { id: string }) => item.id)).toEqual(['b', 'd', 'e']);
    expect(boundApprovals(approvals, 1).map((item: { id: string }) => item.id)).toEqual(['b', 'd']);
  });
});
