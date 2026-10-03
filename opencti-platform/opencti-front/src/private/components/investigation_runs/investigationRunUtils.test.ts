import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  budgetPercent,
  citationNumbers,
  consistencyOf,
  consumeGraphAutoOpen,
  decideInvestigationApprovals,
  feedbackDecisionFor,
  formatDuration,
  formatProbability,
  goalsFromGoalPlan,
  goalsFromPlan,
  isRunActive,
  normalizeGoalStatus,
  rememberGraphAutoOpen,
  runStatusSeverity,
} from './investigationRunUtils';

describe('Case Autopilot run helpers', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    window.sessionStorage.clear();
  });

  it('tells active runs from terminal ones', () => {
    expect(isRunActive('planned')).toBe(true);
    expect(isRunActive('running')).toBe(true);
    expect(isRunActive('awaiting_approval')).toBe(true);
    expect(isRunActive('completed')).toBe(false);
    expect(isRunActive('failed')).toBe(false);
    expect(isRunActive(null)).toBe(false);
    expect(runStatusSeverity('failed')).toBe('high');
    expect(runStatusSeverity('unknown')).toBe('neutral');
  });

  it('maps consistency values on the ACH scale, clamped', () => {
    expect(consistencyOf(2).code).toBe('CC');
    expect(consistencyOf(-1).code).toBe('I');
    expect(consistencyOf(0).label).toBe('Neutral');
    expect(consistencyOf(7).code).toBe('CC');
    expect(consistencyOf(-9).code).toBe('II');
  });

  it('numbers evidence in collection order, once per id', () => {
    const numbers = citationNumbers([{ id: 'a' }, { id: 'b' }, { id: 'a' }, { id: 'c' }]);
    expect(numbers.get('a')).toBe(1);
    expect(numbers.get('b')).toBe(2);
    expect(numbers.get('c')).toBe(3);
    expect(numbers.size).toBe(3);
  });

  it('computes budget percentages for the progress bars', () => {
    expect(budgetPercent(10, 40)).toBe(25);
    expect(budgetPercent(50, 40)).toBe(100);
    expect(budgetPercent(0, 0)).toBe(0);
    expect(budgetPercent(3, 0)).toBe(100);
  });

  it('formats durations and probabilities', () => {
    expect(formatDuration(250)).toBe('250 ms');
    expect(formatDuration(4200)).toBe('4.2 s');
    expect(formatDuration(125000)).toBe('2 min 5 s');
    expect(formatProbability(0.734)).toBe('73%');
    expect(formatProbability(1.4)).toBe('100%');
  });

  it('finds the analyst decision on an item', () => {
    const feedback = [
      { item_type: 'hypothesis', item_ref: 'apt28', decision: 'accepted' },
      { item_type: 'recommendation', item_ref: 'r1', decision: 'rejected' },
    ];
    expect(feedbackDecisionFor(feedback, 'hypothesis', 'apt28')).toBe('accepted');
    expect(feedbackDecisionFor(feedback, 'recommendation', 'r1')).toBe('rejected');
    expect(feedbackDecisionFor(feedback, 'hypothesis', 'r1')).toBeNull();
  });

  it('reads the engine goal plan, nested goals included', () => {
    const goals = goalsFromGoalPlan({
      goals: [
        { id: 'g1', title: 'Scope the intrusion', status: 'completed', steps: [{ description: 'Enrich the domains', status: 'in_progress' }] },
        { question: 'Who is behind it?', status: 'blocked', approval_required: true },
        { status: 'done' },
      ],
    });
    expect(goals).toHaveLength(2);
    expect(goals?.[0]).toMatchObject({ id: 'g1', title: 'Scope the intrusion', status: 'done' });
    expect(goals?.[0].children[0]).toMatchObject({ id: '1.1', title: 'Enrich the domains', status: 'running' });
    expect(goals?.[1]).toMatchObject({ id: '2', status: 'awaiting_approval', approvalRequired: true });
    expect(goalsFromGoalPlan(null)).toBeNull();
    expect(goalsFromGoalPlan({ goals: 'none' })).toBeNull();
    expect(goalsFromGoalPlan({ goals: [] })).toBeNull();
  });

  it('renders the run plan as goals when the engine sent no goal plan', () => {
    const goals = goalsFromPlan([{ id: 's1', kind: 'enrichment', description: 'Enrich the IP', status: 'awaiting_approval', approval_required: true }]);
    expect(goals).toEqual([{ id: 's1', title: 'Enrich the IP', status: 'awaiting_approval', kind: 'enrichment', approvalRequired: true, children: [] }]);
    expect(normalizeGoalStatus('ACHIEVED')).toBe('done');
    expect(normalizeGoalStatus(42)).toBe('pending');
  });

  it('opens the investigation graph once per remembered run', () => {
    rememberGraphAutoOpen('run-1');
    expect(consumeGraphAutoOpen('run-1')).toBe(true);
    expect(consumeGraphAutoOpen('run-1')).toBe(false);
    expect(consumeGraphAutoOpen('run-2')).toBe(false);
  });

  it('posts approval decisions to the platform approval route', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ status: 'accepted', decided: 1 }), { status: 200 }));
    await expect(decideInvestigationApprovals('run-1', [{ tool_call_id: 'a1', decision: 'approve' }])).resolves.toBe(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain('/chatbot/messages/approve');
    expect(JSON.parse(String(init?.body))).toEqual({ investigation_run_id: 'run-1', decisions: [{ tool_call_id: 'a1', decision: 'approve' }] });
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ status: 'error', error: 'No approval of this investigation is waiting for these decisions' }), { status: 409 }));
    await expect(decideInvestigationApprovals('run-1', [{ tool_call_id: 'a1', decision: 'reject' }])).rejects.toThrow('No approval of this investigation is waiting');
  });
});
