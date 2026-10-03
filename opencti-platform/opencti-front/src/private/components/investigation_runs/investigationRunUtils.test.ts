import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  actionStatus,
  budgetPercent,
  buildGoalPlanView,
  caseAutopilotPath,
  citationNumbers,
  consistencyOf,
  consumeGraphAutoOpen,
  decideInvestigationApprovals,
  engineReasonLabel,
  evidenceHref,
  evidenceObjectPath,
  feedbackDecisionFor,
  formatProbability,
  goalObjective,
  isRunActive,
  rememberGraphAutoOpen,
  runStatusSeverity,
  stepDetail,
  stepStatusLabel,
  stepStatusSeverity,
} from './investigationRunUtils';

const step = (id: string, action: string | null, status: string, position: number, investigation_id = 'inv-1') => ({
  id, action, status, position, investigation_id,
});

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

  it('numbers evidence in collection order, once per id, after the numbers the report cited', () => {
    const numbers = citationNumbers([
      { id: 'a', kind: 'opencti_object' },
      { id: 'b', kind: 'url', n: 2 },
      { id: 'a', kind: 'opencti_object' },
      { id: 'c', kind: 'document' },
    ]);
    expect(numbers.get('b')).toBe(2);
    expect(numbers.get('a')).toBe(3);
    expect(numbers.get('c')).toBe(4);
    expect(numbers.size).toBe(3);
  });

  it('links evidence: web pages by their address, OpenCTI objects by their type', () => {
    expect(evidenceHref({ id: 'e1', kind: 'url', href: 'https://example.com/report' })).toBe('https://example.com/report');
    expect(evidenceHref({ id: 'e2', kind: 'document', href: 'https://example.com/file.pdf' })).toBeNull();
    expect(evidenceObjectPath({ id: 'e3', kind: 'opencti_object' })).toBeNull();
    expect(evidenceObjectPath({ id: 'e4', kind: 'opencti_object', opencti_id: 'x-1' })).toBe('/dashboard/id/x-1');
  });

  it('opens the Autopilot tab of a case on a run', () => {
    expect(caseAutopilotPath({ id: 'c1', entity_type: 'Case-Incident' }, 'run 1')).toBe('/dashboard/cases/incidents/c1/autopilot?run=run%201');
    expect(caseAutopilotPath({ id: 'c2', entity_type: 'Case-Rfi' })).toBe('/dashboard/cases/rfis/c2/autopilot');
  });

  it('computes budget percentages for the progress bars', () => {
    expect(budgetPercent(10, 40)).toBe(25);
    expect(budgetPercent(50, 40)).toBe(100);
    expect(budgetPercent(0, 0)).toBe(0);
    expect(budgetPercent(3, 0)).toBe(100);
  });

  it('formats probabilities', () => {
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

  it('labels the seven step states verbatim, never as a success when nothing was found', () => {
    expect(['pending', 'active', 'completed', 'empty', 'degraded', 'error', 'skipped'].map(stepStatusLabel))
      .toEqual(['Planned step', 'Querying', 'Found', 'Nothing found', 'Partial', 'Failed', 'Not reached']);
    expect(stepStatusLabel('unknown')).toBe('Planned step');
    expect(stepStatusSeverity('completed')).toBe('low');
    expect(stepStatusSeverity('empty')).toBe('neutral');
    expect(stepStatusSeverity('error')).toBe('high');
  });

  it('derives the state of a goal plan action from its steps', () => {
    expect(actionStatus([])).toBe('pending');
    expect(actionStatus([step('1', 'a', 'pending', 1), step('2', 'a', 'completed', 2)])).toBe('active');
    expect(actionStatus([step('1', 'a', 'completed', 1), step('2', 'a', 'error', 2)])).toBe('degraded');
    expect(actionStatus([step('1', 'a', 'completed', 1), step('2', 'a', 'empty', 2)])).toBe('completed');
    expect(actionStatus([step('1', 'a', 'error', 1), step('2', 'a', 'error', 2)])).toBe('error');
    expect(actionStatus([step('1', 'a', 'error', 1), step('2', 'a', 'empty', 2)])).toBe('degraded');
    expect(actionStatus([step('1', 'a', 'empty', 1), step('2', 'a', 'skipped', 2)])).toBe('empty');
    expect(actionStatus([step('1', 'a', 'skipped', 1)])).toBe('skipped');
  });

  it('maps the engine goal plan onto the steps that serve each action', () => {
    const view = buildGoalPlanView({
      objective: 'Investigate {value}',
      reachable: true,
      actions: [
        { slug: 'opencti_context', label: 'Read the case', produces_report: false },
        { slug: 'opencti_context', label: 'Duplicate' },
        { slug: 'report', label: 'Write the report', produces_report: true, servable: false },
        { label: 'No slug' },
      ],
    }, [
      step('s2', 'opencti_context', 'completed', 2),
      step('s1', 'opencti_context', 'empty', 1),
      step('s3', 'enrichment', 'active', 3, 'inv-2'),
      step('s4', null, 'error', 4),
    ]);
    expect(view.objective).toBe('Investigate {value}');
    expect(view.actions.map((action) => action.slug)).toEqual(['opencti_context', 'report', 'enrichment']);
    expect(view.actions[0]).toMatchObject({ label: 'Read the case', status: 'completed' });
    expect(view.actions[0].steps.map((item) => item.id)).toEqual(['s1', 's2']);
    expect(view.actions[1]).toMatchObject({ producesReport: true, servable: false, status: 'pending' });
    expect(view.actions[2]).toMatchObject({ label: 'enrichment', status: 'active' });
    expect(view.otherSteps.map((item) => item.id)).toEqual(['s4']);
    expect(buildGoalPlanView(null, []).actions).toEqual([]);
    expect(buildGoalPlanView({ reachable: false }, []).reachable).toBe(false);
    expect(goalObjective('Investigate {value}', 'APT28 phishing')).toBe('Investigate APT28 phishing');
  });

  it('renders machine-readable step details and engine reasons', () => {
    const translate = (value: string) => `t(${value})`;
    expect(stepDetail('source.timed_out', { seconds: 30, ignored: { a: 1 } }, translate)).toBe('t(The source did not answer in time) (seconds: 30)');
    expect(stepDetail('source.new_code', null, translate)).toBe('new code');
    expect(stepDetail(null, null, translate)).toBeNull();
    expect(engineReasonLabel('engine_disabled')).toContain('Deep Investigation');
    expect(engineReasonLabel('other')).toBeNull();
    expect(engineReasonLabel(null)).toBeNull();
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
