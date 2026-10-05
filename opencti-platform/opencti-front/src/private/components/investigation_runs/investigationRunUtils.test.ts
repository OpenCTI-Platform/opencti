import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  actionStatus,
  approvedDraftOutcome,
  budgetPercent,
  buildGoalPlanView,
  caseAutopilotPath,
  citationNumbers,
  closedByTheRunLabel,
  consistencyOf,
  consumeGraphAutoOpen,
  decideInvestigationApprovals,
  emptySectionSentence,
  engineReasonLabel,
  evidenceHref,
  evidenceObjectPath,
  feedbackDecisionFor,
  formatProbability,
  goalObjective,
  isCaseCreationRefused,
  isEarlierEvidence,
  isDraftValidationFailure,
  isEngineRunOver,
  isReportInDraft,
  isRunActive,
  rememberGraphAutoOpen,
  runStatusSeverity,
  stepStatusLabel,
  stepStatusSeverity,
  withheldSectionReason,
} from './investigationRunUtils';

const step = (id: string, action: string | null, status: string, position: number, investigation_id = 'inv-1') => ({
  id, action, status, position, investigation_id,
});

describe('Case Autopilot run helpers', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    window.sessionStorage.clear();
  });

  it('refuses a launch creating a case only when its policy does not allow it', () => {
    expect(isCaseCreationRefused(true, 'new', ['enrichment'])).toBe(true);
    expect(isCaseCreationRefused(true, 'new', ['create_case', 'enrichment'])).toBe(false);
    expect(isCaseCreationRefused(true, 'existing', ['enrichment'])).toBe(false);
    expect(isCaseCreationRefused(false, 'new', [])).toBe(false);
    expect(isCaseCreationRefused(true, 'new', undefined)).toBe(false);
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

  it('numbers only the latest engine run evidence after a continuation, since each run cites from 1', () => {
    const evidence = [
      { id: 'old-1', kind: 'url', n: 1, investigation_id: 'inv-1' },
      { id: 'context', kind: 'opencti_object', investigation_id: null },
      { id: 'new-1', kind: 'url', n: 1, investigation_id: 'inv-2' },
      { id: 'new-2', kind: 'document', n: 2, investigation_id: 'inv-2' },
    ];
    const numbers = citationNumbers(evidence, 'inv-2');
    expect(numbers.get('new-1')).toBe(1);
    expect(numbers.get('new-2')).toBe(2);
    expect(numbers.get('context')).toBe(3);
    expect(numbers.has('old-1')).toBe(false);
    expect(isEarlierEvidence(evidence[0], 'inv-2')).toBe(true);
    expect(isEarlierEvidence(evidence[1], 'inv-2')).toBe(false);
    expect(isEarlierEvidence(evidence[0], null)).toBe(false);
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

  it('shows what the engine never reached once its run is over', () => {
    const plan = { actions: [{ slug: 'enrichment', label: 'Enrich' }, { slug: 'report', label: 'Write the report' }] };
    const steps = [step('s1', 'enrichment', 'completed', 1), step('s2', 'enrichment', 'pending', 2)];
    expect(buildGoalPlanView(plan, steps).actions.map((action) => action.status)).toEqual(['active', 'pending']);
    expect(buildGoalPlanView(plan, steps, true).actions.map((action) => action.status)).toEqual(['completed', 'skipped']);
    // The action that writes the report has no step: the written report completes it.
    const reportPlan = { actions: [{ slug: 'enrichment', label: 'Enrich' }, { slug: 'report', label: 'Write the report', produces_report: true }] };
    expect(buildGoalPlanView(reportPlan, steps, true, true).actions.map((action) => action.status)).toEqual(['completed', 'completed']);
    expect(buildGoalPlanView(reportPlan, steps, true, false).actions.map((action) => action.status)).toEqual(['completed', 'skipped']);
    expect(isEngineRunOver({ run_status: 'running', run_phase: 'investigating' })).toBe(false);
    expect(isEngineRunOver({ run_status: 'planned', run_phase: 'initializing' })).toBe(false);
    expect(isEngineRunOver({ run_status: 'awaiting_approval', run_phase: 'awaiting_validation' })).toBe(true);
    expect(isEngineRunOver({ run_status: 'running', run_phase: 'ingesting' })).toBe(true);
    expect(isEngineRunOver({ run_status: 'cancelled', run_phase: 'investigating' })).toBe(true);
  });

  it('renders the engine reasons in words', () => {
    expect(engineReasonLabel('engine_disabled')).toContain('Deep Investigation');
    expect(engineReasonLabel('member_restricted')).toContain('ask an administrator for access, then run again');
    expect(engineReasonLabel('source_inaccessible')).toContain('no longer accessible to you');
    expect(engineReasonLabel('draft_validation_failed')).toContain('could not be written to the case');
    expect(engineReasonLabel('draft_validation_unconfirmed')).toContain('did not confirm in time');
    expect(engineReasonLabel('other')).toBeNull();
    expect(engineReasonLabel(null)).toBeNull();
  });

  it('says what became of an approved draft, as far as the platform confirmed it', () => {
    expect(approvedDraftOutcome({ run_status: 'completed', run_phase: 'done' })).toBe('the changes were written to the case');
    expect(approvedDraftOutcome({ run_status: 'running', run_phase: 'validating' })).toBe('the changes are being written to the case');
    expect(approvedDraftOutcome({ run_status: 'failed', run_phase: 'done', end_reason_code: 'draft_validation_failed' })).toBe('some changes could not be written to the case');
    expect(approvedDraftOutcome({ run_status: 'failed', run_phase: 'done', end_reason_code: 'draft_validation_unconfirmed' }))
      .toBe('the platform did not confirm the changes were written to the case');
    expect(isReportInDraft({ run_status: 'completed', draft: { draft_status: 'validated' } })).toBe(false);
    expect(isReportInDraft({ run_status: 'running', draft: { draft_status: 'validated' } })).toBe(true);
    expect(isReportInDraft({ run_status: 'failed', draft: { draft_status: 'validated' } })).toBe(true);
    expect(isReportInDraft({ run_status: 'completed', draft: { draft_status: 'open' } })).toBe(true);
    expect(isReportInDraft({ run_status: 'completed', draft: null })).toBe(false);
    expect(isDraftValidationFailure('draft_validation_failed')).toBe(true);
    expect(isDraftValidationFailure('member_restricted')).toBe(false);
    expect(isDraftValidationFailure(null)).toBe(false);
  });

  it('credits the gates the end of an investigation closed to the investigation, never to an analyst', () => {
    expect(closedByTheRunLabel('Investigation failed', false)).toBe('Closed when the investigation failed: {subject}');
    expect(closedByTheRunLabel('Investigation stopped', false)).toBe('Closed when the investigation stopped: {subject}');
    expect(closedByTheRunLabel('Investigation failed', true)).toBeNull();
    expect(closedByTheRunLabel('Run cancelled', false)).toBeNull();
    expect(closedByTheRunLabel(null, false)).toBeNull();
  });

  it('says why the sections of an investigation stopped at an access boundary are empty', () => {
    const t = (message: string) => `t:${message}`;
    expect(emptySectionSentence({ run_status: 'failed', end_reason_code: 'member_restricted' }, t, 'while active', 'ended'))
      .toBe('t:Withheld: an entity of the investigation became restricted to authorized members.');
    expect(emptySectionSentence({ run_status: 'failed', end_reason_code: 'subject_inaccessible' }, t, 'while active', 'ended'))
      .toBe('t:Withheld: the investigated entity is no longer accessible to the account the investigation runs as.');
    // Served to a reader who lost access to one of its entities, whatever the run status.
    expect(emptySectionSentence({ run_status: 'completed', end_reason_code: 'source_inaccessible' }, t, 'while active', 'ended'))
      .toBe('t:Withheld: an entity of the investigation is no longer accessible to you.');
    expect(emptySectionSentence({ run_status: 'failed', end_reason_code: 'engine_disabled' }, t, 'while active', 'ended')).toBe('ended');
    expect(emptySectionSentence({ run_status: 'running', end_reason_code: null }, t, 'while active', 'ended')).toBe('while active');
    expect(withheldSectionReason(null)).toBeNull();
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
