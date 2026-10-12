import { describe, expect, it } from 'vitest';
import {
  InvestigationEvidenceKind,
  InvestigationRecommendationActionKind,
  InvestigationRecommendationPriority,
  InvestigationRecommendationStatus,
  InvestigationRunTrigger,
  InvestigationStepStatus,
} from '../../../../src/generated/graphql';
import {
  boundGoalPlan,
  buildAllowedIds,
  buildStartBody,
  engineOutcome,
  groundConclusion,
  isReportPending,
  mirrorEvidence,
  conclusionCandidateIds,
  mirrorReportSources,
  mirrorSteps,
  parseEngineInvestigation,
  canonicalObservableValue,
  parseEngineKnowledge,
  REPORT_WAIT_MS,
  type InvestigationEngineContext,
} from '../../../../src/modules/investigationRun/investigationRun-engine';
import { INVESTIGATION_DEFAULT_PACK, INVESTIGATION_LIMITS, INVESTIGATION_START_SCHEMA } from '../../../../src/modules/investigationRun/investigationRun-types';
import { buildPolicy, buildRun } from './investigationRun-fixtures';

const context: InvestigationEngineContext = {
  subject: { id: 'incident-1', standard_id: 'incident--1', entity_type: 'Incident', name: 'Phishing wave' },
  entities: [
    { id: 'domain-1', standard_id: 'domain-name--1', entity_type: 'Domain-Name', name: 'evil.example' },
    { id: 'ip-1', entity_type: 'IPv4-Addr', name: '185.12.4.2' },
  ],
  relationships: [{ id: 'rel-1', relationship_type: 'resolves-to', from_id: 'domain-1', to_id: 'ip-1' }],
  candidates: [{ id: 'apt28', standard_id: 'intrusion-set--28', entity_type: 'Intrusion-Set', name: 'APT28', aliases: ['Fancy Bear'] }],
  courses_of_action: [{ id: 'coa-1', name: 'Block the C2', x_mitre_id: 'M1031' }],
  pir: [],
  connectors: [{ id: 'connector-vt', name: 'VirusTotal', scope: ['IPv4-Addr'], requires_approval: true }],
  allowed_actions: ['enrichment'],
};

const engineAnswer = (overrides: Record<string, unknown> = {}) => parseEngineInvestigation({
  id: 'inv-1',
  status: 'completed',
  revision: 7,
  goal_plan: { pack_slug: 'opencti-case-investigation', declared: true, actions: [{ slug: 'enrich', label: 'Enrich through OpenCTI connectors', effects: ['enriched'] }] },
  steps: [
    { step_id: 's1', position: 1, step_status: 'completed', source_name: 'OpenCTI case context', action: 'read_case', findings_count: 3, evidence: [{}, {}] },
    { step_id: 's2', position: 2, step_status: 'empty', source_name: 'OpenCTI connectors', action: 'enrich', detail_code: 'source.enrichment_awaiting_approval', detail_params: { count: 1 } },
    { step_id: 's3', position: 3, step_status: 'mystery', source_name: 'Web search' },
  ],
  evidence: [
    { n: 1, kind: 'opencti_object', label: '185.12.4.2', opencti_id: 'ip-1', entity_type: 'IPv4-Addr', href: 'https://should-not-be-kept' },
    { n: 2, kind: 'url', label: 'Vendor write-up', href: 'https://vendor.example/apt28', quote: 'The C2 belongs to APT28' },
    { n: 3, kind: 'url', label: 'Unsafe link', href: 'javascript:alert(1)' },
  ],
  conclusion: {
    summary: 'APT28 is the most likely operator.',
    hypotheses: [
      { candidate_id: 'intrusion-set--28', rationale: 'Shared C2', evidence: [{ ref: '1', category: 'infrastructure', consistency: 5, weight: 9 }, { ref: '2', category: 'ttp', consistency: 1 }, { ref: '9', category: 'tooling', consistency: 1 }] },
      { candidate_id: 'unknown-actor', evidence: [] },
    ],
    recommendations: [
      { kind: 'create_task', text: 'Block 185.12.4.2', priority: 'high' },
      { kind: 'apply_course_of_action', text: 'Apply the mitigation', course_of_action_id: 'coa-1', priority: 'medium' },
      { kind: 'apply_course_of_action', text: 'Apply an invented mitigation', course_of_action_id: 'coa-404' },
      { kind: 'notify', text: 'Warn the CERT', priority: 'low' },
      { kind: 'escalate', text: 'Raise the severity', severity: 'critical', priority: 'critical' },
    ],
  },
  report: 'APT28 operates the C2 [2].',
  report_status: 'written',
  report_sources: [{ n: 2, label: 'Vendor write-up', href: 'https://vendor.example/apt28' }, { n: 3, label: 'Unsafe', href: 'ftp://x' }, { label: 'no number' }],
  iterations_used: 4,
  completed_at: '2026-10-01T10:20:00.000Z',
  ...overrides,
});

describe('Case Autopilot engine start', () => {
  it('builds the opencti.investigation.start/v1 body from the run, its policy and its context', () => {
    const allowed = buildAllowedIds(context);
    const body = buildStartBody({
      run: buildRun({ run_trigger: InvestigationRunTrigger.CaseRfiCreation, budget: { ...buildRun().budget, used_iterations: 3 } }),
      policy: buildPolicy({ pack_options: { pivots: 'off' } }),
      agentSlug: 'deep-investigation-agent',
      subjectName: 'Phishing wave',
      context,
      allowed,
      remainingMinutes: 12.7,
      remainingEnrichmentJobs: 5,
      continuesInvestigationId: 'inv-0',
    });
    expect(body.schema).toBe(INVESTIGATION_START_SCHEMA);
    expect(body.pack).toBe(INVESTIGATION_DEFAULT_PACK);
    expect(body.pack_options).toEqual({ [INVESTIGATION_DEFAULT_PACK]: { pivots: 'off' } });
    expect(body.subject).toEqual({ opencti_id: 'incident-1', entity_type: 'Incident', name: 'Phishing wave' });
    expect(body.run).toEqual({ id: 'run-1', draft_id: 'draft-1', workspace_id: null, trigger: 'rfi' });
    expect(body.budget).toEqual({ max_iterations: 7, max_minutes: 12, max_enrichment_jobs: 5 });
    expect(body.policy.enrichment_connector_ids).toEqual(['connector-vt']);
    expect(body.context.entities.map((entity) => entity.id)).toEqual(['incident-1', 'domain-1', 'ip-1']);
    expect(body.allowed_ids.candidates).toEqual(['apt28']);
    expect(body.continues_investigation_id).toBe('inv-0');
    const named = buildStartBody({ run: buildRun(), policy: buildPolicy({ pack_id: 'phishing' }), agentSlug: 'a', subjectName: 's', context, allowed, remainingMinutes: 0.2, remainingEnrichmentJobs: 0 });
    expect(named.pack).toBe('phishing');
    expect(named.budget.max_minutes).toBe(1);
  });
});

describe('Case Autopilot engine state', () => {
  it('parses the engine answer and refuses anything else', () => {
    const engine = engineAnswer();
    expect(engine).toMatchObject({ id: 'inv-1', status: 'completed', revision: 7, iterations_used: 4 });
    expect(parseEngineInvestigation(null)).toBeNull();
    expect(parseEngineInvestigation({ status: 'running' })).toBeNull();
    expect(parseEngineInvestigation({ investigation_id: 'inv-9' })?.id).toBe('inv-9');
  });

  it('maps engine statuses on run outcomes', () => {
    expect(engineOutcome('completed')).toBe('completed');
    expect(engineOutcome('cancelled')).toBe('cancelled');
    expect(engineOutcome('aborted')).toBe('failed');
    expect(engineOutcome('planning')).toBe('running');
    expect(engineOutcome('running')).toBe('running');
  });

  it('waits for a report still being written, within a bound', () => {
    const now = new Date('2026-10-01T10:21:00.000Z');
    const writing = engineAnswer({ report: null, report_status: 'writing' }) as NonNullable<ReturnType<typeof engineAnswer>>;
    expect(isReportPending(writing, '2026-10-01T10:20:00.000Z', now)).toBe(true);
    expect(isReportPending(writing, new Date(now.getTime() - REPORT_WAIT_MS - 1000).toISOString(), now)).toBe(false);
    expect(isReportPending(engineAnswer({ report: null, report_status: 'none' }) as NonNullable<ReturnType<typeof engineAnswer>>, null, now)).toBe(false);
    expect(isReportPending(engineAnswer() as NonNullable<ReturnType<typeof engineAnswer>>, null, now)).toBe(false);
  });

  it('mirrors the steps of an engine run in the seven states, keeping earlier runs', () => {
    const engine = engineAnswer() as NonNullable<ReturnType<typeof engineAnswer>>;
    const previous = mirrorSteps([], 'inv-0', [{ step_id: 'old', position: 1, step_status: 'completed', source_name: 'Old source' }]);
    const steps = mirrorSteps(previous, engine.id, engine.steps);
    expect(steps.map((step) => step.id)).toEqual(['old', 's1', 's2', 's3']);
    expect(steps[1]).toMatchObject({ status: InvestigationStepStatus.Completed, findings_count: 3, evidence_count: 2, action: 'read_case' });
    expect(steps[2]).toMatchObject({ status: InvestigationStepStatus.Empty, detail_code: 'source.enrichment_awaiting_approval', detail_params: { count: 1 } });
    expect(steps[3].status).toBe(InvestigationStepStatus.Pending);
    const again = mirrorSteps(steps, engine.id, engine.steps.slice(0, 1));
    expect(again.map((step) => step.id)).toEqual(['old', 's1']);
  });

  it('mirrors the evidence in the shared shape, links OpenCTI objects to themselves and drops unsafe addresses', () => {
    const engine = engineAnswer() as NonNullable<ReturnType<typeof engineAnswer>>;
    const evidence = mirrorEvidence([], engine);
    expect(evidence[0]).toMatchObject({ id: 'ip-1', kind: InvestigationEvidenceKind.OpenctiObject, opencti_id: 'ip-1', href: null, n: 1 });
    expect(evidence[1]).toMatchObject({ id: 'inv-1:2', kind: InvestigationEvidenceKind.Url, href: 'https://vendor.example/apt28', quote: 'The C2 belongs to APT28' });
    expect(evidence[2].href).toBeNull();
    const known = mirrorEvidence([{ ...evidence[0], confidence: 90, n: null }], engine);
    expect(known[0]).toMatchObject({ confidence: 90, n: 1 });
    expect(mirrorReportSources(engine)).toEqual([{ n: 2, label: 'Vendor write-up', href: 'https://vendor.example/apt28' }, { n: 3, label: 'Unsafe', href: null }]);
  });

  it('names every candidate the conclusion quotes, cited as evidence or not', () => {
    const engine = engineAnswer() as NonNullable<ReturnType<typeof engineAnswer>>;
    expect(conclusionCandidateIds(engine.conclusion)).toEqual(['intrusion-set--28', 'unknown-actor']);
    expect(conclusionCandidateIds(null)).toEqual([]);
    expect(conclusionCandidateIds({ hypotheses: [{ candidate_id: '' }, { other: 1 }, 'x'] })).toEqual([]);
  });

  it('keeps the step that found each piece of evidence', () => {
    const flat = engineAnswer({
      evidence: [{ n: 1, kind: 'url', label: 'Vendor write-up', href: 'https://vendor.example/apt28', step_id: 's2' }],
    }) as NonNullable<ReturnType<typeof engineAnswer>>;
    expect(mirrorEvidence([], flat)[0].step_id).toBe('s2');
    // An older answer without the flat list: the evidence is read from its step.
    const nested = engineAnswer({
      evidence: undefined,
      report_sources: [],
      steps: [{ step_id: 's1', position: 1, step_status: 'completed', source_name: 'Web', evidence: [{ kind: 'url', label: 'Blog', href: 'https://blog.example/a' }] }],
    }) as NonNullable<ReturnType<typeof engineAnswer>>;
    expect(mirrorEvidence([], nested)[0]).toMatchObject({ label: 'Blog', step_id: 's1' });
    // Evidence collected by OpenCTI keeps no step; a known item keeps the step it was found by.
    const known = mirrorEvidence([{ ...mirrorEvidence([], flat)[0], step_id: null }], flat);
    expect(known[0].step_id).toBe('s2');
  });

  it('numbers the evidence a continuation cites again with the continuation, never with the earlier run', () => {
    const engine = engineAnswer() as NonNullable<ReturnType<typeof engineAnswer>>;
    const earlier = mirrorEvidence([], { ...engine, id: 'inv-0' });
    const continued = mirrorEvidence(earlier, {
      ...engine,
      evidence: [{ kind: 'opencti_object', opencti_id: 'ip-1', label: 'IP', step_id: 's9' }],
    });
    const cited = continued.find((item) => item.id === 'ip-1');
    expect(cited).toMatchObject({ investigation_id: engine.id, n: null, step_id: 's9' });
    // What the continuation does not cite stays with the run that found it.
    expect(continued.filter((item) => item.id !== 'ip-1').every((item) => item.investigation_id === 'inv-0')).toBe(true);
  });

  it('keeps the engine goal plan as a bounded JSON object', () => {
    const goalPlan = { actions: [{ slug: 'enrich' }] };
    expect(boundGoalPlan(goalPlan)).toEqual(goalPlan);
    expect(boundGoalPlan([goalPlan])).toBeNull();
    expect(boundGoalPlan({ notes: 'z'.repeat(INVESTIGATION_LIMITS.goalPlanLength) })).toBeNull();
  });
});

describe('Case Autopilot conclusion grounding', () => {
  it('grounds hypotheses on citations and ids the run may use, never on the model weights', () => {
    const engine = engineAnswer() as NonNullable<ReturnType<typeof engineAnswer>>;
    const evidence = mirrorEvidence([], engine);
    const allowed = buildAllowedIds(context);
    evidence.forEach((item) => allowed.evidence.add(item.id));
    const candidateInfo = new Map([['apt28', { name: 'APT28', entity_type: 'Intrusion-Set', standard_id: 'intrusion-set--28' }]]);
    const grounded = groundConclusion(engine.conclusion, allowed, candidateInfo, evidence, engine.id);
    expect(grounded.summary).toBe('APT28 is the most likely operator.');
    expect(grounded.hypotheses).toHaveLength(1);
    expect(grounded.hypotheses[0]).toMatchObject({ candidate_id: 'apt28', candidate_name: 'APT28' });
    expect(grounded.hypotheses[0].evidence).toEqual([
      { evidence_id: 'ip-1', category: 'infrastructure_overlap', consistency: 2, rationale: null },
      { evidence_id: 'inv-1:2', category: 'ttp_overlap', consistency: 1, rationale: null },
    ]);
    // An unknown candidate and an unknown citation are dropped, and a course of action that does not exist.
    expect(grounded.dropped).toBe(3);
  });

  it('reads the evidence references of the shared conclusion schema: cite:<n> and OpenCTI ids', () => {
    const engine = engineAnswer({
      conclusion: {
        hypotheses: [{
          candidate_id: 'intrusion-set--28',
          evidence: [
            { evidence_id: 'cite:2', category: 'ttp_overlap', consistency: 1 },
            { evidence_id: 'ip-1', category: 'infrastructure_overlap', consistency: 2 },
            { evidence_id: 'cite:9', category: 'tooling', consistency: 1 },
          ],
        }],
        recommendations: [],
      },
    }) as NonNullable<ReturnType<typeof engineAnswer>>;
    const evidence = mirrorEvidence([], engine);
    const allowed = buildAllowedIds(context);
    evidence.forEach((item) => allowed.evidence.add(item.id));
    const candidateInfo = new Map([['apt28', { name: 'APT28', entity_type: 'Intrusion-Set', standard_id: 'intrusion-set--28' }]]);
    const grounded = groundConclusion(engine.conclusion, allowed, candidateInfo, evidence, engine.id);
    expect(grounded.hypotheses[0].evidence.map((cell) => cell.evidence_id)).toEqual(['inv-1:2', 'ip-1']);
    expect(grounded.dropped).toBe(1);
  });

  it('resolves a citation number only within the engine run that numbered it', () => {
    const engine = engineAnswer({
      conclusion: {
        hypotheses: [{
          candidate_id: 'intrusion-set--28',
          evidence: [
            { evidence_id: 'cite:2', category: 'ttp_overlap', consistency: 1 },
            { evidence_id: 'ip-1', category: 'infrastructure_overlap', consistency: 2 },
          ],
        }],
        recommendations: [],
      },
    }) as NonNullable<ReturnType<typeof engineAnswer>>;
    // A continuation: the earlier run numbered a source 2, the current run has no source 2.
    const evidence = mirrorEvidence([], engine).map((item) => (item.n === 2 ? { ...item, investigation_id: 'inv-0' } : item));
    const allowed = buildAllowedIds(context);
    evidence.forEach((item) => allowed.evidence.add(item.id));
    const candidateInfo = new Map([['apt28', { name: 'APT28', entity_type: 'Intrusion-Set', standard_id: 'intrusion-set--28' }]]);
    const grounded = groundConclusion(engine.conclusion, allowed, candidateInfo, evidence, engine.id);
    expect(grounded.hypotheses[0].evidence.map((cell) => cell.evidence_id)).toEqual(['ip-1']);
    expect(grounded.dropped).toBe(1);
  });

  it('maps recommendations on OpenCTI actions, behind an approval when they act on the case or reach people', () => {
    const engine = engineAnswer() as NonNullable<ReturnType<typeof engineAnswer>>;
    const grounded = groundConclusion(engine.conclusion, buildAllowedIds(context), new Map(), [], engine.id);
    const [task, coa, invented, notify, escalate] = grounded.recommendations;
    expect(task).toMatchObject({
      action_kind: InvestigationRecommendationActionKind.Task,
      priority: InvestigationRecommendationPriority.P2,
      status: InvestigationRecommendationStatus.Proposed,
    });
    expect(coa).toMatchObject({ action_kind: InvestigationRecommendationActionKind.CourseOfAction, course_of_action_id: 'coa-1', priority: InvestigationRecommendationPriority.P3 });
    expect(invented).toMatchObject({ action_kind: InvestigationRecommendationActionKind.Task, course_of_action_id: null });
    expect(notify).toMatchObject({
      action_kind: InvestigationRecommendationActionKind.Notification,
      approval_required: true,
      status: InvestigationRecommendationStatus.AwaitingApproval,
    });
    expect(escalate).toMatchObject({ action_kind: InvestigationRecommendationActionKind.SeverityChange, severity: 'critical', approval_required: true, priority: InvestigationRecommendationPriority.P1 });
    expect(groundConclusion(null, buildAllowedIds(context), new Map(), [], 'inv-1')).toEqual({ summary: null, hypotheses: [], recommendations: [], dropped: 0 });
  });
});

describe('Case Autopilot knowledge list', () => {
  it('keeps typed observables, relationships between them and notes on them only', () => {
    const knowledge = parseEngineKnowledge({
      observables: [{ type: 'Domain-Name', value: 'Evil.Example' }, { type: 'IPv4-Addr', value: '185.12.4.2' }, { type: 'Malware', value: 'x' }],
      relationships: [['evil.example', '185.12.4.2', 'resolves-to', 'passive DNS'], { from: 'evil.example', to: 'other.example', type: 'resolves-to' }, { from: 'evil.example', to: '185.12.4.2', type: 'targets' }],
      notes: [['evil.example', 'Newsroom fingerprint matched'], { value: 'ghost.example', content: 'x' }],
    });
    expect(knowledge.observables).toEqual([{ type: 'Domain-Name', value: 'evil.example' }, { type: 'IPv4-Addr', value: '185.12.4.2' }]);
    expect(knowledge.relationships).toEqual([{ from: 'evil.example', to: '185.12.4.2', type: 'resolves-to', description: 'passive DNS' }]);
    expect(knowledge.notes).toEqual([{ value: 'evil.example', content: 'Newsroom fingerprint matched' }]);
    expect(parseEngineKnowledge(null)).toEqual({ observables: [], relationships: [], notes: [] });
  });

  it('keeps the case of a URL path and query, which carry meaning, and matches it without case', () => {
    const knowledge = parseEngineKnowledge({
      observables: [{ type: 'Url', value: 'HTTPS://Login.Example.com/CaseA?Token=X' }, { type: 'Domain-Name', value: 'Login.Example.com' }],
      relationships: [['https://login.example.com/casea?token=x', 'login.example.com', 'related-to']],
      notes: [['https://login.example.com/CaseA?Token=X', 'Credential harvesting page']],
    });
    expect(knowledge.observables).toEqual([{ type: 'Url', value: 'https://login.example.com/CaseA?Token=X' }, { type: 'Domain-Name', value: 'login.example.com' }]);
    expect(knowledge.relationships).toEqual([{ from: 'https://login.example.com/CaseA?Token=X', to: 'login.example.com', type: 'related-to', description: null }]);
    expect(knowledge.notes).toEqual([{ value: 'https://login.example.com/CaseA?Token=X', content: 'Credential harvesting page' }]);
    expect(canonicalObservableValue('Url', 'not a url')).toBe('not a url');
  });
});
