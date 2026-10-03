import { describe, expect, it } from 'vitest';
import {
  InvestigationEvidenceCategory,
  InvestigationPlanStepKind,
  InvestigationRecommendationActionKind,
  InvestigationRecommendationPriority,
  InvestigationRecommendationStatus,
  InvestigationRunPhase,
} from '../../../../src/generated/graphql';
import {
  agentPhaseFor,
  buildAgentRequest,
  buildAllowedIds,
  groundAgentResponse,
  parseAgentResponse,
  type InvestigationAgentContext,
} from '../../../../src/modules/investigationRun/investigationRun-agent';
import { INVESTIGATION_LIMITS, INVESTIGATION_REQUEST_SCHEMA } from '../../../../src/modules/investigationRun/investigationRun-types';
import { buildRun } from './investigationRun-fixtures';

const context: InvestigationAgentContext = {
  subject: { id: 'incident-1', standard_id: 'incident--1', entity_type: 'Incident', name: 'Phishing wave' },
  entities: [
    { id: 'domain-1', standard_id: 'domain-name--1', entity_type: 'Domain-Name', name: 'evil.example' },
    { id: 'ip-1', entity_type: 'IPv4-Addr', name: '185.12.4.2' },
  ],
  relationships: [{ id: 'rel-1', relationship_type: 'resolves-to', from_id: 'domain-1', to_id: 'ip-1' }],
  candidates: [{ id: 'apt28', standard_id: 'intrusion-set--28', entity_type: 'Intrusion-Set', name: 'APT28' }],
  courses_of_action: [{ id: 'coa-1', name: 'Block newly registered domains' }],
  pir: [],
  connectors: [{ id: 'connector-vt', name: 'VirusTotal', scope: ['Domain-Name'], requires_approval: true }],
  allowed_actions: ['enrichment'],
};

const candidateInfo = new Map([['apt28', { name: 'APT28', entity_type: 'Intrusion-Set', standard_id: 'intrusion-set--28' }]]);

describe('Case Autopilot agent contract', () => {
  it('maps run phases to agent phases', () => {
    expect(agentPhaseFor(InvestigationRunPhase.Planning)).toBe('plan');
    expect(agentPhaseFor(InvestigationRunPhase.Iterating)).toBe('iterate');
    expect(agentPhaseFor(InvestigationRunPhase.Concluding)).toBe('conclude');
  });

  it('builds a self-contained JSON request with the allowed ids', () => {
    const allowed = buildAllowedIds(context);
    const request = JSON.parse(buildAgentRequest(buildRun(), 'plan', context, { new_entity_ids: [], new_relationship_ids: [], enrichments: [] }, allowed, 42.25));
    expect(request.schema).toBe(INVESTIGATION_REQUEST_SCHEMA);
    expect(request.phase).toBe('plan');
    expect(request.budget.remaining_minutes).toBe(42.3);
    expect(request.allowed_ids.evidence).toEqual(expect.arrayContaining(['incident-1', 'domain-1', 'ip-1', 'rel-1']));
    expect(request.allowed_ids.candidates).toEqual(['apt28']);
    expect(request.allowed_ids.connectors).toEqual(['connector-vt']);
    expect(request.policy.enrichment_connectors[0].requires_approval).toBe(true);
  });

  it('parses strict JSON, fenced JSON and JSON wrapped in prose', () => {
    expect(parseAgentResponse('{"done": true}')).toEqual({ done: true });
    expect(parseAgentResponse('```json\n{"done": false}\n```')).toEqual({ done: false });
    expect(parseAgentResponse('Here is the result: {"summary": "ok"} hope it helps')).toEqual({ summary: 'ok' });
    expect(parseAgentResponse('no json at all')).toBeNull();
    expect(parseAgentResponse('[1, 2]')).toBeNull();
    expect(parseAgentResponse(null)).toBeNull();
  });

  it('drops every id the agent was not given and accepts standard ids', () => {
    const allowed = buildAllowedIds(context);
    const grounded = groundAgentResponse({
      enrichment_requests: [
        { entity_id: 'domain-name--1', connector_id: 'connector-vt', reason: 'reputation' },
        { entity_id: 'domain-1', connector_id: 'connector-vendor', reason: 'not allowed' },
        { entity_id: 'unknown', connector_id: 'connector-vt' },
        { entity_id: 'domain-1', connector_id: 'connector-vt' },
      ],
      hypotheses: [
        {
          candidate_id: 'intrusion-set--28',
          candidate_name: 'Made up name',
          evidence: [
            { evidence_id: 'ip-1', category: 'infrastructure_overlap', consistency: 5, rationale: 'shared C2' },
            { evidence_id: 'ghost', category: 'tooling', consistency: 1 },
            { evidence_id: 'rel-1', category: 'not_a_category', consistency: 1 },
          ],
        },
        { candidate_id: 'apt99', evidence: [] },
      ],
    }, allowed, candidateInfo);
    expect(grounded.enrichment_requests).toEqual([{ entity_id: 'domain-1', connector_id: 'connector-vt', reason: 'reputation' }]);
    expect(grounded.hypotheses).toHaveLength(1);
    expect(grounded.hypotheses[0].candidate_id).toBe('apt28');
    // Names come from the graph, never from the agent.
    expect(grounded.hypotheses[0].candidate_name).toBe('APT28');
    expect(grounded.hypotheses[0].evidence).toEqual([
      { evidence_id: 'ip-1', category: InvestigationEvidenceCategory.InfrastructureOverlap, consistency: 2, rationale: 'shared C2' },
    ]);
    expect(grounded.dropped).toBe(6);
  });

  it('normalizes the plan and caps its size', () => {
    const allowed = buildAllowedIds(context);
    const plan = Array.from({ length: 30 }, (_, index) => ({ id: index === 1 ? 's1' : `s${index}`, kind: index === 0 ? 'ENRICHMENT' : 'dance', description: `step ${index}` }));
    const grounded = groundAgentResponse({ plan: [...plan, { kind: 'pivot' }] }, allowed, candidateInfo);
    expect(grounded.plan).toHaveLength(INVESTIGATION_LIMITS.planSteps);
    expect(grounded.plan[0].kind).toBe(InvestigationPlanStepKind.Enrichment);
    expect(grounded.plan[2].kind).toBe(InvestigationPlanStepKind.Pivot);
    expect(new Set(grounded.plan.map((step) => step.id)).size).toBe(grounded.plan.length);
  });

  it('gates sensitive recommendations and grounds courses of action', () => {
    const allowed = buildAllowedIds(context);
    const grounded = groundAgentResponse({
      recommendations: [
        { id: 'r1', text: 'Raise the case severity', action_kind: 'severity_change', severity: 'HIGH', priority: 'P1' },
        { id: 'r2', text: 'Apply mitigation', action_kind: 'course_of_action', course_of_action_id: 'coa-1' },
        { id: 'r3', text: 'Apply a made up mitigation', action_kind: 'course_of_action', course_of_action_id: 'coa-unknown' },
        { id: 'r4', text: 'Share with the CERT', action_kind: 'sharing', approval_required: false },
        { id: 'r5', text: 'Severity without target', action_kind: 'severity_change' },
        { text: '' },
      ],
      summary: 'Summary',
      done: true,
    }, allowed, candidateInfo);
    const [r1, r2, r3, r4, r5] = grounded.recommendations;
    expect(grounded.recommendations).toHaveLength(5);
    expect(r1).toMatchObject({ action_kind: InvestigationRecommendationActionKind.SeverityChange, severity: 'high', approval_required: true, status: InvestigationRecommendationStatus.AwaitingApproval, priority: InvestigationRecommendationPriority.P1 });
    expect(r2).toMatchObject({ action_kind: InvestigationRecommendationActionKind.CourseOfAction, course_of_action_id: 'coa-1', approval_required: false, status: InvestigationRecommendationStatus.Proposed });
    expect(r3).toMatchObject({ action_kind: InvestigationRecommendationActionKind.Task, course_of_action_id: null });
    expect(r4).toMatchObject({ action_kind: InvestigationRecommendationActionKind.Sharing, approval_required: true });
    expect(r5).toMatchObject({ action_kind: InvestigationRecommendationActionKind.Task, severity: null });
    expect(grounded.summary).toBe('Summary');
    expect(grounded.done).toBe(true);
  });

  it('caps the number of hypotheses and truncates long texts', () => {
    const allowed = buildAllowedIds({
      ...context,
      candidates: Array.from({ length: 10 }, (_, index) => ({ id: `c${index}`, entity_type: 'Intrusion-Set', name: `C${index}` })),
    });
    const grounded = groundAgentResponse({
      hypotheses: Array.from({ length: 10 }, (_, index) => ({ candidate_id: `c${index}`, rationale: 'x'.repeat(10000), evidence: [] })),
      summary: 'y'.repeat(INVESTIGATION_LIMITS.summaryLength + 100),
    }, allowed, new Map());
    expect(grounded.hypotheses).toHaveLength(INVESTIGATION_LIMITS.hypotheses);
    expect(grounded.hypotheses[0].rationale?.length).toBe(4000);
    expect(grounded.summary?.length).toBe(INVESTIGATION_LIMITS.summaryLength);
  });
});
