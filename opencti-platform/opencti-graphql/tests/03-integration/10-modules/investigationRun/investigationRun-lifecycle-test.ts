import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../../utils/testQueryHelper';
import { v4 as uuid } from 'uuid';
import { ADMIN_USER, getAuthUser, getUserIdByEmail, testContext, USER_EDITOR, USER_PARTICIPATE } from '../../../utils/testQuery';
import { connectorDelete, registerConnector } from '../../../../src/domain/connector';
import { createWork, updateProcessedTime } from '../../../../src/domain/work';
import { ConnectorType, InvestigationEvidenceKind, InvestigationRunPhase, InvestigationRunStatus, InvestigationRunTrigger } from '../../../../src/generated/graphql';
import { MARKING_TLP_AMBER, MARKING_TLP_RED } from '../../../../src/schema/identifier';
import {
  addInvestigationRun,
  cancelInvestigationRun,
  decideInvestigationApprovals,
  findInvestigationRunsWithheldReasons,
  findServedInvestigationRuns,
  loadInvestigationRun,
  updateInvestigationRun,
} from '../../../../src/modules/investigationRun/investigationRun-domain';
import { addMalware } from '../../../../src/domain/malware';
import * as reportDomain from '../../../../src/domain/report';
import * as stixCoreObjectDomain from '../../../../src/domain/stixCoreObject';
import { DatabaseError } from '../../../../src/config/errors';
import { internalLoadById } from '../../../../src/database/middleware-loader';
import { stixLoadById, stixLoadByIds } from '../../../../src/database/middleware';
import { INVESTIGATION_MANAGER_USER } from '../../../../src/utils/access';
import { RELATION_OBJECT_MARKING } from '../../../../src/schema/stixRefRelationship';
import { statusTransition, VALIDATION_TIMEOUT_MS } from '../../../../src/modules/investigationRun/investigationRun-state';
import * as investigationRunDomain from '../../../../src/modules/investigationRun/investigationRun-domain';
import { DRAFT_VALIDATION_CONNECTOR } from '../../../../src/modules/draftWorkspace/draftWorkspace-connector';
import { runCitedIds } from '../../../../src/modules/investigationRun/investigationRun-utils';
import type { BasicStoreEntityInvestigationRun } from '../../../../src/modules/investigationRun/investigationRun-types';
import * as entrepriseEdition from '../../../../src/enterprise-edition/ee';
import * as aiAgentShared from '../../../../src/modules/playbook/components/ai-agent-shared';
import * as investigationXtm from '../../../../src/modules/investigationRun/investigationRun-xtm';
import * as draftWorkspaceDomain from '../../../../src/modules/draftWorkspace/draftWorkspace-domain';
import { parseEngineInvestigation } from '../../../../src/modules/investigationRun/investigationRun-engine';
import investigationRunResolvers from '../../../../src/modules/investigationRun/investigationRun-resolvers';
import { computeLoaders } from '../../../../src/http/httpAuthenticatedContext';
import {
  listAwaitingInvestigationRunsToRevalidate,
  listInvestigationRunsToProcess,
  processInvestigationRun,
  revalidateAwaitingInvestigationRun,
} from '../../../../src/modules/investigationRun/investigationRun-executor';

// A faithful stand-in for the XTM One investigation engine: raw answers in the
// shape of `GET /api/v1/platform/investigations/{id}` (dev-docs/investigations.md
// of XTM One), read by OpenCTI's own parser, so only the HTTP transport is mocked.
const ENGINE_ID = 'inv-e2e-1';

const GOAL_PLAN = {
  objective: 'Investigate {value}',
  reachable: true,
  actions: [
    { slug: 'context_read', label: 'Read the case' },
    { slug: 'known_checked', label: 'Check what OpenCTI already knows' },
    { slug: 'enriched', label: 'Enrich through OpenCTI connectors' },
    { slug: 'hypotheses_weighed', label: 'Weigh the hypotheses', produces_conclusion: true },
    { slug: 'reported', label: 'Write the cited report', produces_report: true },
  ],
};

interface Fixture {
  caseId: string;
  intrusionSetId: string;
  ipId: string;
  ipValue: string;
}

const engineState = (fixture: Fixture, stage: 'planning' | 'running' | 'completed') => {
  const planned = GOAL_PLAN.actions.map((action, index) => ({
    step_id: `${ENGINE_ID}:${index}`,
    position: index,
    action: action.slug,
    source_name: action.label,
    step_status: 'pending',
  }));
  if (stage === 'planning') {
    return { id: ENGINE_ID, investigation_id: ENGINE_ID, status: 'planning', revision: 0, goal_plan: GOAL_PLAN, steps: planned, evidence: [] };
  }
  const caseContextEvidence = {
    n: 1,
    kind: 'opencti_object',
    label: fixture.ipValue,
    opencti_id: fixture.ipId,
    entity_type: 'IPv4-Addr',
  };
  if (stage === 'running') {
    return {
      id: ENGINE_ID,
      status: 'running',
      revision: 1,
      goal_plan: GOAL_PLAN,
      steps: [
        { ...planned[0], step_status: 'completed', detail_code: 'source.case_context', findings_count: 2, evidence: [caseContextEvidence] },
        { ...planned[1], step_status: 'active' },
        ...planned.slice(2),
      ],
      evidence: [caseContextEvidence],
    };
  }
  return {
    id: ENGINE_ID,
    status: 'completed',
    revision: 2,
    goal_plan: GOAL_PLAN,
    steps: [
      { ...planned[0], step_status: 'completed', detail_code: 'source.case_context', findings_count: 2, evidence: [caseContextEvidence] },
      { ...planned[1], step_status: 'empty', detail_code: 'source.opencti_none_known' },
      { ...planned[2], step_status: 'empty', detail_code: 'source.enrichment_nothing_to_enrich' },
      { ...planned[3], step_status: 'completed', detail_code: 'source.conclusion_written', findings_count: 1 },
      { ...planned[4], step_status: 'completed', findings_count: 1 },
    ],
    evidence: [
      caseContextEvidence,
      { n: 2, kind: 'url', label: 'Vendor write-up', href: 'https://vendor.example/report', quote: 'The C2 server belongs to the operator.' },
    ],
    conclusion: {
      summary: 'The intrusion set of the case most likely operates the infrastructure.',
      hypotheses: [{
        candidate_id: fixture.intrusionSetId,
        rationale: 'Shared command and control infrastructure.',
        evidence: [
          { evidence_id: fixture.ipId, category: 'infrastructure_overlap', consistency: 2, rationale: 'The C2 address is in the case.' },
          { evidence_id: 'cite:2', category: 'ttp_overlap', consistency: 1, rationale: 'Same tradecraft.' },
        ],
      }],
      recommendations: [
        { id: 'r1', text: `Block ${fixture.ipValue} at the proxy`, action_kind: 'task', priority: 'P1', rationale: 'Active C2.' },
        { id: 'r2', text: 'Raise the severity of the case', action_kind: 'severity_change', severity: 'high', priority: 'P2' },
      ],
    },
    report: 'The intrusion set operates the C2 server [2].',
    report_status: 'written',
    report_sources: [{ n: 2, label: 'Vendor write-up', href: 'https://vendor.example/report' }],
    knowledge: { observables: [], relationships: [], notes: [] },
    iterations_used: 3,
    completed_at: new Date().toISOString(),
  };
};

const engineAnswer = (raw: unknown) => {
  const value = parseEngineInvestigation(raw);
  if (!value) throw new Error('The stand-in engine answer must be a valid engine run');
  return { ok: true as const, value };
};

const CREATE_INTRUSION_SET = gql`
  mutation IntrusionSetAdd($input: IntrusionSetAddInput!) { intrusionSetAdd(input: $input) { id } }
`;
const CREATE_IP = gql`
  mutation ObservableAdd($value: String!) { stixCyberObservableAdd(type: "IPv4-Addr", IPv4Addr: { value: $value }) { id } }
`;
const CREATE_CASE = gql`
  mutation CaseIncidentAdd($input: CaseIncidentAddInput!) { caseIncidentAdd(input: $input) { id } }
`;
const DELETE_CASE = gql`mutation CaseIncidentDelete($id: ID!) { caseIncidentDelete(id: $id) }`;
const RESTRICT_CONTAINER = gql`
  mutation ContainerRestrict($id: ID!, $input: [MemberAccessInput!]) { containerEdit(id: $id) { editAuthorizedMembers(input: $input) { id } } }
`;
const MARK_SDO = gql`
  mutation SdoMark($id: ID!, $input: StixRefRelationshipAddInput!) { stixDomainObjectEdit(id: $id) { relationAdd(input: $input) { id } } }
`;
const UNMARK_SDO = gql`
  mutation SdoUnmark($id: ID!, $toId: StixRef!, $relationship_type: String!) {
    stixDomainObjectEdit(id: $id) { relationDelete(toId: $toId, relationship_type: $relationship_type) { id } }
  }
`;
const DELETE_SDO = gql`mutation SdoDelete($id: ID!) { stixDomainObjectEdit(id: $id) { delete } }`;
const DELETE_SCO = gql`mutation ScoDelete($id: ID!) { stixCyberObservableEdit(id: $id) { delete } }`;
const DELETE_DRAFT = gql`mutation DraftDelete($id: ID!) { draftWorkspaceDelete(id: $id) }`;
const DELETE_WORKSPACE = gql`mutation WorkspaceDelete($id: ID!) { workspaceDelete(id: $id) }`;

const RUN_ADD = gql`
  mutation RunAdd($subjectId: ID!) { investigationRunAdd(subjectId: $subjectId) { id run_status run_phase run_trigger case_id } }
`;
const RUN_ADD_WITH_POLICY = gql`
  mutation RunAddWithPolicy($subjectId: ID!, $policyId: ID) { investigationRunAdd(subjectId: $subjectId, policyId: $policyId) { id } }
`;
const POLICY_ADD = gql`mutation PolicyAdd($input: InvestigationPolicyAddInput!) { investigationPolicyAdd(input: $input) { id } }`;
const POLICY_DELETE = gql`mutation PolicyDelete($id: ID!) { investigationPolicyDelete(id: $id) }`;
const RUN_DELETE = gql`mutation RunDelete($id: ID!) { investigationRunDelete(id: $id) }`;
const RUN_CANCEL = gql`mutation RunCancel($id: ID!) { investigationRunCancel(id: $id) { id run_status run_phase } }`;
const RUN_FEEDBACK = gql`
  mutation RunFeedback($id: ID!, $input: InvestigationRunFeedbackInput!) {
    investigationRunFeedback(id: $id, input: $input) { id analyst_feedback { item_type item_ref decision } acceptance { hypotheses_accepted rate } }
  }
`;
const RUN_READ = gql`
  query RunRead($id: ID!) {
    investigationRun(id: $id) {
      id
      run_status
      run_phase
      end_reason_code
      pack_id
      agent_slug
      draft_id
      workspace_id
      xtm_investigation_id
      xtm_investigation_ids
      xtm_revision
      goal_plan
      subject_id
      subject { id }
      case_id
      case { id }
      steps { id action status detail_code findings_count evidence_count }
      evidence { id n kind label href quote opencti_id entity_type in_draft }
      hypotheses { candidate_id rank probability confidence confidence_label evidence { evidence_id category consistency } }
      recommendations { id text priority action_kind approval_required status }
      summary
      report
      report_sources { n label href }
      report_id
      budget { max_iterations used_iterations }
    }
  }
`;
const RUN_RECORDS = gql`
  query RunRecords($id: ID!) {
    investigationRun(id: $id) {
      id
      can_continue
      approvals { id kind status entity_id recommendation_id }
      enrichment_requests { id entity_id connector_id status }
      enrichment_entities { id entity_type name }
      policy { id }
      draft { id }
      runAs { id }
      acceptance { hypotheses_accepted rate }
      report_sections { report }
    }
  }
`;
const PIR_ADD = gql`mutation PirAdd($input: PirAddInput!) { pirAdd(input: $input) { id } }`;
const PIR_RESTRICT = gql`mutation PirRestrict($id: ID!, $input: [MemberAccessInput!]!) { pirEditAuthorizedMembers(id: $id, input: $input) { id } }`;
const PIR_DELETE = gql`mutation PirDelete($id: ID!) { pirDelete(id: $id) }`;
const RUN_IDENTITY = gql`query RunIdentity($id: ID!) { investigationRun(id: $id) { id policy { id } runAs { id } } }`;
const RUN_APPLY = gql`
  mutation RunApply($id: ID!, $recommendationId: String!, $mode: InvestigationRecommendationApplyMode!) {
    investigationRunRecommendationApply(id: $id, recommendationId: $recommendationId, mode: $mode) { id recommendations { id status task_id } }
  }
`;
const RUN_CONTINUE = gql`mutation RunContinue($id: ID!) { investigationRunContinue(id: $id) { id run_status } }`;
const RUN_ENRICH = gql`
  mutation RunEnrich($id: ID!, $input: InvestigationRunEnrichmentRequestInput!) {
    investigationRunEnrichmentRequest(id: $id, input: $input) { wave_id accepted { entity_id connector_id status } rejected { entity_id connector_id reason } }
  }
`;
const RUN_WAVE = gql`
  query RunWave($id: ID!, $waveId: ID!) {
    investigationRunEnrichmentWave(id: $id, waveId: $waveId) { id status jobs { entity_id connector_id status } delta { id } }
  }
`;
const RUN_ENRICHMENT_STATE = gql`
  query RunEnrichmentState($id: ID!) {
    investigationRun(id: $id) { id enrichment_requests { id entity_id status work_id } budget { used_enrichment_jobs } }
  }
`;
const CASE_LATEST_RUN = gql`
  query CaseLatestRun($id: String!) { caseIncident(id: $id) { id latestInvestigationRun { id run_status } } }
`;
const RUN_MARKINGS = gql`
  query RunMarkings($id: ID!) { investigationRun(id: $id) { id xtm_revision objectMarking { standard_id } } }
`;
const RUNS_OF_CASE = gql`
  query RunsOfCase($caseId: String) { investigationRuns(caseId: $caseId, first: 10) { edges { node { id run_status } } } }
`;

const readRun = async (id: string) => {
  const { data } = await queryAsAdminWithSuccess({ query: RUN_READ, variables: { id } });
  return data.investigationRun;
};

// One manager tick after the other, as investigationRunManager would run them.
const tickUntil = async (runId: string, done: (run: { run_status: string; run_phase: string }) => boolean, maxTicks = 10) => {
  for (let tick = 0; tick < maxTicks; tick += 1) {
    await processInvestigationRun(testContext, runId);
    const run = await readRun(runId);
    if (done(run)) return run;
  }
  return readRun(runId);
};

describe('Case Autopilot run lifecycle against the XTM One investigation engine', () => {
  const fixture: Fixture = { caseId: '', intrusionSetId: '', ipId: '', ipValue: '198.51.100.77' };
  const otherCase = { id: '' };
  const createdRuns: { id: string; draft_id?: string | null; workspace_id?: string | null }[] = [];
  let startBody: Record<string, unknown> | null = null;
  let startDraftId: string | null | undefined;
  let engineStage: 'planning' | 'running' | 'completed' = 'planning';

  beforeAll(async () => {
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
    vi.spyOn(aiAgentShared, 'isXtmOneConfigured').mockReturnValue(true);
    vi.spyOn(investigationXtm, 'resolveInvestigationAgent').mockResolvedValue('deep-investigation-agent');
    vi.spyOn(investigationXtm, 'startInvestigation').mockImplementation(async (_user, body, draftId) => {
      startBody = body;
      startDraftId = draftId;
      engineStage = 'planning';
      return engineAnswer(engineState(fixture, 'planning'));
    });
    vi.spyOn(investigationXtm, 'getInvestigation').mockImplementation(async () => engineAnswer(engineState(fixture, engineStage)));
    vi.spyOn(investigationXtm, 'cancelInvestigation').mockResolvedValue({ ok: true, value: true });
    vi.spyOn(investigationXtm, 'pushInvestigationFeedback').mockResolvedValue(true);
    const intrusionSet = await queryAsAdminWithSuccess({ query: CREATE_INTRUSION_SET, variables: { input: { name: 'Case Autopilot e2e intrusion set' } } });
    fixture.intrusionSetId = intrusionSet.data.intrusionSetAdd.id;
    const ip = await queryAsAdminWithSuccess({ query: CREATE_IP, variables: { value: fixture.ipValue } });
    fixture.ipId = ip.data.stixCyberObservableAdd.id;
    const caseIncident = await queryAsAdminWithSuccess({
      query: CREATE_CASE,
      variables: { input: { name: 'Case Autopilot e2e case', objects: [fixture.intrusionSetId, fixture.ipId] } },
    });
    fixture.caseId = caseIncident.data.caseIncidentAdd.id;
    const second = await queryAsAdminWithSuccess({ query: CREATE_CASE, variables: { input: { name: 'Case Autopilot e2e second case', objects: [fixture.ipId] } } });
    otherCase.id = second.data.caseIncidentAdd.id;
  });

  afterAll(async () => {
    for (let index = 0; index < createdRuns.length; index += 1) {
      const run = await readRun(createdRuns[index].id).catch(() => null);
      await queryAsAdmin({ query: RUN_DELETE, variables: { id: createdRuns[index].id } });
      if (run?.draft_id) await queryAsAdmin({ query: DELETE_DRAFT, variables: { id: run.draft_id } });
      if (run?.workspace_id) await queryAsAdmin({ query: DELETE_WORKSPACE, variables: { id: run.workspace_id } });
    }
    await queryAsAdmin({ query: DELETE_CASE, variables: { id: fixture.caseId } });
    await queryAsAdmin({ query: DELETE_CASE, variables: { id: otherCase.id } });
    await queryAsAdmin({ query: DELETE_SDO, variables: { id: fixture.intrusionSetId } });
    await queryAsAdmin({ query: DELETE_SCO, variables: { id: fixture.ipId } });
    vi.restoreAllMocks();
  });

  it('refuses to start a run for a user who cannot update knowledge', async () => {
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, { query: RUN_ADD, variables: { subjectId: fixture.caseId } });
  });

  it('refuses to start, for a user who can update but not enrich knowledge, a run whose policy runs enrichments', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: RUN_ADD, variables: { subjectId: fixture.caseId } });
  });

  it('refuses, on the internal launch path of playbooks, an identity that cannot run the enrichments of its policy', async () => {
    const editorId = await getUserIdByEmail(USER_EDITOR.email);
    await expect(addInvestigationRun(testContext, ADMIN_USER, fixture.caseId, null, { runAsUserId: editorId, trigger: InvestigationRunTrigger.Playbook }))
      .rejects.toThrow('must be allowed to enrich knowledge');
  });

  it('refuses a new case the investigation policy does not allow', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: POLICY_ADD, variables: { input: { name: 'Case Autopilot e2e without cases', allowed_actions: ['enrichment'] } } });
    const policyId = data.investigationPolicyAdd.id;
    try {
      // An observable is investigated inside a case: without a picked case, a new one is needed.
      const refused = await queryAsAdmin({ query: RUN_ADD_WITH_POLICY, variables: { subjectId: fixture.ipId, policyId } });
      expect(refused.errors?.[0]?.message).toContain('does not allow creating a case');
    } finally {
      await queryAsAdmin({ query: POLICY_DELETE, variables: { id: policyId } });
    }
  });

  it('runs a launch from the interface as the analyst who starts it, never as the identity its policy names for automatic investigations', async () => {
    const editorId = await getUserIdByEmail(USER_EDITOR.email);
    const created = await queryAsAdminWithSuccess({ query: CREATE_CASE, variables: { input: { name: 'Case Autopilot e2e manual identity case', objects: [fixture.ipId] } } });
    const caseId = created.data.caseIncidentAdd.id;
    const policy = await queryAsAdminWithSuccess({
      query: POLICY_ADD,
      variables: { input: { name: 'Case Autopilot e2e automatic identity', allowed_actions: ['create_note'], run_as_id: ADMIN_USER.id } },
    });
    const policyId = policy.data.investigationPolicyAdd.id;
    let runId = '';
    try {
      // The policy acts as the administrator for automatic investigations: an editor who starts one reads only what the editor can read.
      const launched = await queryAsUserWithSuccess(USER_EDITOR, { query: RUN_ADD_WITH_POLICY, variables: { subjectId: caseId, policyId } });
      runId = launched.data.investigationRunAdd.id;
      const identity = await queryAsAdminWithSuccess({ query: RUN_IDENTITY, variables: { id: runId } });
      expect(identity.data.investigationRun.policy.id).toBe(policyId);
      expect(identity.data.investigationRun.runAs.id).toBe(editorId);
    } finally {
      // Never processed: the run has no draft or graph yet. The runs of the suite start with the next test.
      if (runId) {
        await queryAsAdmin({ query: RUN_CANCEL, variables: { id: runId } });
        await queryAsAdmin({ query: RUN_DELETE, variables: { id: runId } });
      }
      await queryAsAdmin({ query: POLICY_DELETE, variables: { id: policyId } });
      await queryAsAdmin({ query: DELETE_CASE, variables: { id: caseId } });
    }
  });

  it('plans a run on the case and dedupes a second launch on the same subject', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: RUN_ADD, variables: { subjectId: fixture.caseId } });
    const run = data.investigationRunAdd;
    createdRuns.push({ id: run.id });
    expect(run).toMatchObject({ run_status: 'planned', run_phase: 'initializing', run_trigger: 'manual', case_id: fixture.caseId });
    const again = await queryAsAdminWithSuccess({ query: RUN_ADD, variables: { subjectId: fixture.caseId } });
    expect(again.data.investigationRunAdd.id).toBe(run.id);
  });

  it('starts the engine with the opencti.investigation.start/v1 body, scoped to the run draft', async () => {
    const runId = createdRuns[0].id;
    const run = await tickUntil(runId, (current) => current.run_phase === 'investigating');
    expect(run.run_status).toBe('running');
    expect(run.draft_id).toBeTruthy();
    expect(run.xtm_investigation_id).toBe(ENGINE_ID);
    expect(run.xtm_investigation_ids).toEqual([ENGINE_ID]);
    expect(run.agent_slug).toBe('deep-investigation-agent');
    expect(run.goal_plan).toMatchObject({ objective: 'Investigate {value}' });
    expect(startDraftId).toBe(run.draft_id);
    expect(startBody).toMatchObject({
      schema: 'opencti.investigation.start/v1',
      pack: 'opencti-case-investigation',
      agent_slug: 'deep-investigation-agent',
      subject: { opencti_id: fixture.caseId, entity_type: 'Case-Incident', name: 'Case Autopilot e2e case' },
      run: { id: runId, draft_id: run.draft_id, trigger: 'manual' },
    });
    const body = startBody as unknown as {
      budget: { max_iterations: number; max_minutes: number };
      context: { candidates: { id: string }[]; entities: { id: string }[] };
      allowed_ids: { candidates: string[]; evidence: string[] };
      continues_investigation_id: string | null;
    };
    expect(body.budget.max_iterations).toBeGreaterThan(0);
    expect(body.budget.max_minutes).toBeGreaterThan(0);
    expect(body.context.candidates.map((candidate) => candidate.id)).toContain(fixture.intrusionSetId);
    expect(body.allowed_ids.candidates).toContain(fixture.intrusionSetId);
    expect(body.allowed_ids.evidence).toContain(fixture.ipId);
    expect(body.continues_investigation_id).toBeNull();
  });

  it('mirrors the goal plan, the step states and the evidence while the engine runs', async () => {
    const runId = createdRuns[0].id;
    engineStage = 'running';
    const run = await tickUntil(runId, (current) => (current as unknown as { xtm_revision: number }).xtm_revision >= 1);
    expect(run.xtm_revision).toBe(1);
    expect(run.steps.map((step: { status: string }) => step.status)).toEqual(['completed', 'active', 'pending', 'pending', 'pending']);
    expect(run.steps[0]).toMatchObject({ action: 'context_read', detail_code: 'source.case_context', findings_count: 2, evidence_count: 1 });
    expect(run.evidence).toEqual([expect.objectContaining({ id: fixture.ipId, n: 1, kind: 'opencti_object', opencti_id: fixture.ipId, entity_type: 'IPv4-Addr' })]);
  });

  it('ingests the completed engine run into the draft: ACH-scored hypotheses, recommendations and the cited report', async () => {
    const runId = createdRuns[0].id;
    engineStage = 'completed';
    const run = await tickUntil(runId, (current) => current.run_status !== 'running');
    expect(run.run_status).toBe('awaiting_approval');
    expect(run.run_phase).toBe('awaiting_validation');
    expect(run.steps.map((step: { status: string }) => step.status)).toEqual(['completed', 'empty', 'empty', 'completed', 'completed']);
    expect(run.evidence.map((item: { kind: string }) => item.kind)).toEqual(['opencti_object', 'url']);
    expect(run.evidence[1]).toMatchObject({ n: 2, href: 'https://vendor.example/report', quote: 'The C2 server belongs to the operator.' });
    expect(run.hypotheses).toHaveLength(1);
    const [leading] = run.hypotheses;
    expect(leading.candidate_id).toBe(fixture.intrusionSetId);
    expect(leading.rank).toBe(1);
    expect(leading.confidence).toBe(Math.round(leading.probability * 100));
    expect(leading.confidence_label).toBeTruthy();
    expect(leading.evidence.map((cell: { category: string }) => cell.category)).toEqual(['infrastructure_overlap', 'ttp_overlap']);
    expect(run.recommendations).toEqual([
      expect.objectContaining({ id: 'r1', priority: 'P1', action_kind: 'task', approval_required: false, status: 'proposed' }),
      expect.objectContaining({ id: 'r2', action_kind: 'severity_change', approval_required: true, status: 'awaiting_approval' }),
    ]);
    expect(run.summary).toContain('most likely operates the infrastructure');
    expect(run.report).toContain('[2]');
    expect(run.report_sources).toEqual([{ n: 2, label: 'Vendor write-up', href: 'https://vendor.example/report' }]);
    expect(run.report_id).toBeTruthy();
    expect(run.case.id).toBe(fixture.caseId);
  });

  it('exposes the run on its case and stores the analyst feedback', async () => {
    const runId = createdRuns[0].id;
    const latest = await queryAsAdminWithSuccess({ query: CASE_LATEST_RUN, variables: { id: fixture.caseId } });
    expect(latest.data.caseIncident.latestInvestigationRun).toMatchObject({ id: runId, run_status: 'awaiting_approval' });
    const runs = await queryAsAdminWithSuccess({ query: RUNS_OF_CASE, variables: { caseId: fixture.caseId } });
    expect(runs.data.investigationRuns.edges.map((edge: { node: { id: string } }) => edge.node.id)).toEqual([runId]);
    const feedback = await queryAsAdminWithSuccess({
      query: RUN_FEEDBACK,
      variables: { id: runId, input: { item_type: 'hypothesis', item_ref: fixture.intrusionSetId, decision: 'accepted', comment: 'Confirmed by the SOC' } },
    });
    expect(feedback.data.investigationRunFeedback.analyst_feedback).toEqual([{ item_type: 'hypothesis', item_ref: fixture.intrusionSetId, decision: 'accepted' }]);
    expect(feedback.data.investigationRunFeedback.acceptance.hypotheses_accepted).toBe(1);
    expect(investigationXtm.pushInvestigationFeedback).toHaveBeenCalled();
  });

  it('keeps runs and policies out of the generic object lookup without the Enterprise Edition', async () => {
    const runId = createdRuns[0].id;
    const query = gql`query GenericRunLookup($id: String!) { stixObjectOrStixRelationship(id: $id) { ... on InvestigationRun { id } } }`;
    const withEdition = await queryAsAdminWithSuccess({ query, variables: { id: runId } });
    expect(withEdition.data.stixObjectOrStixRelationship).toMatchObject({ id: runId });
    // The raw STIX serialization of any object, by id: never a run, whose own
    // fields withhold what it derived; a policy only under the edition.
    const raw = gql`query GenericRunRaw($id: String!) { stix(id: $id) stixCoreObjectRaw(id: $id) }`;
    const policyId = (await loadInvestigationRun(testContext, runId))?.policy_id as string;
    expect(policyId).toBeTruthy();
    const rawRun = await queryAsAdminWithSuccess({ query: raw, variables: { id: runId } });
    expect(rawRun.data.stix || null).toBeNull();
    expect(rawRun.data.stixCoreObjectRaw || null).toBeNull();
    const rawPolicy = await queryAsAdminWithSuccess({ query: raw, variables: { id: policyId } });
    expect(rawPolicy.data.stix).toContain(policyId);
    expect(rawPolicy.data.stixCoreObjectRaw).toContain(policyId);
    // The same holds for the STIX loaders every export path shares (workbench refresh, playbooks, TAXII, streams).
    expect(await stixLoadById(testContext, ADMIN_USER, runId)).toBeNull();
    expect(JSON.stringify(await stixLoadById(testContext, ADMIN_USER, policyId))).toContain(policyId);
    expect((await stixLoadByIds(testContext, ADMIN_USER, [runId, policyId])).length).toBe(1);
    const edition = vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(false);
    try {
      const withoutEdition = await queryAsAdminWithSuccess({ query, variables: { id: runId } });
      expect(withoutEdition.data.stixObjectOrStixRelationship).toBeNull();
      const rawPolicyWithoutEdition = await queryAsAdminWithSuccess({ query: raw, variables: { id: policyId } });
      expect(rawPolicyWithoutEdition.data.stix || null).toBeNull();
      expect(rawPolicyWithoutEdition.data.stixCoreObjectRaw || null).toBeNull();
      expect(await stixLoadById(testContext, ADMIN_USER, policyId)).toBeNull();
      expect(await stixLoadByIds(testContext, ADMIN_USER, [runId, policyId])).toEqual([]);
      // The generic listing reads STIX objects and relationships only: never these internal types.
      const listing = gql`
        query GenericRunList($filters: FilterGroup) {
          stixObjectOrStixRelationships(first: 10, filters: $filters) { edges { node { ... on InvestigationRun { id } ... on InvestigationPolicy { id } } } }
        }
      `;
      const filters = { mode: 'and', filters: [{ key: 'entity_type', values: ['Investigation-Run', 'Investigation-Policy'] }], filterGroups: [] };
      const listed = await queryAsAdminWithSuccess({ query: listing, variables: { filters } });
      expect(listed.data.stixObjectOrStixRelationships.edges).toEqual([]);
    } finally {
      edition.mockResolvedValue(true);
    }
  });

  it('reads the records of a run and the objects they reference', async () => {
    const runId = createdRuns[0].id;
    const { data } = await queryAsAdminWithSuccess({ query: RUN_RECORDS, variables: { id: runId } });
    const record = data.investigationRun;
    expect(record.approvals.map((approval: { kind: string }) => approval.kind).sort()).toEqual(['draft_validation', 'recommendation']);
    expect(record.approvals.find((approval: { kind: string }) => approval.kind === 'recommendation')).toMatchObject({ recommendation_id: 'r2', status: 'pending' });
    expect(record.enrichment_requests).toEqual([]);
    // The sensitive recommendation names the case it changes.
    expect(record.enrichment_entities).toEqual([expect.objectContaining({ id: fixture.caseId, entity_type: 'Case-Incident' })]);
    expect(record.policy.id).toBeTruthy();
    expect(record.draft.id).toBeTruthy();
    expect(record.runAs.id).toBeTruthy();
    expect(record.can_continue).toBe(true);
    expect(record.acceptance.hypotheses_accepted).toBe(1);
    expect(record.report_sections.report).toContain('[2]');
  });

  it('applies a proposed recommendation as a task, once', async () => {
    const runId = createdRuns[0].id;
    const { data } = await queryAsAdminWithSuccess({ query: RUN_APPLY, variables: { id: runId, recommendationId: 'r1', mode: 'task' } });
    const applied = data.investigationRunRecommendationApply.recommendations.find((recommendation: { id: string }) => recommendation.id === 'r1');
    expect(applied.status).not.toBe('proposed');
    expect(applied.task_id).toBeTruthy();
    const again = await queryAsAdmin({ query: RUN_APPLY, variables: { id: runId, recommendationId: 'r1', mode: 'task' } });
    expect(again.errors?.[0]?.message).toContain('already handled');
    // The task is live knowledge: removed again, as the stream counters of the suite expect.
    await queryAsAdminWithSuccess({ query: gql`mutation TaskDelete($id: ID!) { taskDelete(id: $id) }`, variables: { id: applied.task_id } });
  });

  it('refuses to continue, for a user who can update but not enrich knowledge, a run whose policy runs enrichments', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: RUN_CONTINUE, variables: { id: createdRuns[0].id } });
  });

  it('continues an investigation whose draft waits, and writes its outputs again', async () => {
    const runId = createdRuns[0].id;
    const before = await readRun(runId);
    const { data } = await queryAsAdminWithSuccess({ query: RUN_CONTINUE, variables: { id: runId } });
    expect(data.investigationRunContinue.id).toBe(runId);
    await tickUntil(runId, (current) => current.run_phase === 'investigating');
    expect(startBody).toMatchObject({ continues_investigation_id: ENGINE_ID });
    engineStage = 'completed';
    const run = await tickUntil(runId, (current) => current.run_status === 'awaiting_approval');
    expect(run.run_status).toBe('awaiting_approval');
    expect(run.report_id).toBe(before.report_id);
    expect(run.hypotheses[0].candidate_id).toBe(fixture.intrusionSetId);
  });

  it('decides the approvals of a run: a sensitive recommendation, then the draft', async () => {
    const runId = createdRuns[0].id;
    const { data } = await queryAsAdminWithSuccess({ query: RUN_RECORDS, variables: { id: runId } });
    const pending = data.investigationRun.approvals.filter((approval: { status: string }) => approval.status === 'pending');
    const recommendation = pending.find((approval: { kind: string }) => approval.kind === 'recommendation');
    const draft = pending.find((approval: { kind: string }) => approval.kind === 'draft_validation');
    // Both rejected: the live case and the stream of the suite stay unchanged.
    const first = await decideInvestigationApprovals(testContext, ADMIN_USER, runId, [{ tool_call_id: recommendation.id, decision: 'reject', rejection_reason: 'The severity is already right' }]);
    expect(first.decided).toBe(1);
    const second = await decideInvestigationApprovals(testContext, ADMIN_USER, runId, [{ tool_call_id: draft.id, decision: 'reject', rejection_reason: 'Not enough evidence yet' }]);
    expect(second.decided).toBe(1);
    const after = await queryAsAdminWithSuccess({ query: RUN_RECORDS, variables: { id: runId } });
    const statuses = Object.fromEntries(after.data.investigationRun.approvals.map((approval: { id: string; status: string }) => [approval.id, approval.status]));
    expect(statuses[recommendation.id]).toBe('rejected');
    expect(statuses[draft.id]).toBe('rejected');
    const replay = await decideInvestigationApprovals(testContext, ADMIN_USER, runId, [{ tool_call_id: draft.id, decision: 'approve', rejection_reason: null }]);
    expect(replay.decided).toBe(0);
  });

  it('enriches only what the investigation is about, through the connectors of its policy', async () => {
    const connectorId = uuid();
    await registerConnector(testContext, ADMIN_USER, {
      id: connectorId, name: 'Case Autopilot e2e enrichment', type: ConnectorType.InternalEnrichment, scope: ['IPv4-Addr'], auto: false,
    });
    try {
      const { data } = await queryAsAdminWithSuccess({ query: RUN_ADD, variables: { subjectId: otherCase.id } });
      const runId = data.investigationRunAdd.id;
      createdRuns.push({ id: runId });
      await tickUntil(runId, (current) => current.run_phase === 'investigating');
      const request = await queryAsAdminWithSuccess({
        query: RUN_ENRICH,
        variables: { id: runId, input: { entity_ids: [fixture.ipId, fixture.intrusionSetId], connector_ids: [connectorId, 'unknown-connector'], reason: 'Check the address' } },
      });
      const result = request.data.investigationRunEnrichmentRequest;
      expect(result.accepted).toEqual([{ entity_id: fixture.ipId, connector_id: connectorId, status: 'queued' }]);
      expect(result.rejected).toEqual(expect.arrayContaining([
        { entity_id: fixture.intrusionSetId, connector_id: connectorId, reason: 'entity_not_in_scope' },
        { entity_id: fixture.ipId, connector_id: 'unknown-connector', reason: 'connector_not_allowed' },
      ]));
      const wave = await queryAsAdminWithSuccess({ query: RUN_WAVE, variables: { id: runId, waveId: result.wave_id } });
      expect(wave.data.investigationRunEnrichmentWave.jobs).toEqual([expect.objectContaining({ entity_id: fixture.ipId, connector_id: connectorId })]);
      const records = await queryAsAdminWithSuccess({ query: RUN_RECORDS, variables: { id: runId } });
      expect(records.data.investigationRun.enrichment_requests).toEqual([expect.objectContaining({ entity_id: fixture.ipId })]);
      expect(records.data.investigationRun.enrichment_entities).toEqual([expect.objectContaining({ id: fixture.ipId, entity_type: 'IPv4-Addr' })]);
      // The next tick dispatches the job to the connector, within the enrichment budget.
      await processInvestigationRun(testContext, runId);
      const dispatched = await queryAsAdminWithSuccess({ query: RUN_ENRICHMENT_STATE, variables: { id: runId } });
      const [job] = dispatched.data.investigationRun.enrichment_requests;
      expect(job).toMatchObject({ entity_id: fixture.ipId, status: 'dispatched' });
      expect(job.work_id).toBeTruthy();
      expect(dispatched.data.investigationRun.budget.used_enrichment_jobs).toBe(1);
      // Once the connector ends its work, the wave records what it brought into the draft.
      await updateProcessedTime(testContext, ADMIN_USER, job.work_id, 'Enrichment done');
      await processInvestigationRun(testContext, runId);
      const ended = await queryAsAdminWithSuccess({ query: RUN_ENRICHMENT_STATE, variables: { id: runId } });
      expect(ended.data.investigationRun.enrichment_requests).toEqual([expect.objectContaining({ id: job.id, status: 'completed' })]);
      const endedWave = await queryAsAdminWithSuccess({ query: RUN_WAVE, variables: { id: runId, waveId: result.wave_id } });
      expect(endedWave.data.investigationRunEnrichmentWave).toMatchObject({ status: 'completed', jobs: [expect.objectContaining({ status: 'completed' })] });
      expect(endedWave.data.investigationRunEnrichmentWave.delta).toEqual([]);
      await queryAsAdminWithSuccess({ query: RUN_CANCEL, variables: { id: runId } });
    } finally {
      await connectorDelete(testContext, ADMIN_USER, connectorId);
    }
  });

  it('cancels the engine run when an analyst cancels the investigation, until XTM One confirms it', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: RUN_ADD, variables: { subjectId: otherCase.id } });
    const runId = data.investigationRunAdd.id;
    createdRuns.push({ id: runId });
    await tickUntil(runId, (current) => current.run_phase === 'investigating');
    // A reader of the run without the update capability cannot cancel it.
    const reader = { ...ADMIN_USER, capabilities: [{ name: 'KNOWLEDGE' }] } as unknown as typeof ADMIN_USER;
    await expect(cancelInvestigationRun(testContext, reader, runId)).rejects.toThrow();
    expect((await loadInvestigationRun(testContext, runId))?.run_status).toBe('running');
    vi.mocked(investigationXtm.cancelInvestigation).mockResolvedValueOnce({ ok: false, failure: 'engine_unreachable', status: 503, message: 'XTM One is unreachable' });
    const cancelled = await queryAsAdminWithSuccess({ query: RUN_CANCEL, variables: { id: runId } });
    expect(cancelled.data.investigationRunCancel).toMatchObject({ run_status: 'cancelled', run_phase: 'done' });
    expect(investigationXtm.cancelInvestigation).toHaveBeenCalledWith(expect.anything(), ENGINE_ID);
    expect((await loadInvestigationRun(testContext, runId))?.xtm_status).toBe('cancel_pending');
    // Deleting the run asks XTM One again first: refused while the stop is not confirmed, the run kept.
    vi.mocked(investigationXtm.cancelInvestigation).mockResolvedValueOnce({ ok: false, failure: 'engine_unreachable', status: 503, message: 'XTM One is unreachable' });
    const refusedDeletion = await queryAsAdmin({ query: RUN_DELETE, variables: { id: runId } });
    expect(refusedDeletion.errors?.[0]?.message).toBe('XTM One has not confirmed yet that the engine run of this investigation stopped: try deleting it again in a moment');
    expect((await loadInvestigationRun(testContext, runId))?.xtm_status).toBe('cancel_pending');
    // Not confirmed by XTM One: the manager lists the run again and asks again.
    const toProcess = await listInvestigationRunsToProcess(testContext, 50);
    expect(toProcess.map((run) => run.internal_id)).toContain(runId);
    await processInvestigationRun(testContext, runId);
    expect((await loadInvestigationRun(testContext, runId))?.xtm_status).toBe('cancelled');
    expect((await listInvestigationRunsToProcess(testContext, 50)).map((run) => run.internal_id)).not.toContain(runId);
  });

  it('cancels the engine run when the investigation fails while the engine runs it', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: RUN_ADD, variables: { subjectId: otherCase.id } });
    const runId = data.investigationRunAdd.id;
    createdRuns.push({ id: runId });
    await tickUntil(runId, (current) => current.run_phase === 'investigating');
    vi.mocked(investigationXtm.cancelInvestigation).mockClear();
    vi.mocked(investigationXtm.getInvestigation).mockRejectedValue(new Error('Unexpected engine answer'));
    try {
      const failed = await tickUntil(runId, (current) => current.run_status === 'failed');
      expect(failed.run_status).toBe('failed');
    } finally {
      vi.mocked(investigationXtm.getInvestigation).mockImplementation(async () => engineAnswer(engineState(fixture, engineStage)));
    }
    expect(investigationXtm.cancelInvestigation).toHaveBeenCalledWith(expect.anything(), ENGINE_ID);
    expect((await loadInvestigationRun(testContext, runId))?.xtm_status).toBe('cancelled');
  });

  it('ends with the engine reason, and no fallback loop, when XTM One does not run investigations', async () => {
    vi.mocked(investigationXtm.startInvestigation).mockResolvedValueOnce({ ok: false, failure: 'engine_disabled', status: 403, message: 'Deep Investigation is not enabled' });
    const { data } = await queryAsAdminWithSuccess({ query: RUN_ADD, variables: { subjectId: otherCase.id } });
    const runId = data.investigationRunAdd.id;
    createdRuns.push({ id: runId });
    const run = await tickUntil(runId, (current) => current.run_status === 'failed');
    expect(run).toMatchObject({ run_status: 'failed', end_reason_code: 'engine_disabled' });
    expect(run.xtm_investigation_id).toBeNull();
    expect(run.hypotheses).toEqual([]);
  });

  it('stops, withholds what it found and stops the engine run when its case becomes restricted to authorized members', async () => {
    const created = await queryAsAdminWithSuccess({ query: CREATE_CASE, variables: { input: { name: 'Case Autopilot e2e restricted case', objects: [fixture.ipId] } } });
    const caseId = created.data.caseIncidentAdd.id;
    try {
      const { data } = await queryAsAdminWithSuccess({ query: RUN_ADD, variables: { subjectId: caseId } });
      const runId = data.investigationRunAdd.id;
      createdRuns.push({ id: runId });
      await tickUntil(runId, (current) => current.run_phase === 'investigating');
      engineStage = 'running';
      const mirrored = await tickUntil(runId, (current) => (current as unknown as { xtm_revision: number }).xtm_revision >= 1);
      expect(mirrored.evidence).toHaveLength(1);
      expect(mirrored.draft_id).toBeTruthy();
      const reader = await getAuthUser(await getUserIdByEmail(USER_EDITOR.email));
      // One context per read, as one per request: what is withheld is read once per context.
      const requestContext = () => ({ ...testContext });
      expect(await draftWorkspaceDomain.findById(requestContext(), reader, mirrored.draft_id as string)).toBeTruthy();
      vi.mocked(investigationXtm.cancelInvestigation).mockClear();
      await queryAsAdminWithSuccess({ query: RESTRICT_CONTAINER, variables: { id: caseId, input: [{ id: ADMIN_USER.id, access_right: 'admin' }] } });
      engineStage = 'completed';
      // At the stop the restriction of the draft fails, then its first deletion fails: the run keeps its reference and
      // the manager retries both, in that order.
      const restriction = vi.spyOn(draftWorkspaceDomain, 'draftWorkspaceEditAuthorizedMembers').mockRejectedValueOnce(new Error('Draft store unavailable'));
      const deletion = vi.spyOn(draftWorkspaceDomain, 'deleteDraftWorkspace').mockRejectedValueOnce(new Error('Draft store unavailable'));
      const stopped = await tickUntil(runId, (current) => current.run_status !== 'running');
      expect(stopped).toMatchObject({
        run_status: 'failed',
        run_phase: 'done',
        end_reason_code: 'member_restricted',
        goal_plan: null,
        evidence: [],
        summary: null,
        report: null,
        report_sources: [],
        report_id: null,
        hypotheses: [],
        recommendations: [],
        // Kept on the stored run for the retry, never served from a withheld run.
        draft_id: null,
        workspace_id: null,
        // So is its engine run, which holds what it found; the stored run keeps it to stop it.
        xtm_investigation_id: null,
        xtm_investigation_ids: [],
        // Its case stays named for a member who can still read it.
        subject_id: caseId,
      });
      // A reader beyond the restriction is served no identifier of what it read.
      const restrictedRun = await loadInvestigationRun(testContext, runId);
      const runFields = investigationRunResolvers.InvestigationRun as unknown as Record<string, (run: unknown, args: unknown, context: unknown) => Promise<unknown>>;
      const editor = await getAuthUser(await getUserIdByEmail(USER_EDITOR.email));
      const editorContext = { ...testContext, user: editor, batch: computeLoaders(testContext, editor) };
      expect(restrictedRun?.subject_id).toBe(caseId);
      expect(await runFields.subject_id(restrictedRun, {}, editorContext)).toBeNull();
      expect(await runFields.subject(restrictedRun, {}, editorContext) ?? null).toBeNull();
      expect(await runFields.case_id(restrictedRun, {}, editorContext)).toBeNull();
      expect(await runFields.case(restrictedRun, {}, editorContext)).toBeNull();
      const draftId = mirrored.draft_id as string;
      expect((await loadInvestigationRun(testContext, runId))?.draft_id).toBe(draftId);
      const draftMembers = async () => ((await internalLoadById(testContext, ADMIN_USER, draftId)) as unknown as { restricted_members?: { id: string }[] })
        .restricted_members?.map((member) => member.id) ?? [];
      // Nothing is deleted under its old members while its restriction failed...
      expect(restriction).toHaveBeenCalled();
      expect(deletion).not.toHaveBeenCalled();
      expect(await draftMembers()).not.toEqual([INVESTIGATION_MANAGER_USER.id]);
      // ...and the draft is withheld from the stop on all the same: a reader who kept its id opens nothing, lists nothing,
      // counts nothing and, still one of its members, cannot give it new members (an edit returns the draft).
      expect(await draftWorkspaceDomain.findById(requestContext(), reader, draftId) ?? null).toBeNull();
      const listed = await draftWorkspaceDomain.findDraftWorkspacePaginated(requestContext(), reader, { first: 100 } as never);
      expect(listed.edges.map((edge: { node: { id: string } }) => edge.node.id)).not.toContain(draftId);
      const byId = { mode: 'and', filters: [{ key: ['id'], values: [draftId] }], filterGroups: [] };
      expect((await draftWorkspaceDomain.draftWorkspacesNumber(requestContext(), reader, { filters: byId })).count).toBe(0);
      restriction.mockRestore();
      await expect(draftWorkspaceDomain.draftWorkspaceEditAuthorizedMembers(requestContext(), reader, draftId, [{ id: reader.id, access_right: 'admin' }]))
        .rejects.toThrow('cannot be found');
      // The next pass restricts it to the manager, then its deletion fails: the run keeps its reference.
      await processInvestigationRun(testContext, runId);
      expect(deletion).toHaveBeenCalledTimes(1);
      expect(await draftMembers()).toEqual([INVESTIGATION_MANAGER_USER.id]);
      expect(await draftWorkspaceDomain.findById(requestContext(), reader, draftId) ?? null).toBeNull();
      expect((await loadInvestigationRun(testContext, runId))?.draft_id).toBe(draftId);
      expect(stopped.steps).toEqual([]);
      expect((await listInvestigationRunsToProcess(testContext, 50)).map((run) => run.internal_id)).toContain(runId);
      // Deleting the run deletes its draft first: refused while that fails, the run keeps its reference.
      deletion.mockRejectedValueOnce(new Error('Draft store unavailable'));
      const refusedDeletion = await queryAsAdmin({ query: RUN_DELETE, variables: { id: runId } });
      expect(refusedDeletion.errors?.[0]?.message).toBe('The draft or the investigation graph of this investigation could not be deleted yet: try deleting it again in a moment');
      expect((await loadInvestigationRun(testContext, runId))?.draft_id).toBe(mirrored.draft_id);
      await processInvestigationRun(testContext, runId);
      deletion.mockRestore();
      expect((await loadInvestigationRun(testContext, runId))?.draft_id ?? null).toBeNull();
      expect((await listInvestigationRunsToProcess(testContext, 50)).map((run) => run.internal_id)).not.toContain(runId);
      // The draft of the run is deleted with what it wrote there.
      const draft = await queryAsAdmin({ query: gql`query Draft($id: String!) { draftWorkspace(id: $id) { id } }`, variables: { id: mirrored.draft_id } });
      expect(draft.data?.draftWorkspace ?? null).toBeNull();
      expect(investigationXtm.cancelInvestigation).toHaveBeenCalledWith(expect.anything(), ENGINE_ID);
      expect((await loadInvestigationRun(testContext, runId))?.xtm_status).toBe('cancelled');
    } finally {
      await queryAsAdmin({ query: DELETE_CASE, variables: { id: caseId } });
    }
  });

  it('carries a marking added to its case after its draft copied the case', async () => {
    const created = await queryAsAdminWithSuccess({ query: CREATE_CASE, variables: { input: { name: 'Case Autopilot e2e marked case', objects: [fixture.ipId] } } });
    const caseId = created.data.caseIncidentAdd.id;
    const runMarkings = async (runId: string) => {
      const { data } = await queryAsAdminWithSuccess({ query: RUN_MARKINGS, variables: { id: runId } });
      return data.investigationRun.objectMarking.map((marking: { standard_id: string }) => marking.standard_id);
    };
    let runId = '';
    try {
      engineStage = 'planning';
      const { data } = await queryAsAdminWithSuccess({ query: RUN_ADD, variables: { subjectId: caseId } });
      runId = data.investigationRunAdd.id;
      createdRuns.push({ id: runId });
      await tickUntil(runId, (current) => current.run_phase === 'investigating');
      engineStage = 'running';
      await tickUntil(runId, (current) => (current as unknown as { xtm_revision: number }).xtm_revision >= 1);
      expect(await runMarkings(runId)).not.toContain(MARKING_TLP_AMBER);
      // The draft of the run holds the copy of the case it made at creation, without the marking.
      await queryAsAdminWithSuccess({ query: MARK_SDO, variables: { id: caseId, input: { toId: MARKING_TLP_AMBER, relationship_type: 'object-marking' } } });
      engineStage = 'completed';
      await tickUntil(runId, (current) => (current as unknown as { xtm_revision: number }).xtm_revision >= 2);
      expect(await runMarkings(runId)).toContain(MARKING_TLP_AMBER);
    } finally {
      // An active run cannot be deleted: cancelled here so that the suite deletes it with its marking.
      if (runId) await queryAsAdmin({ query: RUN_CANCEL, variables: { id: runId } });
      await queryAsAdmin({ query: DELETE_CASE, variables: { id: caseId } });
    }
  });

  it('stops an investigation waiting for approval once its case becomes restricted to authorized members', async () => {
    const created = await queryAsAdminWithSuccess({ query: CREATE_CASE, variables: { input: { name: 'Case Autopilot e2e reviewed case', objects: [fixture.ipId] } } });
    const caseId = created.data.caseIncidentAdd.id;
    let runId = '';
    try {
      engineStage = 'planning';
      const { data } = await queryAsAdminWithSuccess({ query: RUN_ADD, variables: { subjectId: caseId } });
      runId = data.investigationRunAdd.id;
      createdRuns.push({ id: runId });
      await tickUntil(runId, (current) => current.run_phase === 'investigating');
      engineStage = 'completed';
      const awaiting = await tickUntil(runId, (current) => current.run_status !== 'running', 15);
      expect(awaiting.run_status).toBe('awaiting_approval');
      expect(awaiting.draft_id).toBeTruthy();
      // Nothing moved: the run keeps waiting for the analyst.
      await revalidateAwaitingInvestigationRun(testContext, runId);
      expect((await readRun(runId)).run_status).toBe('awaiting_approval');
      const records = await queryAsAdminWithSuccess({ query: RUN_RECORDS, variables: { id: runId } });
      const draftGate = records.data.investigationRun.approvals.find((approval: { kind: string; status: string }) => approval.kind === 'draft_validation' && approval.status === 'pending');
      expect(draftGate).toBeTruthy();
      await queryAsAdminWithSuccess({ query: RESTRICT_CONTAINER, variables: { id: caseId, input: [{ id: ADMIN_USER.id, access_right: 'admin' }] } });
      expect((await listAwaitingInvestigationRunsToRevalidate(testContext, 50)).map((run) => run.internal_id)).toContain(runId);
      await revalidateAwaitingInvestigationRun(testContext, runId);
      expect(await readRun(runId)).toMatchObject({
        run_status: 'failed',
        end_reason_code: 'member_restricted',
        evidence: [],
        hypotheses: [],
        recommendations: [],
        summary: null,
        report: null,
        draft_id: null,
        workspace_id: null,
      });
      // Its gates are closed: nothing of an ended investigation can be approved any more.
      const closed = await queryAsAdminWithSuccess({ query: RUN_RECORDS, variables: { id: runId } });
      expect(closed.data.investigationRun.approvals.find((approval: { id: string }) => approval.id === draftGate.id)?.status).toBe('rejected');
      await expect(decideInvestigationApprovals(testContext, ADMIN_USER, runId, [{ tool_call_id: draftGate.id, decision: 'approve', rejection_reason: null }])).rejects.toThrow();
      const draft = await queryAsAdmin({ query: gql`query Draft($id: String!) { draftWorkspace(id: $id) { id } }`, variables: { id: awaiting.draft_id } });
      expect(draft.data?.draftWorkspace ?? null).toBeNull();
      expect((await listAwaitingInvestigationRunsToRevalidate(testContext, 50)).map((run) => run.internal_id)).not.toContain(runId);
    } finally {
      if (runId) await queryAsAdmin({ query: RUN_CANCEL, variables: { id: runId } });
      await queryAsAdmin({ query: DELETE_CASE, variables: { id: caseId } });
    }
  });

  it('refuses to cancel an investigation whose approved draft is validated, and stops it once its case becomes restricted to authorized members', async () => {
    const created = await queryAsAdminWithSuccess({ query: CREATE_CASE, variables: { input: { name: 'Case Autopilot e2e validated case', objects: [fixture.ipId] } } });
    const caseId = created.data.caseIncidentAdd.id;
    let runId = '';
    try {
      engineStage = 'planning';
      const { data } = await queryAsAdminWithSuccess({ query: RUN_ADD, variables: { subjectId: caseId } });
      runId = data.investigationRunAdd.id;
      createdRuns.push({ id: runId });
      await tickUntil(runId, (current) => current.run_phase === 'investigating');
      engineStage = 'completed';
      const awaiting = await tickUntil(runId, (current) => current.run_status !== 'running', 15);
      expect(awaiting.run_status).toBe('awaiting_approval');
      expect(awaiting.draft_id).toBeTruthy();
      // The run as an approval of its draft leaves it, without ingesting the draft into the live graph of the suite.
      const now = new Date();
      await updateInvestigationRun(testContext, runId, (current) => ({
        ...statusTransition(current, InvestigationRunStatus.Running, InvestigationRunPhase.Validating, now),
        validation_work_id: null,
        wave_started_at: now.toISOString(),
      }));
      // The approved changes are with the worker that writes them: the run keeps tracking that work.
      const refused = await queryAsAdmin({ query: RUN_CANCEL, variables: { id: runId } });
      expect(refused.errors?.[0]?.message).toBe('The approved changes of this investigation are being written to the case: it can no longer be cancelled');
      expect(await loadInvestigationRun(testContext, runId)).toMatchObject({ run_status: 'running', run_phase: 'validating' });
      await queryAsAdminWithSuccess({ query: RESTRICT_CONTAINER, variables: { id: caseId, input: [{ id: ADMIN_USER.id, access_right: 'admin' }] } });
      await processInvestigationRun(testContext, runId);
      expect(await readRun(runId)).toMatchObject({
        run_status: 'failed',
        end_reason_code: 'member_restricted',
        evidence: [],
        hypotheses: [],
        summary: null,
        report: null,
        draft_id: null,
        workspace_id: null,
      });
      const draft = await queryAsAdmin({ query: gql`query Draft($id: String!) { draftWorkspace(id: $id) { id } }`, variables: { id: awaiting.draft_id } });
      expect(draft.data?.draftWorkspace ?? null).toBeNull();
    } finally {
      if (runId) await queryAsAdmin({ query: RUN_CANCEL, variables: { id: runId } });
      await queryAsAdmin({ query: DELETE_CASE, variables: { id: caseId } });
    }
  });

  it('completes an investigation once the platform confirms its approved changes, and fails it when the platform reports errors or does not confirm them in time', async () => {
    const caseIds: string[] = [];
    // A run whose approved changes a validation work writes, without ingesting a draft into the live graph of the suite.
    const startValidating = async (name: string, startedAt: Date) => {
      const created = await queryAsAdminWithSuccess({ query: CREATE_CASE, variables: { input: { name, objects: [fixture.ipId] } } });
      caseIds.push(created.data.caseIncidentAdd.id);
      engineStage = 'planning';
      const { data } = await queryAsAdminWithSuccess({ query: RUN_ADD, variables: { subjectId: created.data.caseIncidentAdd.id } });
      const runId: string = data.investigationRunAdd.id;
      createdRuns.push({ id: runId });
      await tickUntil(runId, (current) => current.run_phase === 'investigating');
      const work = await createWork(testContext, ADMIN_USER, DRAFT_VALIDATION_CONNECTOR, `Draft validation ${name}`, DRAFT_VALIDATION_CONNECTOR.internal_id, { receivedTime: startedAt.toISOString() });
      if (!work) throw new Error(`No validation work created for ${name}`);
      await updateInvestigationRun(testContext, runId, (current) => ({
        ...statusTransition(current, InvestigationRunStatus.Running, InvestigationRunPhase.Validating, new Date()),
        validation_work_id: work.id,
        wave_started_at: startedAt.toISOString(),
      }));
      return { runId, workId: work.id as string };
    };
    try {
      // Confirmed: the run keeps validating while the work writes, and completes once it completes.
      const confirmed = await startValidating('Case Autopilot e2e confirmed validation case', new Date());
      await processInvestigationRun(testContext, confirmed.runId);
      expect(await loadInvestigationRun(testContext, confirmed.runId)).toMatchObject({ run_status: 'running', run_phase: 'validating' });
      await updateProcessedTime(testContext, ADMIN_USER, confirmed.workId, 'Draft validated');
      await processInvestigationRun(testContext, confirmed.runId);
      const completed = await loadInvestigationRun(testContext, confirmed.runId);
      expect(completed).toMatchObject({ run_status: 'completed', run_phase: 'done' });
      expect(completed?.end_reason_code ?? null).toBeNull();
      // Written with errors: the run fails and says what the platform reported.
      const partial = await startValidating('Case Autopilot e2e partial validation case', new Date());
      await updateProcessedTime(testContext, ADMIN_USER, partial.workId, 'Relationship not ingested', true);
      await processInvestigationRun(testContext, partial.runId);
      const failed = await loadInvestigationRun(testContext, partial.runId);
      expect(failed).toMatchObject({ run_status: 'failed', run_phase: 'done', end_reason_code: 'draft_validation_failed' });
      expect(failed?.status_reason).toContain('1 error(s)');
      expect(failed?.status_reason).toContain('Relationship not ingested');
      // Still being written once the bound passed: the run fails as not confirmed, never as completed.
      const late = await startValidating('Case Autopilot e2e unconfirmed validation case', new Date(Date.now() - VALIDATION_TIMEOUT_MS - 60 * 1000));
      await processInvestigationRun(testContext, late.runId);
      expect(await loadInvestigationRun(testContext, late.runId)).toMatchObject({ run_status: 'failed', run_phase: 'done', end_reason_code: 'draft_validation_unconfirmed' });
    } finally {
      for (let index = 0; index < caseIds.length; index += 1) {
        await queryAsAdmin({ query: DELETE_CASE, variables: { id: caseIds[index] } });
      }
    }
  });

  it('stops an investigation once an object the engine received as context, without citing it, becomes restricted to authorized members', async () => {
    // The second case of the suite, inside this case, reaches the engine as context; the engine never cites it.
    const created = await queryAsAdminWithSuccess({
      query: CREATE_CASE,
      variables: { input: { name: 'Case Autopilot e2e context case', objects: [fixture.ipId, otherCase.id] } },
    });
    const caseId = created.data.caseIncidentAdd.id;
    let runId = '';
    try {
      engineStage = 'planning';
      const { data } = await queryAsAdminWithSuccess({ query: RUN_ADD, variables: { subjectId: caseId } });
      runId = data.investigationRunAdd.id;
      createdRuns.push({ id: runId });
      await tickUntil(runId, (current) => current.run_phase === 'investigating');
      const started = await loadInvestigationRun(testContext, runId) as BasicStoreEntityInvestigationRun;
      expect(started.context_ids).toContain(otherCase.id);
      expect(runCitedIds(started)).not.toContain(otherCase.id);
      await queryAsAdminWithSuccess({ query: RESTRICT_CONTAINER, variables: { id: otherCase.id, input: [{ id: ADMIN_USER.id, access_right: 'admin' }] } });
      // Withheld on every read from now on, before the manager stops the run.
      expect(await readRun(runId)).toMatchObject({ run_status: 'running', end_reason_code: 'member_restricted', evidence: [] });
      await processInvestigationRun(testContext, runId);
      expect(await readRun(runId)).toMatchObject({
        run_status: 'failed',
        end_reason_code: 'member_restricted',
        evidence: [],
        summary: null,
        draft_id: null,
        workspace_id: null,
      });
    } finally {
      if (runId) await queryAsAdmin({ query: RUN_CANCEL, variables: { id: runId } });
      await queryAsAdmin({ query: DELETE_CASE, variables: { id: caseId } });
    }
  });

  it('withholds what it found and stops once a PIR of its context becomes restricted to authorized members', async () => {
    const created = await queryAsAdminWithSuccess({ query: CREATE_CASE, variables: { input: { name: 'Case Autopilot e2e PIR context case', objects: [fixture.ipId] } } });
    const caseId = created.data.caseIncidentAdd.id;
    const pir = await queryAsAdminWithSuccess({
      query: PIR_ADD,
      variables: {
        input: {
          name: 'Case Autopilot e2e PIR',
          pir_type: 'THREAT_LANDSCAPE',
          pir_rescan_days: 0,
          pir_filters: { mode: 'and', filterGroups: [], filters: [{ key: ['confidence'], values: ['80'], operator: 'gt' }] },
          // A criterion nothing of the suite matches: the PIR flags nothing while it exists.
          pir_criteria: [{ weight: 1, filters: { mode: 'and', filterGroups: [], filters: [{ key: ['toId'], values: [uuid()] }] } }],
        },
      },
    });
    const pirId = pir.data.pirAdd.id;
    let runId = '';
    try {
      engineStage = 'planning';
      const { data } = await queryAsAdminWithSuccess({ query: RUN_ADD, variables: { subjectId: caseId } });
      runId = data.investigationRunAdd.id;
      createdRuns.push({ id: runId });
      await tickUntil(runId, (current) => current.run_phase === 'investigating');
      // The PIR a candidate of the case matters to reaches the engine as context, readable by everyone.
      await updateInvestigationRun(testContext, runId, (current) => ({ context_ids: [...(current.context_ids ?? []), pirId] }));
      expect(await readRun(runId)).toMatchObject({ run_status: 'running', end_reason_code: null });
      await queryAsAdminWithSuccess({ query: PIR_RESTRICT, variables: { id: pirId, input: [{ id: ADMIN_USER.id, access_right: 'admin' }] } });
      // Withheld on every read from now on, before the manager stops the run.
      expect(await readRun(runId)).toMatchObject({ run_status: 'running', end_reason_code: 'member_restricted', evidence: [] });
      await processInvestigationRun(testContext, runId);
      expect(await readRun(runId)).toMatchObject({ run_status: 'failed', end_reason_code: 'member_restricted', draft_id: null, workspace_id: null });
    } finally {
      if (runId) await queryAsAdmin({ query: RUN_CANCEL, variables: { id: runId } });
      await queryAsAdmin({ query: PIR_DELETE, variables: { id: pirId } });
      await queryAsAdmin({ query: DELETE_CASE, variables: { id: caseId } });
    }
  });

  it('withholds what it found on every read path and refuses actions on it once its case is restricted, before the manager stops it', async () => {
    const created = await queryAsAdminWithSuccess({ query: CREATE_CASE, variables: { input: { name: 'Case Autopilot e2e withheld case', objects: [fixture.ipId] } } });
    const caseId = created.data.caseIncidentAdd.id;
    let runId = '';
    try {
      engineStage = 'planning';
      const { data } = await queryAsAdminWithSuccess({ query: RUN_ADD, variables: { subjectId: caseId } });
      runId = data.investigationRunAdd.id;
      createdRuns.push({ id: runId });
      await tickUntil(runId, (current) => current.run_phase === 'investigating');
      engineStage = 'completed';
      const awaiting = await tickUntil(runId, (current) => current.run_status !== 'running', 15);
      expect(awaiting.run_status).toBe('awaiting_approval');
      expect(awaiting.evidence.length).toBeGreaterThan(0);
      const before = await queryAsAdminWithSuccess({ query: RUN_RECORDS, variables: { id: runId } });
      const draftGate = before.data.investigationRun.approvals.find((approval: { kind: string }) => approval.kind === 'draft_validation');
      expect(before.data.investigationRun.approvals.some((approval: { kind: string }) => approval.kind === 'recommendation')).toBe(true);
      await queryAsAdminWithSuccess({ query: RESTRICT_CONTAINER, variables: { id: caseId, input: [{ id: ADMIN_USER.id, access_right: 'admin' }] } });
      // No manager pass: the run is still waiting, and what it found is already withheld.
      expect(await readRun(runId)).toMatchObject({
        run_status: 'awaiting_approval',
        end_reason_code: 'member_restricted',
        goal_plan: null,
        evidence: [],
        hypotheses: [],
        recommendations: [],
        summary: null,
        report: null,
        report_sources: [],
        report_id: null,
        xtm_investigation_id: null,
        xtm_investigation_ids: [],
        subject_id: caseId,
      });
      const records = await queryAsAdminWithSuccess({ query: RUN_RECORDS, variables: { id: runId } });
      expect(records.data.investigationRun.can_continue).toBe(false);
      expect(records.data.investigationRun.approvals.map((approval: { kind: string }) => approval.kind)).toEqual(['draft_validation']);
      expect(records.data.investigationRun.report_sections.report).toBe('No report was written.');
      const findings = 'evidence { id } summary report';
      const badge = await queryAsAdminWithSuccess({ query: gql`query Badge($id: String!) { caseIncident(id: $id) { latestInvestigationRun { id ${findings} } } }`, variables: { id: caseId } });
      expect(badge.data.caseIncident.latestInvestigationRun).toEqual({ id: runId, evidence: [], summary: null, report: null });
      const listed = await queryAsAdminWithSuccess({ query: gql`query Listed($caseId: String) { investigationRuns(caseId: $caseId, first: 10) { edges { node { id ${findings} } } } }`, variables: { caseId } });
      expect(listed.data.investigationRuns.edges.map((edge: { node: unknown }) => edge.node)).toEqual([{ id: runId, evidence: [], summary: null, report: null }]);
      const lookedUp = await queryAsAdminWithSuccess({ query: gql`query LookedUp($id: String!) { stixObjectOrStixRelationship(id: $id) { ... on InvestigationRun { id ${findings} } } }`, variables: { id: runId } });
      expect(lookedUp.data.stixObjectOrStixRelationship).toEqual({ id: runId, evidence: [], summary: null, report: null });
      // A subscription event carries the stored run: its fields are served the same way.
      const stored = await loadInvestigationRun(testContext, runId);
      expect(stored?.evidence.length).toBeGreaterThan(0);
      const runFields = investigationRunResolvers.InvestigationRun as unknown as Record<string, (run: unknown, args: unknown, context: unknown) => Promise<unknown>>;
      const eventContext = { ...testContext, user: ADMIN_USER, batch: computeLoaders(testContext, ADMIN_USER) };
      expect(await runFields.evidence(stored, {}, eventContext)).toEqual([]);
      expect(await runFields.summary(stored, {}, eventContext)).toBeNull();
      expect(await runFields.end_reason_code(stored, {}, eventContext)).toBe('member_restricted');
      expect(stored?.draft_id).toBeTruthy();
      expect(await runFields.draft_id(stored, {}, eventContext)).toBeNull();
      expect(await runFields.draft(stored, {}, eventContext)).toBeNull();
      expect(await runFields.xtm_investigation_ids(stored, {}, eventContext)).toEqual([]);
      expect(await runFields.subject_id(stored, {}, eventContext)).toBe(caseId);
      const outsider = await getAuthUser(await getUserIdByEmail(USER_EDITOR.email));
      const outsiderContext = { ...testContext, user: outsider, batch: computeLoaders(testContext, outsider) };
      expect(await runFields.subject_id(stored, {}, outsiderContext)).toBeNull();
      expect(await runFields.case_id(stored, {}, outsiderContext)).toBeNull();
      // Nothing it found can be acted on; cancelling stays possible.
      const feedback = await queryAsAdmin({
        query: RUN_FEEDBACK,
        variables: { id: runId, input: { item_type: 'hypothesis', item_ref: fixture.intrusionSetId, decision: 'accepted' } },
      });
      expect(feedback.errors?.[0]?.message).toContain('withheld');
      const applied = await queryAsAdmin({ query: RUN_APPLY, variables: { id: runId, recommendationId: 'r1', mode: 'task' } });
      expect(applied.errors?.[0]?.message).toContain('withheld');
      const continued = await queryAsAdmin({ query: RUN_CONTINUE, variables: { id: runId } });
      expect(continued.errors?.[0]?.message).toContain('withheld');
      await expect(decideInvestigationApprovals(testContext, ADMIN_USER, runId, [{ tool_call_id: draftGate.id, decision: 'approve', rejection_reason: null }]))
        .rejects.toThrow('withheld');
      expect((await loadInvestigationRun(testContext, runId))?.run_status).toBe('awaiting_approval');
      const cancelled = await queryAsAdminWithSuccess({ query: RUN_CANCEL, variables: { id: runId } });
      expect(cancelled.data.investigationRunCancel.run_status).toBe('cancelled');
    } finally {
      if (runId) await queryAsAdmin({ query: RUN_CANCEL, variables: { id: runId } });
      await queryAsAdmin({ query: DELETE_CASE, variables: { id: caseId } });
    }
  });

  it('withholds what it found from a reader who can no longer read an object it cites, and from that reader only', async () => {
    const created = await queryAsAdminWithSuccess({ query: CREATE_CASE, variables: { input: { name: 'Case Autopilot e2e marked source case', objects: [fixture.intrusionSetId, fixture.ipId] } } });
    const caseId = created.data.caseIncidentAdd.id;
    let runId = '';
    let marked = false;
    try {
      engineStage = 'planning';
      const { data } = await queryAsAdminWithSuccess({ query: RUN_ADD, variables: { subjectId: caseId } });
      runId = data.investigationRunAdd.id;
      createdRuns.push({ id: runId });
      await tickUntil(runId, (current) => current.run_phase === 'investigating');
      engineStage = 'completed';
      const awaiting = await tickUntil(runId, (current) => current.run_status !== 'running', 15);
      expect(awaiting.hypotheses.map((hypothesis: { candidate_id: string }) => hypothesis.candidate_id)).toContain(fixture.intrusionSetId);
      const editor = await getAuthUser(await getUserIdByEmail(USER_EDITOR.email));
      const stored = await loadInvestigationRun(testContext, runId) as BasicStoreEntityInvestigationRun;
      expect(await findInvestigationRunsWithheldReasons(testContext, editor, [stored])).toEqual([null]);
      // The cited intrusion set gets a marking the editor does not have, after the run read it.
      await queryAsAdminWithSuccess({ query: MARK_SDO, variables: { id: fixture.intrusionSetId, input: { toId: MARKING_TLP_RED, relationship_type: 'object-marking' } } });
      marked = true;
      expect(await findInvestigationRunsWithheldReasons(testContext, editor, [stored])).toEqual(['source_inaccessible']);
      expect(await findInvestigationRunsWithheldReasons(testContext, ADMIN_USER, [stored])).toEqual([null]);
      const runFields = investigationRunResolvers.InvestigationRun as unknown as Record<string, (run: unknown, args: unknown, context: unknown) => Promise<unknown>>;
      const editorContext = { ...testContext, user: editor, batch: computeLoaders(testContext, editor) };
      expect(await runFields.evidence(stored, {}, editorContext)).toEqual([]);
      expect(await runFields.hypotheses(stored, {}, editorContext)).toEqual([]);
      expect(await runFields.analyst_feedback(stored, {}, editorContext)).toEqual([]);
      expect(await runFields.end_reason_code(stored, {}, editorContext)).toBe('source_inaccessible');
      // The engine run, which holds what it found, is withheld; the case, which the editor still reads, stays named.
      expect(await runFields.xtm_investigation_id(stored, {}, editorContext)).toBeNull();
      expect(await runFields.subject_id(stored, {}, editorContext)).toBe(caseId);
      expect(await runFields.name(stored, {}, editorContext)).toBe('Case Autopilot');
      expect(await runFields.name(stored, {}, { ...testContext, user: ADMIN_USER, batch: computeLoaders(testContext, ADMIN_USER) })).toBe(stored.name);
      const adminContext = { ...testContext, user: ADMIN_USER, batch: computeLoaders(testContext, ADMIN_USER) };
      expect((await runFields.evidence(stored, {}, adminContext)) as unknown[]).not.toEqual([]);
      expect(await runFields.end_reason_code(stored, {}, adminContext)).toBeNull();
      expect(await runFields.subject_id(stored, {}, adminContext)).toBe(caseId);
      expect(await runFields.xtm_investigation_id(stored, {}, adminContext)).toBe(stored.xtm_investigation_id);
      // A status reason can carry error details of what the run did: withheld with the findings, the code says why.
      const failureDetail = 'Not written: the report (search engine unavailable)';
      const withDetail = { ...stored, status_reason: failureDetail };
      expect(await runFields.status_reason(withDetail, {}, editorContext)).toBeNull();
      expect(await runFields.status_reason(withDetail, {}, adminContext)).toBe(failureDetail);
      // The run copied the markings of what it read; it is served with those its sources carry now.
      const servedMarkings = await runFields.objectMarking(stored, {}, adminContext) as Array<{ standard_id: string }>;
      expect(servedMarkings.map((marking) => marking.standard_id)).toContain(MARKING_TLP_RED);
      // The stored run is unchanged: the findings are withheld when served, not erased.
      expect((await readRun(runId)).summary).toContain('most likely operates the infrastructure');
    } finally {
      if (marked) {
        await queryAsAdmin({ query: UNMARK_SDO, variables: { id: fixture.intrusionSetId, toId: MARKING_TLP_RED, relationship_type: 'object-marking' } });
      }
      if (runId) await queryAsAdmin({ query: RUN_CANCEL, variables: { id: runId } });
      await queryAsAdmin({ query: DELETE_CASE, variables: { id: caseId } });
    }
  });

  it('checks what exists only in its draft, such as an enrichment result, against the reader', async () => {
    const created = await queryAsAdminWithSuccess({ query: CREATE_CASE, variables: { input: { name: 'Case Autopilot e2e draft source case', objects: [fixture.intrusionSetId, fixture.ipId] } } });
    const caseId = created.data.caseIncidentAdd.id;
    let runId = '';
    try {
      engineStage = 'planning';
      const { data } = await queryAsAdminWithSuccess({ query: RUN_ADD, variables: { subjectId: caseId } });
      runId = data.investigationRunAdd.id;
      createdRuns.push({ id: runId });
      await tickUntil(runId, (current) => current.run_phase === 'investigating');
      engineStage = 'completed';
      await tickUntil(runId, (current) => current.run_status !== 'running', 15);
      const stored = await loadInvestigationRun(testContext, runId) as BasicStoreEntityInvestigationRun;
      expect(stored.draft_id).toBeTruthy();
      // A result an enrichment brought exists only in the run draft, here under a marking the editor does not have.
      const draftContext = { ...testContext, draft_context: stored.draft_id as string };
      const result = await addMalware(draftContext, ADMIN_USER, { name: 'Case Autopilot e2e draft-only result', objectMarking: [MARKING_TLP_RED] });
      const objectEvidence = stored.evidence.find((item) => item.kind === InvestigationEvidenceKind.OpenctiObject) as BasicStoreEntityInvestigationRun['evidence'][number];
      expect(objectEvidence).toBeDefined();
      const citing = {
        ...stored,
        evidence: [...stored.evidence, { ...objectEvidence, id: result.id, n: stored.evidence.length + 1, opencti_id: result.id, entity_type: 'Malware' }],
      } as BasicStoreEntityInvestigationRun;
      expect(runCitedIds(citing)).toContain(result.id);
      const editor = await getAuthUser(await getUserIdByEmail(USER_EDITOR.email));
      expect(await findInvestigationRunsWithheldReasons(testContext, editor, [stored])).toEqual([null]);
      expect(await findInvestigationRunsWithheldReasons(testContext, editor, [citing])).toEqual(['source_inaccessible']);
      expect(await findInvestigationRunsWithheldReasons(testContext, ADMIN_USER, [citing])).toEqual([null]);
      // Served with the marking of the draft-only result, so an export ceiling weighs it too.
      const tlpRed = await internalLoadById(testContext, ADMIN_USER, MARKING_TLP_RED);
      const [served] = await findServedInvestigationRuns(testContext, ADMIN_USER, [citing]);
      expect((served as unknown as Record<string, string[]>)[RELATION_OBJECT_MARKING]).toContain(tlpRed.internal_id);
    } finally {
      if (runId) await queryAsAdmin({ query: RUN_CANCEL, variables: { id: runId } });
      await queryAsAdmin({ query: DELETE_CASE, variables: { id: caseId } });
    }
  });

  it('retries an ingestion a transient failure interrupts, reusing the outputs it already wrote', async () => {
    const created = await queryAsAdminWithSuccess({ query: CREATE_CASE, variables: { input: { name: 'Case Autopilot e2e interrupted ingestion case', objects: [fixture.intrusionSetId, fixture.ipId] } } });
    const caseId = created.data.caseIncidentAdd.id;
    let runId = '';
    const reportWrite = vi.spyOn(reportDomain, 'addReport');
    try {
      engineStage = 'planning';
      const { data } = await queryAsAdminWithSuccess({ query: RUN_ADD, variables: { subjectId: caseId } });
      runId = data.investigationRunAdd.id;
      createdRuns.push({ id: runId });
      await tickUntil(runId, (current) => current.run_phase === 'investigating');
      engineStage = 'completed';
      // The report of the first ingestion pass meets a transient failure of the platform.
      reportWrite.mockRejectedValueOnce(DatabaseError('Search engine unavailable'));
      const interrupted = await tickUntil(runId, () => reportWrite.mock.calls.length > 0, 15);
      expect(interrupted.run_status).toBe('running');
      const checkpointed = await loadInvestigationRun(testContext, runId) as BasicStoreEntityInvestigationRun;
      expect(checkpointed.step_failures).toBe(1);
      expect(checkpointed.outputs.note_id).toBeTruthy();
      expect(checkpointed.outputs.report_id ?? null).toBeNull();
      // The next pass writes the report and edits the note the first one wrote, instead of writing it again.
      const ingested = await tickUntil(runId, (current) => current.run_status !== 'running', 5);
      expect(ingested.run_status).toBe('awaiting_approval');
      const stored = await loadInvestigationRun(testContext, runId) as BasicStoreEntityInvestigationRun;
      expect(stored.outputs.note_id).toBe(checkpointed.outputs.note_id);
      expect(stored.outputs.report_id).toBeTruthy();
      expect(stored.step_failures ?? 0).toBe(0);
      expect(stored.status_reason ?? '').not.toContain('Not written');
    } finally {
      reportWrite.mockRestore();
      if (runId) await queryAsAdmin({ query: RUN_CANCEL, variables: { id: runId } });
      await queryAsAdmin({ query: DELETE_CASE, variables: { id: caseId } });
    }
  });

  it('records the job of an enrichment dispatch interrupted once its work exists, and retries one that never started', async () => {
    const created = await queryAsAdminWithSuccess({ query: CREATE_CASE, variables: { input: { name: 'Case Autopilot e2e interrupted dispatch case', objects: [fixture.intrusionSetId, fixture.ipId] } } });
    const caseId = created.data.caseIncidentAdd.id;
    const connectorId = uuid();
    await registerConnector(testContext, ADMIN_USER, {
      id: connectorId, name: 'Case Autopilot e2e interrupted dispatch', type: ConnectorType.InternalEnrichment, scope: ['IPv4-Addr'], auto: false,
    });
    let runId = '';
    const askEnrichment = stixCoreObjectDomain.askElementEnrichmentForConnectors;
    const dispatch = vi.spyOn(stixCoreObjectDomain, 'askElementEnrichmentForConnectors');
    try {
      engineStage = 'planning';
      const { data } = await queryAsAdminWithSuccess({ query: RUN_ADD, variables: { subjectId: caseId } });
      runId = data.investigationRunAdd.id;
      createdRuns.push({ id: runId });
      await tickUntil(runId, (current) => current.run_phase === 'investigating');
      const request = await queryAsAdminWithSuccess({
        query: RUN_ENRICH,
        variables: { id: runId, input: { entity_ids: [fixture.ipId], connector_ids: [connectorId], reason: 'Check the address' } },
      });
      expect(request.data.investigationRunEnrichmentRequest.accepted).toEqual([{ entity_id: fixture.ipId, connector_id: connectorId, status: 'queued' }]);
      // A transient failure before the job started: the request stays queued, nothing is charged.
      dispatch.mockRejectedValueOnce(DatabaseError('Search engine unavailable'));
      await processInvestigationRun(testContext, runId);
      const retried = await queryAsAdminWithSuccess({ query: RUN_ENRICHMENT_STATE, variables: { id: runId } });
      expect(retried.data.investigationRun.enrichment_requests).toEqual([expect.objectContaining({ entity_id: fixture.ipId, status: 'queued', work_id: null })]);
      expect(retried.data.investigationRun.budget.used_enrichment_jobs).toBe(0);
      // A failure once the job was pushed: its work is recorded with its budget charge, as a started job.
      dispatch.mockImplementationOnce(async (context, user, enrichedId, connectorIds) => {
        await askEnrichment(context, user, enrichedId, connectorIds);
        throw new Error('Connection closed after the job was pushed');
      });
      await processInvestigationRun(testContext, runId);
      const recorded = await queryAsAdminWithSuccess({ query: RUN_ENRICHMENT_STATE, variables: { id: runId } });
      const [job] = recorded.data.investigationRun.enrichment_requests;
      expect(job).toMatchObject({ entity_id: fixture.ipId, status: 'dispatched' });
      expect(job.work_id).toBeTruthy();
      expect(recorded.data.investigationRun.budget.used_enrichment_jobs).toBe(1);
      expect(dispatch).toHaveBeenCalledTimes(2);
    } finally {
      dispatch.mockRestore();
      if (runId) await queryAsAdmin({ query: RUN_CANCEL, variables: { id: runId } });
      await connectorDelete(testContext, ADMIN_USER, connectorId);
      await queryAsAdmin({ query: DELETE_CASE, variables: { id: caseId } });
    }
  });

  it('records the job a connector accepted when the run could not record it, instead of starting it again', async () => {
    const created = await queryAsAdminWithSuccess({ query: CREATE_CASE, variables: { input: { name: 'Case Autopilot e2e unrecorded dispatch case', objects: [fixture.intrusionSetId, fixture.ipId] } } });
    const caseId = created.data.caseIncidentAdd.id;
    const connectorId = uuid();
    await registerConnector(testContext, ADMIN_USER, {
      id: connectorId, name: 'Case Autopilot e2e unrecorded dispatch', type: ConnectorType.InternalEnrichment, scope: ['IPv4-Addr'], auto: false,
    });
    let runId = '';
    let acceptedWorkId = '';
    const askEnrichment = stixCoreObjectDomain.askElementEnrichmentForConnectors;
    const dispatch = vi.spyOn(stixCoreObjectDomain, 'askElementEnrichmentForConnectors');
    const update = vi.spyOn(investigationRunDomain, 'updateInvestigationRun');
    try {
      engineStage = 'planning';
      const { data } = await queryAsAdminWithSuccess({ query: RUN_ADD, variables: { subjectId: caseId } });
      runId = data.investigationRunAdd.id;
      createdRuns.push({ id: runId });
      await tickUntil(runId, (current) => current.run_phase === 'investigating');
      await queryAsAdminWithSuccess({
        query: RUN_ENRICH,
        variables: { id: runId, input: { entity_ids: [fixture.ipId], connector_ids: [connectorId], reason: 'Check the address' } },
      });
      // The connector accepts the job, then recording its work on the run meets a transient failure.
      dispatch.mockImplementationOnce(async (context, user, enrichedId, connectorIds) => {
        const works = await askEnrichment(context, user, enrichedId, connectorIds);
        acceptedWorkId = works?.[0]?.id ?? '';
        update.mockRejectedValueOnce(DatabaseError('Search engine unavailable'));
        return works;
      });
      await processInvestigationRun(testContext, runId);
      const unrecorded = await queryAsAdminWithSuccess({ query: RUN_ENRICHMENT_STATE, variables: { id: runId } });
      expect(acceptedWorkId).toBeTruthy();
      expect(unrecorded.data.investigationRun.enrichment_requests).toEqual([expect.objectContaining({ entity_id: fixture.ipId, status: 'queued', work_id: null })]);
      expect(unrecorded.data.investigationRun.budget.used_enrichment_jobs).toBe(0);
      // The next pass records the job the connector accepted, with its budget charge, and starts no second one.
      await processInvestigationRun(testContext, runId);
      const recorded = await queryAsAdminWithSuccess({ query: RUN_ENRICHMENT_STATE, variables: { id: runId } });
      expect(recorded.data.investigationRun.enrichment_requests).toEqual([expect.objectContaining({ entity_id: fixture.ipId, status: 'dispatched', work_id: acceptedWorkId })]);
      expect(recorded.data.investigationRun.budget.used_enrichment_jobs).toBe(1);
      expect(dispatch).toHaveBeenCalledTimes(1);
    } finally {
      dispatch.mockRestore();
      update.mockRestore();
      if (runId) await queryAsAdmin({ query: RUN_CANCEL, variables: { id: runId } });
      await connectorDelete(testContext, ADMIN_USER, connectorId);
      await queryAsAdmin({ query: DELETE_CASE, variables: { id: caseId } });
    }
  });
});
