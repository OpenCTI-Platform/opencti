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

// Side effects of the investigation run state machine, executed by the
// investigation run manager: one phase per tick and per run. Every read of
// knowledge and every write runs as the identity of the run (its markings,
// organizations and capabilities apply); writes land in the run's Draft.

import { v4 as uuidv4 } from 'uuid';
import { Promise as BluePromise } from 'bluebird';
import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity, BasicStoreRelation, StoreEntity } from '../../types/store';
import type { BasicStoreSettings } from '../../types/settings';
import {
  FilterMode,
  FilterOperator,
  InvestigationApprovalKind,
  InvestigationApprovalStatus,
  InvestigationAutonomousAction,
  InvestigationEnrichmentRequestStatus,
  InvestigationEvidenceOrigin,
  InvestigationLedgerStatus,
  InvestigationPlanStepKind,
  InvestigationPlanStepStatus,
  InvestigationRecommendationStatus,
  InvestigationRunPhase,
  InvestigationRunStatus,
} from '../../generated/graphql';
import { logApp } from '../../config/conf';
import { elFindByIds } from '../../database/engine';
import { internalFindByIds, topEntitiesList, topRelationsList } from '../../database/middleware-loader';
import { storeLoadByIdWithRefs } from '../../database/middleware';
import { getEntityFromCache } from '../../database/cache';
import { READ_DATA_INDICES_WITHOUT_INTERNAL, READ_INDEX_DRAFT_OBJECTS, READ_RELATIONSHIPS_INDICES } from '../../database/utils';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP, buildRefRelationKey } from '../../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { RELATION_ATTRIBUTED_TO, RELATION_MITIGATES, RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';
import { RELATION_OBJECT } from '../../schema/stixRefRelationship';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_COURSE_OF_ACTION, ENTITY_TYPE_INCIDENT } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_CASE } from '../case/case-types';
import { ENTITY_TYPE_PIR } from '../pir/pir-types';
import { checkStixCoreRelationshipMapping } from '../../database/stix';
import { executionContext, INVESTIGATION_MANAGER_USER, isUserHasCapability, isUserInPlatformOrganization, KNOWLEDGE_KNENRICHMENT } from '../../utils/access';
import { resolveUserByIdFromCache } from '../user/user-domain';
import { addDraftWorkspace, validateDraftWorkspace } from '../draftWorkspace/draftWorkspace-domain';
import { addWorkspace, workspaceEditField } from '../workspace/workspace-domain';
import { askElementEnrichmentForConnectors } from '../../domain/stixCoreObject';
import { loadWorkById } from '../../domain/work';
import { addNote } from '../../domain/note';
import { addStixCoreRelationship } from '../../domain/stixCoreRelationship';
import { stixDomainObjectAddRelation } from '../../domain/stixDomainObject';
import { addCaseIncident } from '../case/case-incident/case-incident-domain';
import { addInvestigationEnrichmentJobCount, addInvestigationRunOutcomeCount } from '../../manager/telemetryManager';
import { isXtmOneConfigured } from '../playbook/components/ai-agent-shared';
import {
  ENTITY_TYPE_INVESTIGATION_RUN,
  INVESTIGATION_CASE_SUBJECT_TYPES,
  INVESTIGATION_LIMITS,
  TERMINAL_RUN_STATUSES,
  type BasicStoreEntityInvestigationPolicy,
  type BasicStoreEntityInvestigationRun,
  type InvestigationApproval,
  type InvestigationDelta,
  type InvestigationEnrichmentRequest,
  type InvestigationEvidence,
  type InvestigationLedgerEntry,
  type InvestigationPlanStep,
  type InvestigationRecommendation,
} from './investigationRun-types';
import { listPolicyEnrichmentConnectors, loadInvestigationRun, updateInvestigationRun } from './investigationRun-domain';
import { loadInvestigationPolicy } from './investigationPolicy-domain';
import {
  appendLedger,
  buildLedgerEntry,
  buildTimeline,
  canAutoApproveDraft,
  ENRICHMENT_WAVE_TIMEOUT_MS,
  evaluateEnrichmentRequest,
  isBudgetExhausted,
  isEnrichmentRejection,
  remainingEnrichmentJobs,
  remainingMinutes,
  statusTransition,
  VALIDATION_TIMEOUT_MS,
  type TimelineSource,
} from './investigationRun-state';
import {
  agentPhaseFor,
  buildAgentRequest,
  buildAllowedIds,
  groundAgentResponse,
  parseAgentResponse,
  type AgentContextEntity,
  type AgentEnrichmentConnector,
  type InvestigationAgentContext,
} from './investigationRun-agent';
import { scoreAchMatrix, type AchEvidenceMeta } from './investigationRun-ach';
import { callInvestigationAgent, resolveInvestigationAgent } from './investigationRun-xtm';
import { buildInvestigationNoteContent } from './investigationRun-report';
import { ATTRIBUTION_CANDIDATE_TYPES, authorIdOf, evidenceFromElement, markingIdsOf } from './investigationRun-utils';

export const INVESTIGATION_MANAGER_CONTEXT = 'investigation_run_manager';

const NOTE_ABSTRACT = 'Case Autopilot - autonomous investigation summary';
// Phases that consume the budget: once it is exhausted the run concludes.
const BUDGETED_PHASES = [
  InvestigationRunPhase.Planning,
  InvestigationRunPhase.Enriching,
  InvestigationRunPhase.WaitingEnrichment,
  InvestigationRunPhase.Iterating,
  InvestigationRunPhase.Concluding,
];
const MAX_CASE_OBJECTS = 200;
const MAX_ATTRIBUTED_INCIDENTS = 5;
const DETERMINISTIC_REASON = 'No Case Autopilot agent is available in XTM One: deterministic investigation (enrichment, timeline, report) without attribution';

interface RunExecution {
  run: BasicStoreEntityInvestigationRun;
  runUser: AuthUser;
  policy: BasicStoreEntityInvestigationPolicy;
  liveContext: AuthContext;
  draftContext: AuthContext;
  now: Date;
}

// region helpers

interface WorkState {
  id: string;
  status?: string;
}

const loadWork = async (context: AuthContext, workId: string): Promise<WorkState | null> => {
  const work = await loadWorkById(context, INVESTIGATION_MANAGER_USER, workId) as WorkState | undefined;
  return work ?? null;
};

// Elements by internal or standard id, among the data the user can see.
const findElements = async <T extends BasicStoreEntity = BasicStoreEntity>(
  context: AuthContext,
  user: AuthUser,
  ids: string[],
  opts: { type?: string } = {},
): Promise<T[]> => {
  if (ids.length === 0) return [];
  const options = opts.type ? { type: opts.type } : { indices: READ_DATA_INDICES_WITHOUT_INTERNAL };
  return await elFindByIds<T>(context, user, ids, options) as T[];
};

const draftQuery = (filters?: unknown, first = 500) => ({ indices: [READ_INDEX_DRAFT_OBJECTS], filters: filters as never, first });

const STIX_RELATIONSHIP_TYPES = [ABSTRACT_STIX_CORE_RELATIONSHIP, STIX_SIGHTING_RELATIONSHIP];

const userContext = async (user: AuthUser, draftId?: string | null): Promise<AuthContext> => {
  const context = executionContext(INVESTIGATION_MANAGER_CONTEXT, user, draftId ?? undefined);
  const settings = await getEntityFromCache<BasicStoreSettings>(context, INVESTIGATION_MANAGER_USER, ENTITY_TYPE_SETTINGS);
  // Organization restrictions depend on it: computed like an authenticated request.
  context.user_inside_platform_organization = isUserInPlatformOrganization(user, settings);
  return context;
};

const ledger = (run: BasicStoreEntityInvestigationRun, now: Date, entry: Partial<InvestigationLedgerEntry> & Pick<InvestigationLedgerEntry, 'tool' | 'description'>) => {
  return buildLedgerEntry(run, entry, now);
};

const errorMessage = (error: unknown) => (error instanceof Error ? error.message : String(error)).slice(0, INVESTIGATION_LIMITS.textLength);

const mergeEvidence = (current: InvestigationEvidence[], additions: InvestigationEvidence[]) => {
  const known = new Set(current.map((evidence) => evidence.id));
  const merged = [...current];
  additions.forEach((evidence) => {
    if (!known.has(evidence.id)) {
      known.add(evidence.id);
      merged.push(evidence);
    }
  });
  return merged.slice(0, INVESTIGATION_LIMITS.evidence);
};

const toTimelineSource = (evidence: InvestigationEvidence): TimelineSource => ({
  id: evidence.id,
  entity_type: evidence.entity_type,
  name: evidence.name,
  created: evidence.created,
  first_seen: evidence.first_seen,
  last_seen: evidence.last_seen,
});

// Reliability of the authors of the evidence, read from their identities.
const loadAuthorReliabilities = async (context: AuthContext, user: AuthUser, elements: object[]) => {
  const authorIds = R.uniq(elements.map((element) => authorIdOf(element)).filter((id): id is string => !!id));
  if (authorIds.length === 0) return new Map<string, string>();
  const authors = await findElements<BasicStoreEntity & { x_opencti_reliability?: string }>(context, user, authorIds);
  return new Map(authors.filter((author) => author.x_opencti_reliability).map((author) => [author.internal_id, author.x_opencti_reliability as string]));
};

const toEvidence = (elements: object[], reliabilities: Map<string, string>, origin: InvestigationEvidenceOrigin, draftId?: string | null) => {
  return elements.map((element) => {
    const authorId = authorIdOf(element);
    return evidenceFromElement(element, { origin, draftId, authorReliability: authorId ? reliabilities.get(authorId) ?? null : null });
  });
};

const toAgentEntity = (evidence: InvestigationEvidence): AgentContextEntity => ({
  id: evidence.id,
  standard_id: evidence.standard_id,
  entity_type: evidence.entity_type,
  name: evidence.name,
  created: evidence.created,
  first_seen: evidence.first_seen,
  last_seen: evidence.last_seen,
  confidence: evidence.confidence,
  author_reliability: evidence.author_reliability,
});

const failRun = async (context: AuthContext, runId: string, reason: string) => {
  const now = new Date();
  const updated = await updateInvestigationRun(context, runId, (current) => {
    if (TERMINAL_RUN_STATUSES.includes(current.run_status)) return null;
    return {
      ...statusTransition(current, InvestigationRunStatus.Failed, InvestigationRunPhase.Done, now, reason),
      steps: appendLedger(current.steps, [ledger(current, now, { tool: 'opencti.manager', description: 'Investigation failed', status: InvestigationLedgerStatus.Failed, error: reason })]),
      pending_work_ids: [],
    };
  });
  if (updated.run_status === InvestigationRunStatus.Failed) {
    addInvestigationRunOutcomeCount(InvestigationRunStatus.Failed);
  }
  logApp.warn('[CASE AUTOPILOT] Investigation failed', { runId, reason });
};

// endregion

// region context

// Relationships around the seed entities and the entities on their other side.
const collectNeighborhood = async (exec: RunExecution, seedIds: string[]) => {
  if (seedIds.length === 0) return { relationships: [] as BasicStoreRelation[], entities: [] as BasicStoreEntity[] };
  const relationships = await topRelationsList<BasicStoreRelation>(exec.draftContext, exec.runUser, [ABSTRACT_STIX_CORE_RELATIONSHIP, STIX_SIGHTING_RELATIONSHIP], {
    fromOrToId: seedIds.slice(0, 100),
    indices: READ_RELATIONSHIPS_INDICES,
    first: INVESTIGATION_LIMITS.contextRelationships,
  }) as unknown as BasicStoreRelation[];
  const seeds = new Set(seedIds);
  const neighborIds = R.uniq(relationships.flatMap((relationship) => [relationship.fromId, relationship.toId]).filter((id) => !seeds.has(id)));
  const entities = neighborIds.length === 0 ? [] : await elFindByIds<BasicStoreEntity>(
    exec.draftContext,
    exec.runUser,
    neighborIds.slice(0, INVESTIGATION_LIMITS.contextEntities),
    { indices: READ_DATA_INDICES_WITHOUT_INTERNAL },
  ) as BasicStoreEntity[];
  return { relationships, entities };
};

// Objects of a case (the case of the run or the investigated case).
const collectCaseObjects = async (exec: RunExecution, caseId: string) => {
  const refs = await topRelationsList<BasicStoreRelation>(exec.draftContext, exec.runUser, RELATION_OBJECT, {
    fromId: caseId,
    first: INVESTIGATION_LIMITS.contextEntities,
  }) as unknown as BasicStoreRelation[];
  const ids = R.uniq(refs.map((ref) => ref.toId));
  if (ids.length === 0) return [];
  return elFindByIds<BasicStoreEntity>(exec.draftContext, exec.runUser, ids, { indices: READ_DATA_INDICES_WITHOUT_INTERNAL }) as Promise<BasicStoreEntity[]>;
};

interface CollectedContext {
  agentContext: InvestigationAgentContext;
  evidence: InvestigationEvidence[];
  candidateInfo: Map<string, { name?: string | null; entity_type?: string | null; standard_id?: string | null }>;
}

const collectInvestigationContext = async (exec: RunExecution, subject: BasicStoreEntity): Promise<CollectedContext> => {
  const { run, runUser, draftContext } = exec;
  const caseId = run.case_id;
  const caseObjects = caseId ? await collectCaseObjects(exec, caseId) : [];
  const evidenceIds = run.evidence.map((evidence) => evidence.id);
  const seedIds = R.uniq([subject.internal_id, ...caseObjects.map((object) => object.internal_id), ...evidenceIds]);
  const { relationships, entities: neighbors } = await collectNeighborhood(exec, seedIds);
  const knownElements = R.uniqBy((element: BasicStoreEntity) => element.internal_id, [...caseObjects, ...neighbors]);
  // Candidates: threats in the neighborhood and threats one hop further.
  const candidateRelations = await topRelationsList<BasicStoreRelation>(draftContext, runUser, ABSTRACT_STIX_CORE_RELATIONSHIP, {
    fromOrToId: R.uniq([...seedIds, ...knownElements.map((element) => element.internal_id)]).slice(0, 100),
    first: INVESTIGATION_LIMITS.contextRelationships,
  }) as unknown as BasicStoreRelation[];
  const candidateIds = R.uniq([
    ...knownElements.filter((element) => ATTRIBUTION_CANDIDATE_TYPES.includes(element.entity_type)).map((element) => element.internal_id),
    ...candidateRelations.flatMap((relationship) => [
      ATTRIBUTION_CANDIDATE_TYPES.includes(relationship.fromType) ? relationship.fromId : null,
      ATTRIBUTION_CANDIDATE_TYPES.includes(relationship.toType) ? relationship.toId : null,
    ]).filter((id): id is string => !!id),
  ]).slice(0, INVESTIGATION_LIMITS.candidates);
  const knownIds = new Set(knownElements.map((element) => element.internal_id));
  const missingCandidateIds = candidateIds.filter((id) => !knownIds.has(id));
  const extraCandidates = await findElements(draftContext, runUser, missingCandidateIds);
  const candidates = [...knownElements, ...extraCandidates].filter((element) => ATTRIBUTION_CANDIDATE_TYPES.includes(element.entity_type));
  // Courses of action mitigating the techniques in scope.
  const attackPatternIds = knownElements.filter((element) => element.entity_type === ENTITY_TYPE_ATTACK_PATTERN).map((element) => element.internal_id);
  const mitigations = attackPatternIds.length === 0 ? [] : await topRelationsList<BasicStoreRelation>(draftContext, runUser, RELATION_MITIGATES, {
    toId: attackPatternIds.slice(0, 100),
    first: INVESTIGATION_LIMITS.coursesOfAction,
  }) as unknown as BasicStoreRelation[];
  const coaIds = R.uniq([
    ...knownElements.filter((element) => element.entity_type === ENTITY_TYPE_COURSE_OF_ACTION).map((element) => element.internal_id),
    ...mitigations.map((relationship) => relationship.fromId),
  ]).slice(0, INVESTIGATION_LIMITS.coursesOfAction);
  const coursesOfAction = await findElements<BasicStoreEntity & { x_mitre_id?: string }>(draftContext, runUser, coaIds, { type: ENTITY_TYPE_COURSE_OF_ACTION });
  // PIRs the candidates matter to, among the PIRs the identity can see.
  const pirScores = new Map<string, number>();
  candidates.forEach((candidate) => {
    ((candidate as unknown as { pir_information?: Array<{ pir_id: string; pir_score: number }> }).pir_information ?? []).forEach(({ pir_id, pir_score }) => {
      pirScores.set(pir_id, Math.max(pirScores.get(pir_id) ?? 0, pir_score));
    });
  });
  const pirIds = Array.from(pirScores.keys());
  const pirs = pirIds.length === 0 ? [] : await internalFindByIds<BasicStoreEntity>(exec.liveContext, runUser, pirIds, { type: ENTITY_TYPE_PIR }) as BasicStoreEntity[];
  const reliabilities = await loadAuthorReliabilities(draftContext, runUser, [subject, ...knownElements, ...candidates]);
  const contextEvidence = toEvidence(knownElements, reliabilities, InvestigationEvidenceOrigin.Context, run.draft_id);
  const evidence = mergeEvidence(run.evidence, contextEvidence).map((item) => {
    // Refresh the weighting attributes of known evidence.
    const fresh = contextEvidence.find((e) => e.id === item.id);
    return fresh ? { ...item, confidence: fresh.confidence, author_reliability: fresh.author_reliability } : item;
  });
  const connectors = await listPolicyEnrichmentConnectors(exec.liveContext, runUser, exec.policy);
  const agentConnectors: AgentEnrichmentConnector[] = connectors.map((connector) => ({
    id: connector.internal_id,
    name: connector.name,
    scope: connector.connector_scope ?? [],
    requires_approval: (exec.policy.approval_connector_ids ?? []).includes(connector.internal_id),
  }));
  const subjectEvidence = toEvidence([subject], reliabilities, InvestigationEvidenceOrigin.Subject, run.draft_id)[0];
  const candidateInfo = new Map(candidates.map((candidate) => [candidate.internal_id, {
    name: evidenceFromElement(candidate).name,
    entity_type: candidate.entity_type,
    standard_id: candidate.standard_id,
  }]));
  const agentContext: InvestigationAgentContext = {
    subject: { ...toAgentEntity(subjectEvidence), description: (subject as unknown as { description?: string }).description?.slice(0, INVESTIGATION_LIMITS.textLength) ?? null },
    entities: evidence.filter((e) => e.id !== subject.internal_id).slice(0, INVESTIGATION_LIMITS.contextEntities).map(toAgentEntity),
    relationships: relationships.slice(0, INVESTIGATION_LIMITS.contextRelationships).map((relationship) => ({
      id: relationship.internal_id,
      standard_id: relationship.standard_id,
      relationship_type: relationship.relationship_type ?? relationship.entity_type,
      from_id: relationship.fromId,
      to_id: relationship.toId,
      first_seen: (relationship as unknown as { start_time?: string; first_seen?: string }).start_time ?? (relationship as unknown as { first_seen?: string }).first_seen ?? null,
      last_seen: (relationship as unknown as { stop_time?: string; last_seen?: string }).stop_time ?? (relationship as unknown as { last_seen?: string }).last_seen ?? null,
      confidence: (relationship as unknown as { confidence?: number }).confidence ?? null,
    })),
    candidates: candidates.map((candidate) => ({
      id: candidate.internal_id,
      standard_id: candidate.standard_id,
      entity_type: candidate.entity_type,
      name: evidenceFromElement(candidate).name ?? candidate.internal_id,
      aliases: ((candidate as unknown as { aliases?: string[] }).aliases ?? []).slice(0, 10),
    })),
    courses_of_action: coursesOfAction.map((coa) => ({
      id: coa.internal_id,
      standard_id: coa.standard_id,
      name: evidenceFromElement(coa).name ?? coa.internal_id,
      x_mitre_id: coa.x_mitre_id ?? null,
    })),
    pir: pirs.map((pir) => ({ id: pir.internal_id, name: (pir as unknown as { name: string }).name, score: pirScores.get(pir.internal_id) ?? 0 })),
    connectors: agentConnectors,
    allowed_actions: exec.policy.allowed_actions,
  };
  return { agentContext, evidence, candidateInfo };
};

// endregion

// region phases

const loadSubject = async (exec: RunExecution) => {
  return storeLoadByIdWithRefs<StoreEntity>(exec.draftContext, exec.runUser, exec.run.subject_id);
};

const findCaseContainingSubject = async (exec: RunExecution, subjectId: string) => {
  const [found] = await topEntitiesList<BasicStoreEntity>(exec.liveContext, exec.runUser, [ENTITY_TYPE_CONTAINER_CASE], {
    filters: { mode: FilterMode.And, filters: [{ key: [buildRefRelationKey(RELATION_OBJECT)], values: [subjectId] }], filterGroups: [] },
    orderBy: 'created',
    orderMode: 'desc' as never,
    first: 1,
  });
  return found ?? null;
};

const initializeRun = async (exec: RunExecution) => {
  const { run, runUser, liveContext, now } = exec;
  const subject = await storeLoadByIdWithRefs<StoreEntity>(liveContext, runUser, run.subject_id);
  if (!subject) {
    await failRun(liveContext, run.internal_id, 'The investigated entity is no longer accessible to the identity of the run');
    return;
  }
  const entries: InvestigationLedgerEntry[] = [];
  const patch: Record<string, unknown> = {};
  // Draft: every write of the run lands here, nothing reaches the live graph without approval.
  let draftId = run.draft_id ?? null;
  if (!draftId) {
    const started = Date.now();
    const draft = await addDraftWorkspace(liveContext, runUser, {
      name: run.name,
      description: 'Draft of a Case Autopilot investigation: enrichment results, notes and relationships proposed by the run.',
      entity_id: subject.internal_id,
    });
    draftId = draft.id;
    patch.draft_id = draftId;
    entries.push(ledger(run, now, { tool: 'opencti.draft', description: 'Investigation draft created', output_ref: draftId, duration_ms: Date.now() - started }));
  }
  // Case: the investigated case, or the most recent case containing the subject.
  if (!run.case_id) {
    const existingCase = INVESTIGATION_CASE_SUBJECT_TYPES.includes(subject.entity_type) ? subject : await findCaseContainingSubject(exec, subject.internal_id);
    if (existingCase) {
      patch.case_id = existingCase.internal_id;
      patch.case_ids = R.uniq([...(run.case_ids ?? []), existingCase.internal_id, existingCase.standard_id]);
      entries.push(ledger(run, now, { tool: 'opencti.case', description: 'Existing case found for the investigated entity', output_ref: existingCase.internal_id }));
    }
  }
  const execInDraft: RunExecution = { ...exec, run: { ...run, ...patch } as BasicStoreEntityInvestigationRun, draftContext: await userContext(runUser, draftId) };
  const collected = await collectInvestigationContext(execInDraft, subject);
  patch.evidence = collected.evidence;
  patch.timeline = buildTimeline(collected.evidence.map(toTimelineSource));
  entries.push(ledger(run, now, {
    tool: 'opencti.context',
    description: `Context collected: ${collected.agentContext.entities.length} entities, ${collected.agentContext.relationships.length} relationships, ${collected.agentContext.candidates.length} candidates`,
  }));
  // Investigation workspace, the graph the analyst opens when the run completes.
  if (!run.workspace_id) {
    if (isUserHasCapability(runUser, 'INVESTIGATION_INUPDATE')) {
      const liveEntityIds = collected.evidence.filter((evidence) => !evidence.in_draft && !evidence.entity_type.includes('relationship')).map((evidence) => evidence.id);
      const workspace = await addWorkspace(liveContext, runUser, {
        type: 'investigation',
        name: run.name,
        description: 'Investigation graph of a Case Autopilot run.',
        investigated_entities_ids: liveEntityIds.slice(0, INVESTIGATION_LIMITS.evidence),
      });
      patch.workspace_id = workspace.id;
      entries.push(ledger(run, now, { tool: 'opencti.workspace', description: 'Investigation graph created', output_ref: workspace.id }));
    } else {
      entries.push(ledger(run, now, { tool: 'opencti.workspace', description: 'Investigation graph skipped: the identity of the run cannot create investigations', status: InvestigationLedgerStatus.Skipped }));
    }
  }
  patch.run_phase = InvestigationRunPhase.Planning;
  await updateInvestigationRun(liveContext, run.internal_id, (current) => ({
    ...patch,
    steps: appendLedger(current.steps, entries),
  }));
};

// Enrichment plan used when no agent is available: every allowed connector on
// the subject and on the indicators and observables already in scope.
const buildDeterministicRequests = (exec: RunExecution, collected: CollectedContext) => {
  const targets = [
    collected.agentContext.subject,
    ...collected.agentContext.entities.filter((entity) => entity.entity_type === 'Indicator' || entity.entity_type.endsWith('Addr')
      || ['Domain-Name', 'Url', 'StixFile', 'Hostname', 'Email-Addr', 'Artifact'].includes(entity.entity_type)),
  ].slice(0, INVESTIGATION_LIMITS.enrichmentRequestsPerCall);
  const requests: Array<{ entity_id: string; connector_id: string; reason: string }> = [];
  targets.forEach((target) => {
    collected.agentContext.connectors
      .filter((connector) => connector.scope.length === 0 || connector.scope.some((scope) => scope.toLowerCase() === target.entity_type.toLowerCase()))
      .forEach((connector) => requests.push({ entity_id: target.id, connector_id: connector.id, reason: 'Deterministic enrichment of the investigation scope' }));
  });
  return requests.slice(0, INVESTIGATION_LIMITS.enrichmentRequestsPerCall);
};

const gateRequests = (
  exec: RunExecution,
  current: BasicStoreEntityInvestigationRun,
  requests: Array<{ entity_id: string; connector_id: string; reason: string | null }>,
  allowedConnectorIds: Set<string>,
  allowedEntityIds: Set<string>,
  connectorNames: Map<string, string>,
  requestedBy: string,
) => {
  const newRequests: InvestigationEnrichmentRequest[] = [];
  const newApprovals: InvestigationApproval[] = [];
  requests.forEach((request) => {
    const verdict = evaluateEnrichmentRequest({
      run: { ...current, enrichment_requests: [...current.enrichment_requests, ...newRequests] },
      policy: exec.policy,
      allowedConnectorIds,
      allowedEntityIds,
      entityId: request.entity_id,
      connectorId: request.connector_id,
      alreadyAccepted: 0,
    });
    if (isEnrichmentRejection(verdict)) return;
    const stored: InvestigationEnrichmentRequest = {
      id: uuidv4(),
      entity_id: request.entity_id,
      connector_id: request.connector_id,
      connector_name: connectorNames.get(request.connector_id) ?? null,
      reason: request.reason,
      status: verdict,
      requested_by: requestedBy,
      iteration: current.iteration,
      work_id: null,
      created_at: exec.now.toISOString(),
      completed_at: null,
    };
    newRequests.push(stored);
    if (verdict === InvestigationEnrichmentRequestStatus.AwaitingApproval) {
      newApprovals.push({
        id: uuidv4(),
        kind: InvestigationApprovalKind.Enrichment,
        status: InvestigationApprovalStatus.Pending,
        description: `Run ${stored.connector_name ?? stored.connector_id} on ${request.entity_id}`,
        reason: request.reason,
        connector_id: request.connector_id,
        entity_id: request.entity_id,
        recommendation_id: null,
        created_at: exec.now.toISOString(),
      });
    }
  });
  return { newRequests, newApprovals };
};

const hasPendingEnrichment = (run: BasicStoreEntityInvestigationRun) => run.enrichment_requests.some((request) => request.status === InvestigationEnrichmentRequestStatus.Queued
  || request.status === InvestigationEnrichmentRequestStatus.AwaitingApproval);

// Keep the analyst-facing state of recommendations already handled.
const mergeRecommendations = (current: InvestigationRecommendation[], proposed: InvestigationRecommendation[]) => {
  if (proposed.length === 0) return current;
  return proposed.map((recommendation) => {
    const existing = current.find((r) => r.id === recommendation.id);
    return existing && existing.status !== InvestigationRecommendationStatus.Proposed && existing.status !== InvestigationRecommendationStatus.AwaitingApproval
      ? existing
      : recommendation;
  });
};

const runAgentPhase = async (exec: RunExecution) => {
  const { run, runUser, now } = exec;
  const subject = await loadSubject(exec);
  if (!subject) {
    await failRun(exec.liveContext, run.internal_id, 'The investigated entity is no longer accessible to the identity of the run');
    return;
  }
  const collected = await collectInvestigationContext(exec, subject);
  const connectorNames = new Map(collected.agentContext.connectors.map((connector) => [connector.id, connector.name]));
  const allowedConnectorIds = new Set(collected.agentContext.connectors.map((connector) => connector.id));
  const evidenceWithContext = collected.evidence;
  const allowed = buildAllowedIds(collected.agentContext, evidenceWithContext);
  const agentSlug = isXtmOneConfigured()
    ? await resolveInvestigationAgent({ id: runUser.id, user_email: runUser.user_email }, exec.policy.agent_slug)
    : null;
  if (!agentSlug) {
    // Deterministic investigation: one enrichment wave, then the report.
    const isFirstCall = run.run_phase === InvestigationRunPhase.Planning;
    const requests = isFirstCall && exec.policy.allowed_actions.includes(InvestigationAutonomousAction.Enrichment) ? buildDeterministicRequests(exec, collected) : [];
    await updateInvestigationRun(exec.liveContext, run.internal_id, (current) => {
      const { newRequests, newApprovals } = gateRequests(exec, current, requests, allowedConnectorIds, allowed.entities, connectorNames, 'manager');
      const plan: InvestigationPlanStep[] = isFirstCall ? [
        { id: 'enrichment', kind: InvestigationPlanStepKind.Enrichment, description: 'Enrich the investigated entity and its indicators and observables with the allowed connectors', status: newRequests.length > 0 ? InvestigationPlanStepStatus.Pending : InvestigationPlanStepStatus.Skipped, approval_required: newApprovals.length > 0 },
        { id: 'timeline', kind: InvestigationPlanStepKind.Timeline, description: 'Rebuild the timeline from the dates of the evidence', status: InvestigationPlanStepStatus.Pending, approval_required: false },
        { id: 'report', kind: InvestigationPlanStepKind.Report, description: 'Write the investigation summary into the draft', status: InvestigationPlanStepStatus.Pending, approval_required: false },
      ] : current.plan;
      const entries = isFirstCall ? [ledger(current, now, { tool: 'opencti.planner', description: DETERMINISTIC_REASON, status: InvestigationLedgerStatus.Skipped })] : [];
      return {
        status_reason: DETERMINISTIC_REASON,
        plan,
        evidence: evidenceWithContext,
        enrichment_requests: [...current.enrichment_requests, ...newRequests],
        approvals: [...current.approvals, ...newApprovals].slice(-INVESTIGATION_LIMITS.approvals),
        steps: appendLedger(current.steps, entries),
        run_phase: newRequests.length > 0 ? InvestigationRunPhase.Enriching : InvestigationRunPhase.Finalizing,
      };
    });
    return;
  }
  const phase = agentPhaseFor(run.run_phase);
  const delta: InvestigationDelta = run.last_delta ?? { new_entity_ids: [], new_relationship_ids: [], enrichments: [] };
  const content = buildAgentRequest({ ...run, evidence: evidenceWithContext }, phase, collected.agentContext, delta, allowed, remainingMinutes(run, now));
  const started = Date.now();
  const answer = await callInvestigationAgent(agentSlug, content, { id: runUser.id, user_email: runUser.user_email }, run.draft_id);
  const duration = Date.now() - started;
  const parsed = parseAgentResponse(answer.content);
  if (!parsed) {
    const reason = answer.error ?? 'The agent answer is not a valid investigation result';
    const failures = (run.agent_failures ?? 0) + 1;
    if (failures > INVESTIGATION_LIMITS.agentRetries) {
      if (run.hypotheses.length > 0 || run.steps.some((step) => step.tool === 'xtm_one.agent' && step.status === InvestigationLedgerStatus.Done)) {
        await updateInvestigationRun(exec.liveContext, run.internal_id, (current) => ({
          agent_failures: failures,
          status_reason: `The agent stopped answering (${reason}): the investigation is concluded with the results collected so far`,
          steps: appendLedger(current.steps, [ledger(current, now, { tool: 'xtm_one.agent', description: `Agent call failed (${phase})`, status: InvestigationLedgerStatus.Failed, error: reason, duration_ms: duration, cost_units: 1 })]),
          budget: { ...current.budget, used_tool_calls: current.budget.used_tool_calls + 1 },
          run_phase: InvestigationRunPhase.Finalizing,
        }));
        return;
      }
      await failRun(exec.liveContext, run.internal_id, `The Case Autopilot agent could not complete the investigation: ${reason}`);
      return;
    }
    await updateInvestigationRun(exec.liveContext, run.internal_id, (current) => ({
      agent_failures: failures,
      steps: appendLedger(current.steps, [ledger(current, now, { tool: 'xtm_one.agent', description: `Agent call failed (${phase}), will retry`, status: InvestigationLedgerStatus.Failed, error: reason, duration_ms: duration, cost_units: 1 })]),
      budget: { ...current.budget, used_tool_calls: current.budget.used_tool_calls + 1 },
    }));
    return;
  }
  // Ids the agent cites beyond its context are accepted only if the identity of the run can see them.
  const citedIds = R.uniq([
    ...((parsed.hypotheses as Array<{ candidate_id?: string; evidence?: Array<{ evidence_id?: string }> }> | undefined) ?? [])
      .flatMap((hypothesis) => [hypothesis?.candidate_id, ...(hypothesis?.evidence ?? []).map((cell) => cell?.evidence_id)]),
  ].filter((id): id is string => typeof id === 'string' && !allowed.aliases.has(id))).slice(0, INVESTIGATION_LIMITS.evidence);
  const citedElements = await findElements(exec.draftContext, runUser, citedIds);
  const citedEvidence = toEvidence(citedElements, new Map(), InvestigationEvidenceOrigin.Agent, run.draft_id);
  citedElements.forEach((element) => {
    allowed.evidence.add(element.internal_id);
    allowed.aliases.set(element.internal_id, element.internal_id);
    if (element.standard_id) allowed.aliases.set(element.standard_id, element.internal_id);
    if (ATTRIBUTION_CANDIDATE_TYPES.includes(element.entity_type)) {
      allowed.candidates.add(element.internal_id);
      collected.candidateInfo.set(element.internal_id, { name: evidenceFromElement(element).name, entity_type: element.entity_type, standard_id: element.standard_id });
    }
  });
  const grounded = groundAgentResponse(parsed, allowed, collected.candidateInfo);
  const allEvidence = mergeEvidence(evidenceWithContext, citedEvidence);
  const evidenceMeta = new Map<string, AchEvidenceMeta>(allEvidence.map((evidence) => [evidence.id, evidence]));
  const scored = grounded.hypotheses.length > 0 ? scoreAchMatrix(grounded.hypotheses, evidenceMeta) : null;
  await updateInvestigationRun(exec.liveContext, run.internal_id, (current) => {
    const { newRequests, newApprovals } = gateRequests(exec, current, grounded.enrichment_requests, allowedConnectorIds, allowed.entities, connectorNames, 'agent');
    const next: BasicStoreEntityInvestigationRun = { ...current, enrichment_requests: [...current.enrichment_requests, ...newRequests] };
    let nextPhase: InvestigationRunPhase;
    if (grounded.done || run.run_phase === InvestigationRunPhase.Concluding) {
      nextPhase = InvestigationRunPhase.Finalizing;
    } else if (hasPendingEnrichment(next)) {
      nextPhase = InvestigationRunPhase.Enriching;
    } else {
      // Nothing left to enrich: one last call to conclude, never an endless loop.
      nextPhase = InvestigationRunPhase.Concluding;
    }
    return {
      agent_slug: agentSlug,
      agent_failures: 0,
      status_reason: null,
      plan: grounded.plan.length > 0 ? grounded.plan : current.plan,
      evidence: mergeEvidence(current.evidence, allEvidence),
      hypotheses: scored ?? current.hypotheses,
      recommendations: mergeRecommendations(current.recommendations, grounded.recommendations),
      summary: grounded.summary ?? current.summary ?? null,
      enrichment_requests: next.enrichment_requests,
      approvals: [...current.approvals, ...newApprovals].slice(-INVESTIGATION_LIMITS.approvals),
      steps: appendLedger(current.steps, [ledger(current, now, {
        tool: 'xtm_one.agent',
        description: `Agent ${phase}: ${grounded.plan.length} plan step(s), ${newRequests.length} enrichment request(s), ${grounded.hypotheses.length} hypothesis(es), ${grounded.recommendations.length} recommendation(s)`
          + (grounded.dropped > 0 ? `, ${grounded.dropped} ungrounded item(s) dropped` : ''),
        input_ref: agentSlug,
        duration_ms: duration,
        cost_units: 1,
      })]),
      budget: { ...current.budget, used_tool_calls: current.budget.used_tool_calls + 1 },
      run_phase: nextPhase,
    };
  });
};

const dispatchEnrichments = async (exec: RunExecution) => {
  const { run, runUser, now } = exec;
  const queued = run.enrichment_requests.filter((request) => request.status === InvestigationEnrichmentRequestStatus.Queued);
  const awaiting = run.enrichment_requests.filter((request) => request.status === InvestigationEnrichmentRequestStatus.AwaitingApproval);
  if (queued.length === 0) {
    if (awaiting.length > 0) {
      // Paid or sensitive connectors: the run pauses until an analyst decides.
      const reason = `${awaiting.length} enrichment request(s) waiting for an approval`;
      await updateInvestigationRun(exec.liveContext, run.internal_id, (current) => {
        return statusTransition(current, InvestigationRunStatus.AwaitingApproval, InvestigationRunPhase.Enriching, now, reason);
      });
      return;
    }
    await updateInvestigationRun(exec.liveContext, run.internal_id, () => ({ run_phase: InvestigationRunPhase.Concluding }));
    return;
  }
  const canEnrich = isUserHasCapability(runUser, KNOWLEDGE_KNENRICHMENT);
  const budgetLeft = Math.max(0, Math.min(run.budget.max_enrichment_jobs - run.budget.used_enrichment_jobs, run.budget.max_tool_calls - run.budget.used_tool_calls));
  const dispatched = new Map<string, { work_id: string | null; error: string | null }>();
  const toDispatch = canEnrich ? queued.slice(0, budgetLeft) : [];
  for (let index = 0; index < toDispatch.length; index += 1) {
    const request = toDispatch[index];
    try {
      const works = await askElementEnrichmentForConnectors(exec.draftContext, runUser, request.entity_id, [request.connector_id]);
      dispatched.set(request.id, { work_id: works?.[0]?.id ?? null, error: null });
    } catch (error) {
      dispatched.set(request.id, { work_id: null, error: errorMessage(error) });
    }
  }
  const dispatchedCount = Array.from(dispatched.values()).filter((result) => result.work_id).length;
  addInvestigationEnrichmentJobCount(dispatchedCount);
  await updateInvestigationRun(exec.liveContext, run.internal_id, (current) => {
    const entries: InvestigationLedgerEntry[] = [];
    const requests = current.enrichment_requests.map((request) => {
      if (request.status !== InvestigationEnrichmentRequestStatus.Queued) return request;
      const result = dispatched.get(request.id);
      if (!result) {
        // Not dispatched: no capability or no budget left.
        entries.push(ledger(current, now, {
          tool: 'opencti.enrichment',
          description: `Enrichment of ${request.entity_id} with ${request.connector_name ?? request.connector_id} skipped: ${canEnrich ? 'budget exhausted' : 'the identity of the run cannot run enrichments'}`,
          status: InvestigationLedgerStatus.Skipped,
        }));
        return { ...request, status: InvestigationEnrichmentRequestStatus.Skipped, completed_at: now.toISOString() };
      }
      entries.push(ledger(current, now, {
        tool: 'opencti.enrichment',
        description: `Enrichment of ${request.entity_id} with ${request.connector_name ?? request.connector_id}`,
        input_ref: request.entity_id,
        work_id: result.work_id,
        status: result.work_id ? InvestigationLedgerStatus.Done : InvestigationLedgerStatus.Failed,
        error: result.error,
        cost_units: 1,
      }));
      return result.work_id
        ? { ...request, status: InvestigationEnrichmentRequestStatus.Dispatched, work_id: result.work_id }
        : { ...request, status: InvestigationEnrichmentRequestStatus.Failed, completed_at: now.toISOString() };
    });
    const workIds = Array.from(dispatched.values()).map((result) => result.work_id).filter((id): id is string => !!id);
    return {
      enrichment_requests: requests,
      steps: appendLedger(current.steps, entries),
      pending_work_ids: workIds,
      wave_started_at: now.toISOString(),
      budget: {
        ...current.budget,
        used_tool_calls: current.budget.used_tool_calls + dispatched.size,
        used_enrichment_jobs: current.budget.used_enrichment_jobs + dispatchedCount,
      },
      plan: current.plan.map((step) => (step.kind === InvestigationPlanStepKind.Enrichment && step.status === InvestigationPlanStepStatus.Pending
        ? { ...step, status: InvestigationPlanStepStatus.Running } : step)),
      run_phase: workIds.length > 0 ? InvestigationRunPhase.WaitingEnrichment : InvestigationRunPhase.Concluding,
    };
  });
};

const collectEnrichments = async (exec: RunExecution) => {
  const { run, runUser, now } = exec;
  const waveStart = run.wave_started_at ? new Date(run.wave_started_at).getTime() : now.getTime();
  const timedOut = now.getTime() - waveStart > ENRICHMENT_WAVE_TIMEOUT_MS || remainingMinutes(run, now) <= 0;
  const works = await Promise.all((run.pending_work_ids ?? []).map((workId) => loadWork(exec.liveContext, workId)));
  const completedWorkIds = new Set(works.filter((work): work is WorkState => work?.status === 'complete').map((work) => work.id));
  const allDone = (run.pending_work_ids ?? []).every((workId) => completedWorkIds.has(workId));
  if (!allDone && !timedOut) {
    return; // Keep waiting, the next tick checks again.
  }
  // What the wave brought into the draft.
  const since = new Date(waveStart).toISOString();
  const draftFilters = { mode: FilterMode.And, filters: [{ key: ['updated_at'], values: [since], operator: FilterOperator.Gte }], filterGroups: [] };
  const [newEntities, newRelationships] = await Promise.all([
    topEntitiesList<BasicStoreEntity>(exec.draftContext, runUser, [ABSTRACT_STIX_CORE_OBJECT], draftQuery(draftFilters, INVESTIGATION_LIMITS.contextEntities)),
    topRelationsList<BasicStoreRelation>(
      exec.draftContext,
      runUser,
      STIX_RELATIONSHIP_TYPES,
      draftQuery(draftFilters, INVESTIGATION_LIMITS.contextRelationships),
    ) as unknown as Promise<BasicStoreRelation[]>,
  ]);
  const reliabilities = await loadAuthorReliabilities(exec.draftContext, runUser, newEntities);
  const newEvidence = [
    ...toEvidence(newEntities, reliabilities, InvestigationEvidenceOrigin.Enrichment, run.draft_id),
    ...toEvidence(newRelationships, new Map(), InvestigationEvidenceOrigin.Enrichment, run.draft_id),
  ];
  const known = new Set(run.evidence.map((evidence) => evidence.id));
  const delta: InvestigationDelta = {
    new_entity_ids: newEntities.map((entity) => entity.internal_id).filter((id) => !known.has(id)),
    new_relationship_ids: newRelationships.map((relationship) => relationship.internal_id).filter((id) => !known.has(id)),
    enrichments: run.enrichment_requests
      .filter((request) => request.status === InvestigationEnrichmentRequestStatus.Dispatched)
      .map((request) => ({
        entity_id: request.entity_id,
        connector_id: request.connector_id,
        status: request.work_id && completedWorkIds.has(request.work_id) ? 'completed' : 'timeout',
        // Objects of the wave touching the enriched entity.
        new_object_ids: newRelationships.filter((r) => r.fromId === request.entity_id || r.toId === request.entity_id).map((r) => r.internal_id).slice(0, 50),
      })),
  };
  await updateInvestigationRun(exec.liveContext, run.internal_id, (current) => {
    const evidence = mergeEvidence(current.evidence, newEvidence);
    const requests = current.enrichment_requests.map((request) => {
      if (request.status !== InvestigationEnrichmentRequestStatus.Dispatched) return request;
      const completed = request.work_id ? completedWorkIds.has(request.work_id) : false;
      return { ...request, status: completed ? InvestigationEnrichmentRequestStatus.Completed : InvestigationEnrichmentRequestStatus.Timeout, completed_at: now.toISOString() };
    });
    const next = { ...current, enrichment_requests: requests };
    const exhausted = remainingEnrichmentJobs(next) === 0 || current.budget.max_tool_calls - current.budget.used_tool_calls <= 1;
    return {
      evidence,
      timeline: buildTimeline(evidence.map(toTimelineSource)),
      enrichment_requests: requests,
      last_delta: delta,
      pending_work_ids: [],
      iteration: current.iteration + 1,
      plan: current.plan.map((step) => (step.kind === InvestigationPlanStepKind.Enrichment && step.status === InvestigationPlanStepStatus.Running
        ? { ...step, status: InvestigationPlanStepStatus.Done } : step)),
      steps: appendLedger(current.steps, [ledger(current, now, {
        tool: 'opencti.enrichment',
        description: `Enrichment wave ${timedOut && !allDone ? 'timed out' : 'completed'}: ${delta.new_entity_ids.length} new entities, ${delta.new_relationship_ids.length} new relationships`,
        status: timedOut && !allDone ? InvestigationLedgerStatus.Failed : InvestigationLedgerStatus.Done,
      })]),
      run_phase: exhausted ? InvestigationRunPhase.Concluding : InvestigationRunPhase.Iterating,
    };
  });
};

// Draft writes of the conclusion, each one allowed by the policy and logged.
const writeOutputs = async (exec: RunExecution, subject: BasicStoreEntity) => {
  const { run, runUser, draftContext, policy, now } = exec;
  const entries: InvestigationLedgerEntry[] = [];
  const patch: Record<string, unknown> = {};
  const allowedAction = (action: InvestigationAutonomousAction) => policy.allowed_actions.includes(action);
  const leading = run.hypotheses.find((hypothesis) => hypothesis.rank === 1) ?? null;
  const markings = markingIdsOf(subject);
  const objectIds = R.uniq([
    subject.internal_id,
    ...run.evidence.filter((evidence) => !evidence.entity_type.includes('relationship')).map((evidence) => evidence.id),
    ...(leading ? [leading.candidate_id] : []),
  ]).slice(0, MAX_CASE_OBJECTS);
  let caseId = run.case_id ?? null;
  const attempt = async (tool: string, description: string, fn: () => Promise<string | null | undefined>) => {
    const started = Date.now();
    try {
      const outputRef = await fn();
      entries.push(ledger(run, now, { tool, description, output_ref: outputRef ?? null, duration_ms: Date.now() - started }));
    } catch (error) {
      entries.push(ledger(run, now, { tool, description, status: InvestigationLedgerStatus.Failed, error: errorMessage(error), duration_ms: Date.now() - started }));
    }
  };
  if (caseId && allowedAction(InvestigationAutonomousAction.AddToCase)) {
    await attempt('opencti.case', `Evidence added to the case (${objectIds.length} objects)`, async () => {
      const addObject = (toId: string) => stixDomainObjectAddRelation(draftContext, runUser, caseId as string, { toId, relationship_type: RELATION_OBJECT })
        .catch((error: unknown) => logApp.debug('[CASE AUTOPILOT] Object not added to the case', { toId, cause: errorMessage(error) }));
      await BluePromise.map(objectIds.filter((id) => id !== caseId), addObject, { concurrency: 5 });
      return caseId;
    });
  } else if (!caseId && allowedAction(InvestigationAutonomousAction.CreateCase)) {
    await attempt('opencti.case', 'Case created for the investigation', async () => {
      const created = await addCaseIncident(draftContext, runUser, {
        name: `Investigation - ${evidenceFromElement(subject).name ?? subject.internal_id}`.slice(0, 250),
        description: run.summary?.slice(0, INVESTIGATION_LIMITS.textLength) ?? 'Case opened by a Case Autopilot investigation.',
        objects: objectIds,
        objectMarking: markings,
      });
      caseId = created.internal_id;
      patch.case_id = created.internal_id;
      patch.case_ids = R.uniq([...(run.case_ids ?? []), created.internal_id, created.standard_id]);
      return created.internal_id;
    });
  }
  if (allowedAction(InvestigationAutonomousAction.CreateNote)) {
    await attempt('opencti.note', 'Investigation summary written', async () => {
      const note = await addNote(draftContext, runUser, {
        attribute_abstract: NOTE_ABSTRACT,
        content: buildInvestigationNoteContent(run),
        objects: R.uniq([subject.internal_id, ...(caseId ? [caseId] : [])]),
        objectMarking: markings,
        note_types: ['analysis'],
        confidence: leading?.confidence ?? undefined,
      });
      return note.internal_id;
    });
  }
  if (leading && allowedAction(InvestigationAutonomousAction.CreateRelationship) && leading.confidence >= policy.attribution_min_confidence) {
    const incidents = subject.entity_type === ENTITY_TYPE_INCIDENT
      ? [subject]
      : run.evidence.filter((evidence) => evidence.entity_type === ENTITY_TYPE_INCIDENT).slice(0, MAX_ATTRIBUTED_INCIDENTS);
    for (let index = 0; index < incidents.length; index += 1) {
      const incident = incidents[index] as { internal_id?: string; id?: string; entity_type: string };
      const fromId = incident.internal_id ?? incident.id as string;
      const candidateType = leading.candidate_type ?? '';
      const relationshipType = checkStixCoreRelationshipMapping(ENTITY_TYPE_INCIDENT, candidateType, RELATION_ATTRIBUTED_TO) ? RELATION_ATTRIBUTED_TO : RELATION_RELATED_TO;
      await attempt('opencti.relationship', `${relationshipType} ${leading.candidate_name ?? leading.candidate_id} (${leading.confidence}%)`, async () => {
        const relationship = await addStixCoreRelationship(draftContext, runUser, {
          relationship_type: relationshipType,
          fromId,
          toId: leading.candidate_id,
          confidence: leading.confidence,
          description: leading.explanation,
          objectMarking: markings,
        });
        return relationship.internal_id;
      });
    }
  }
  return { entries, patch, caseId };
};

const listDraftTypes = async (exec: RunExecution) => {
  const draftContext = await userContext(INVESTIGATION_MANAGER_USER, exec.run.draft_id);
  const [entities, relationships] = await Promise.all([
    topEntitiesList<BasicStoreEntity>(draftContext, INVESTIGATION_MANAGER_USER, [ABSTRACT_STIX_CORE_OBJECT], draftQuery()),
    topRelationsList<BasicStoreRelation>(draftContext, INVESTIGATION_MANAGER_USER, STIX_RELATIONSHIP_TYPES, draftQuery()) as unknown as Promise<BasicStoreRelation[]>,
  ]);
  // The investigated entity is loaded in the draft at creation without being changed.
  const changed = [...entities, ...relationships].filter((element) => element.internal_id !== exec.run.subject_id
    || (element as unknown as { draft_change?: { draft_operation?: string } }).draft_change?.draft_operation);
  return R.uniq(changed.map((element) => element.entity_type));
};

// Markings of everything the run read or wrote about, so its text never outlives their restrictions.
const collectRunMarkings = async (exec: RunExecution, subject: BasicStoreEntity) => {
  const draftContext = await userContext(INVESTIGATION_MANAGER_USER, exec.run.draft_id);
  const ids = R.uniq([...exec.run.evidence.map((evidence) => evidence.id), ...(exec.run.case_id ? [exec.run.case_id] : [])]).slice(0, INVESTIGATION_LIMITS.evidence);
  const elements = await findElements(draftContext, INVESTIGATION_MANAGER_USER, ids);
  return R.uniq([...markingIdsOf(subject), ...elements.flatMap((element) => markingIdsOf(element))]);
};

const finalizeRun = async (exec: RunExecution) => {
  const { run, runUser, now, policy } = exec;
  const subject = await loadSubject(exec);
  if (!subject) {
    await failRun(exec.liveContext, run.internal_id, 'The investigated entity is no longer accessible to the identity of the run');
    return;
  }
  // Final scoring with the latest weights of the evidence.
  const evidenceMeta = new Map<string, AchEvidenceMeta>(run.evidence.map((evidence) => [evidence.id, evidence]));
  const hypotheses = run.hypotheses.length > 0 ? scoreAchMatrix(run.hypotheses.map((hypothesis) => ({ ...hypothesis, evidence: hypothesis.evidence })), evidenceMeta) : [];
  const timeline = buildTimeline(run.evidence.map(toTimelineSource));
  const finalRun = { ...run, hypotheses, timeline };
  const { entries, patch, caseId } = await writeOutputs({ ...exec, run: finalRun }, subject);
  const markings = await collectRunMarkings({ ...exec, run: { ...finalRun, case_id: caseId } }, subject);
  const recommendationApprovals: InvestigationApproval[] = run.recommendations
    .filter((recommendation) => recommendation.status === InvestigationRecommendationStatus.AwaitingApproval
      && !run.approvals.some((approval) => approval.recommendation_id === recommendation.id))
    .map((recommendation) => ({
      id: uuidv4(),
      kind: InvestigationApprovalKind.Recommendation,
      status: InvestigationApprovalStatus.Pending,
      description: recommendation.text,
      reason: recommendation.rationale ?? null,
      connector_id: null,
      entity_id: caseId ?? run.subject_id,
      recommendation_id: recommendation.id,
      created_at: now.toISOString(),
    }));
  const draftTypes = run.draft_id ? await listDraftTypes({ ...exec, run: finalRun }) : [];
  const leadingConfidence = hypotheses[0]?.confidence ?? null;
  let validationWorkId: string | null = null;
  let nextStatus = InvestigationRunStatus.AwaitingApproval;
  let nextPhase = InvestigationRunPhase.AwaitingValidation;
  let reason: string | null = 'The investigation draft is waiting for an approval';
  const draftApproval: InvestigationApproval[] = [];
  if (!run.draft_id || draftTypes.length === 0) {
    nextStatus = InvestigationRunStatus.Completed;
    nextPhase = InvestigationRunPhase.Done;
    reason = run.status_reason ?? null;
  } else if (canAutoApproveDraft(policy, draftTypes, leadingConfidence)) {
    // Only low-risk objects (notes, observed data) above the confidence threshold.
    const work = await validateDraftWorkspace(exec.liveContext, runUser, run.draft_id);
    validationWorkId = work?.id ?? null;
    nextStatus = InvestigationRunStatus.Running;
    nextPhase = InvestigationRunPhase.Validating;
    reason = 'Low-risk draft approved automatically by the policy';
    entries.push(ledger(run, now, { tool: 'opencti.draft', description: reason, output_ref: validationWorkId }));
  } else {
    draftApproval.push({
      id: uuidv4(),
      kind: InvestigationApprovalKind.DraftValidation,
      status: InvestigationApprovalStatus.Pending,
      description: `Approve the investigation draft (${draftTypes.join(', ')})`,
      reason: hypotheses[0] ? hypotheses[0].explanation : null,
      connector_id: null,
      entity_id: caseId ?? run.subject_id,
      recommendation_id: null,
      created_at: now.toISOString(),
    });
  }
  await updateInvestigationRun(exec.liveContext, run.internal_id, (current) => ({
    ...patch,
    ...statusTransition(current, nextStatus, nextPhase, now, reason),
    hypotheses,
    timeline,
    objectMarking: markings,
    validation_work_id: validationWorkId,
    wave_started_at: now.toISOString(),
    approvals: [...current.approvals, ...recommendationApprovals, ...draftApproval].slice(-INVESTIGATION_LIMITS.approvals),
    plan: current.plan.map((step) => (step.status === InvestigationPlanStepStatus.Pending || step.status === InvestigationPlanStepStatus.Running
      ? { ...step, status: InvestigationPlanStepStatus.Done } : step)),
    steps: appendLedger(current.steps, entries),
  }));
  if (nextStatus === InvestigationRunStatus.Completed) {
    addInvestigationRunOutcomeCount(InvestigationRunStatus.Completed);
  }
};

const completeValidation = async (exec: RunExecution) => {
  const { run, runUser, now } = exec;
  const work = run.validation_work_id ? await loadWork(exec.liveContext, run.validation_work_id) : null;
  const startedAt = run.wave_started_at ? new Date(run.wave_started_at).getTime() : now.getTime();
  const timedOut = now.getTime() - startedAt > VALIDATION_TIMEOUT_MS;
  if (work && work.status !== 'complete' && !timedOut) {
    return; // The validation work is still being processed.
  }
  // Draft objects got new internal ids in the live graph: resolve them by standard id.
  const draftEvidence = run.evidence.filter((evidence) => evidence.in_draft && evidence.standard_id);
  const standardIds = R.uniq([...draftEvidence.map((evidence) => evidence.standard_id as string), ...(run.case_ids ?? [])]);
  const liveElements = await findElements(exec.liveContext, runUser, standardIds);
  const liveByStandard = new Map<string, string>(liveElements.map((element) => [element.standard_id as string, element.internal_id]));
  const evidence = run.evidence.map((item) => (item.in_draft && item.standard_id && liveByStandard.has(item.standard_id)
    ? { ...item, id: liveByStandard.get(item.standard_id) as string, in_draft: false }
    : item));
  const idMap = new Map(run.evidence.map((item, index) => [item.id, evidence[index].id]));
  const hypotheses = run.hypotheses.map((hypothesis) => ({
    ...hypothesis,
    evidence: hypothesis.evidence.map((cell) => ({ ...cell, evidence_id: idMap.get(cell.evidence_id) ?? cell.evidence_id })),
  }));
  const liveCase = liveElements.find((element) => (run.case_ids ?? []).includes(element.standard_id as string) && INVESTIGATION_CASE_SUBJECT_TYPES.includes(element.entity_type));
  const entries: InvestigationLedgerEntry[] = [ledger(run, now, {
    tool: 'opencti.draft',
    description: work?.status === 'complete' ? 'Investigation draft validated into the knowledge graph' : 'Draft validation not confirmed in time, ids resolved with what is available',
    status: work?.status === 'complete' ? InvestigationLedgerStatus.Done : InvestigationLedgerStatus.Failed,
    output_ref: run.validation_work_id ?? null,
  })];
  if (run.workspace_id) {
    const entityIds = R.uniq(evidence.filter((item) => !item.in_draft && !item.entity_type.includes('relationship')).map((item) => item.id))
      .slice(0, INVESTIGATION_LIMITS.evidence);
    try {
      if (entityIds.length > 0) {
        await workspaceEditField(exec.liveContext, runUser, run.workspace_id, [{ key: 'investigated_entities_ids', value: entityIds, operation: 'replace' as never }]);
      }
      entries.push(ledger(run, now, { tool: 'opencti.workspace', description: `Investigation graph updated (${entityIds.length} entities)`, output_ref: run.workspace_id }));
    } catch (error) {
      entries.push(ledger(run, now, { tool: 'opencti.workspace', description: 'Investigation graph not updated', status: InvestigationLedgerStatus.Failed, error: errorMessage(error) }));
    }
  }
  await updateInvestigationRun(exec.liveContext, run.internal_id, (current) => ({
    ...statusTransition(current, InvestigationRunStatus.Completed, InvestigationRunPhase.Done, now, current.status_reason ?? null),
    evidence,
    hypotheses,
    case_id: liveCase?.internal_id ?? current.case_id ?? null,
    case_ids: R.uniq([...(current.case_ids ?? []), ...(liveCase ? [liveCase.internal_id] : [])]),
    steps: appendLedger(current.steps, entries),
  }));
  addInvestigationRunOutcomeCount(InvestigationRunStatus.Completed);
};

// endregion

/**
 * Advance one run by one phase. Errors fail the run with their message,
 * never the manager.
 */
export const processInvestigationRun = async (context: AuthContext, runId: string) => {
  const run = await loadInvestigationRun(context, runId);
  if (!run || TERMINAL_RUN_STATUSES.includes(run.run_status) || run.run_status === InvestigationRunStatus.AwaitingApproval) {
    return;
  }
  try {
    const runUser = await resolveUserByIdFromCache(context, run.run_as_id);
    if (!runUser) {
      await failRun(context, runId, 'The identity of the run no longer exists');
      return;
    }
    const policy = run.policy_id ? await loadInvestigationPolicy(context, run.policy_id) : null;
    if (!policy) {
      await failRun(context, runId, 'The policy of the run no longer exists');
      return;
    }
    const now = new Date();
    let current = run;
    if (current.run_status === InvestigationRunStatus.Planned) {
      current = await updateInvestigationRun(context, runId, (fresh) => (fresh.run_status === InvestigationRunStatus.Planned
        ? statusTransition(fresh, InvestigationRunStatus.Running, InvestigationRunPhase.Initializing, now)
        : null));
      if (current.run_status !== InvestigationRunStatus.Running) return;
    }
    const exec: RunExecution = {
      run: current,
      runUser,
      policy,
      liveContext: await userContext(runUser),
      draftContext: await userContext(runUser, current.draft_id),
      now,
    };
    if (BUDGETED_PHASES.includes(current.run_phase) && isBudgetExhausted(current, now)) {
      await updateInvestigationRun(context, runId, (fresh) => ({
        run_phase: InvestigationRunPhase.Finalizing,
        status_reason: 'Budget exhausted: the investigation is concluded with the results collected so far',
        steps: appendLedger(fresh.steps, [ledger(fresh, now, { tool: 'opencti.budget', description: 'Budget exhausted', status: InvestigationLedgerStatus.Skipped })]),
      }));
      return;
    }
    switch (current.run_phase) {
      case InvestigationRunPhase.Initializing:
        await initializeRun(exec);
        break;
      case InvestigationRunPhase.Planning:
      case InvestigationRunPhase.Iterating:
      case InvestigationRunPhase.Concluding:
        await runAgentPhase(exec);
        break;
      case InvestigationRunPhase.Enriching:
        await dispatchEnrichments(exec);
        break;
      case InvestigationRunPhase.WaitingEnrichment:
        await collectEnrichments(exec);
        break;
      case InvestigationRunPhase.Finalizing:
        await finalizeRun(exec);
        break;
      case InvestigationRunPhase.Validating:
        await completeValidation(exec);
        break;
      default:
        break;
    }
  } catch (error) {
    logApp.error('[CASE AUTOPILOT] Investigation step error', { runId, cause: error });
    await failRun(context, runId, errorMessage(error));
  }
};

export const listInvestigationRunsToProcess = (context: AuthContext, limit: number) => {
  return topEntitiesList<BasicStoreEntityInvestigationRun>(context, INVESTIGATION_MANAGER_USER, [ENTITY_TYPE_INVESTIGATION_RUN], {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['run_status'], values: [InvestigationRunStatus.Planned, InvestigationRunStatus.Running] }],
      filterGroups: [],
    },
    orderBy: 'created_at',
    orderMode: 'asc' as never,
    first: limit,
  });
};
