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
// investigation run manager, one phase per tick and per run:
//   initializing  Draft, case, context snapshot and investigation graph;
//   starting      one run of the XTM One investigation engine;
//   investigating enrichment jobs the engine asked for, and the engine's goal
//                 plan, steps and evidence mirrored when its revision moves;
//   ingesting     the engine's conclusion grounded, ACH-scored and written
//                 into the Draft with its report and evidence;
//   validating    the approved Draft lands in the knowledge graph.
// Every read of knowledge and every write runs as the identity of the run
// (its markings, organizations and capabilities apply); writes land in the
// run's Draft.

import { v4 as uuidv4 } from 'uuid';
import { Promise as BluePromise } from 'bluebird';
import { createHash } from 'node:crypto';
import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreCommon, BasicStoreEntity, BasicStoreRelation, StoreEntity } from '../../types/store';
import type { BasicStoreSettings } from '../../types/settings';
import {
  FilterMode,
  FilterOperator,
  InvestigationApprovalKind,
  InvestigationApprovalStatus,
  InvestigationAutonomousAction,
  InvestigationEnrichmentRequestStatus,
  InvestigationRecommendationStatus,
  InvestigationRunPhase,
  InvestigationRunStatus,
} from '../../generated/graphql';
import { logApp } from '../../config/conf';
import { elFindByIds } from '../../database/engine';
import { internalFindByIds, pageEntitiesConnection, topEntitiesList, topRelationsList } from '../../database/middleware-loader';
import { deleteElementById, storeLoadByIdWithRefs } from '../../database/middleware';
import { getEntityFromCache } from '../../database/cache';
import { READ_DATA_INDICES_WITHOUT_INTERNAL, READ_INDEX_DRAFT_OBJECTS, READ_INDEX_INTERNAL_OBJECTS, READ_RELATIONSHIPS_INDICES } from '../../database/utils';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP, buildRefRelationKey } from '../../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { RELATION_ATTRIBUTED_TO, RELATION_MITIGATES, RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';
import { RELATION_OBJECT } from '../../schema/stixRefRelationship';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_INCIDENT,
} from '../../schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_CASE } from '../case/case-types';
import { ENTITY_TYPE_PIR } from '../pir/pir-types';
import { checkStixCoreRelationshipMapping } from '../../database/stix';
import { INVESTIGATION_MANAGER_USER, isUserHasCapability, KNOWLEDGE_KNENRICHMENT } from '../../utils/access';
import { addDraftWorkspace, validateDraftWorkspace } from '../draftWorkspace/draftWorkspace-domain';
import { addWorkspace, workspaceEditField } from '../workspace/workspace-domain';
import { askElementEnrichmentForConnectors } from '../../domain/stixCoreObject';
import { loadWorkById, worksForConnector } from '../../domain/work';
import { addNote } from '../../domain/note';
import { addReport } from '../../domain/report';
import { addStixCyberObservable } from '../../domain/stixCyberObservable';
import { addStixCoreRelationship } from '../../domain/stixCoreRelationship';
import { stixDomainObjectAddRelation, stixDomainObjectEditField } from '../../domain/stixDomainObject';
import { addCaseIncident } from '../case/case-incident/case-incident-domain';
import { addInvestigationEnrichmentJobCount, addInvestigationRunOutcomeCount } from '../../manager/telemetryManager';
import { isXtmOneConfigured } from '../playbook/components/ai-agent-shared';
import {
  CARRY_BOUNDARY_CODES,
  DRAFT_VALIDATION_FAILED_CODE,
  DRAFT_VALIDATION_UNCONFIRMED_CODE,
  EMPTY_OUTPUTS,
  ENGINE_CANCEL_PENDING,
  ENGINE_NO_AGENT,
  ENGINE_NOT_CONFIGURED,
  ENGINE_UNAVAILABLE,
  ENGINE_UNREACHABLE,
  ENTITY_TYPE_INVESTIGATION_RUN,
  INVESTIGATION_CASE_SUBJECT_TYPES,
  INVESTIGATION_LIMITS,
  MEMBER_RESTRICTED_CODE,
  SUBJECT_INACCESSIBLE_CODE,
  TERMINAL_RUN_STATUSES,
  ACTIVE_RUN_STATUSES,
  type BasicStoreEntityInvestigationPolicy,
  type BasicStoreEntityInvestigationRun,
  type InvestigationApproval,
  type InvestigationDeltaObject,
  type InvestigationEnrichmentRequest,
  type InvestigationEnrichmentWave,
  type InvestigationEvidence,
  type InvestigationOutputs,
  type InvestigationRecommendation,
} from './investigationRun-types';
import {
  deleteStoppedRunArtifacts,
  investigationIdentityContext,
  listPolicyEnrichmentConnectors,
  loadInvestigationRun,
  resolveRunIdentity,
  stopCancelledEngineRun,
  updateInvestigationRun,
  withRunActions,
} from './investigationRun-domain';
import { loadInvestigationPolicy } from './investigationPolicy-domain';
import {
  boundApprovals,
  buildTimeline,
  canAutoApproveDraft,
  computeWaveStatus,
  createRunWindow,
  ENRICHMENT_WAVE_TIMEOUT_MS,
  isBudgetExhausted,
  isTerminalRequest,
  remainingEnrichmentJobs,
  remainingMinutes,
  statusTransition,
  VALIDATION_TIMEOUT_MS,
  type DraftChanges,
  type TimelineSource,
} from './investigationRun-state';
import {
  buildAllowedIds,
  buildStartBody,
  conclusionCandidateIds,
  conclusionCourseOfActionIds,
  engineOutcome,
  groundConclusion,
  isReportPending,
  mirrorEvidence,
  mirrorReportSources,
  mirrorSteps,
  parseEngineKnowledge,
  type EngineContextEntity,
  type EngineEnrichmentConnector,
  type EngineInvestigation,
  type InvestigationEngineContext,
} from './investigationRun-engine';
import { scoreAchMatrix, type AchEvidenceMeta } from './investigationRun-ach';
import { cancelInvestigation, getInvestigation, resolveInvestigationAgent, startInvestigation, type EngineResult } from './investigationRun-xtm';
import { buildInvestigationNoteContent, buildInvestigationReportSections } from './investigationRun-report';
import {
  ATTRIBUTION_CANDIDATE_TYPES,
  authorIdOf,
  evidenceFromElement,
  intersectOrganizationIds,
  isCreationSharingWidened,
  isMemberRestricted,
  isObjectEvidence,
  isTransientFailure,
  markingIdsOf,
  organizationIdsOf,
  representativeNameOf,
  runCitedIds,
  runReceivedIds,
  withheldRunContent,
  withoutMemberRestricted,
} from './investigationRun-utils';

export const INVESTIGATION_MANAGER_CONTEXT = 'investigation_run_manager';

const NOTE_ABSTRACT = 'Case Autopilot - autonomous investigation summary';
const FINDING_NOTE_ABSTRACT = 'Case Autopilot - investigation finding';
const MAX_CASE_OBJECTS = 200;
const MAX_ATTRIBUTED_INCIDENTS = 5;
// After cancelling the engine for the time budget, how long OpenCTI waits for
// the engine to confirm before it concludes with what it mirrored.
const BUDGET_CANCEL_GRACE_MS = 2 * 60 * 1000;
const OBSERVABLE_INPUT_KEYS: Record<string, string> = {
  'Domain-Name': 'DomainName',
  'IPv4-Addr': 'IPv4Addr',
  'IPv6-Addr': 'IPv6Addr',
  Url: 'Url',
};
const ENGINE_FAILURE_REASONS: Record<string, string> = {
  [ENGINE_NOT_CONFIGURED]: 'XTM One is not connected to this platform: Case Autopilot needs the XTM One investigation engine',
  engine_disabled: 'The connected XTM One does not run investigations (Deep Investigation is turned off)',
  [ENGINE_UNAVAILABLE]: 'The connected XTM One does not provide the investigation engine: upgrade XTM One',
  [ENGINE_NO_AGENT]: 'No agent of the connected XTM One answers the autonomous investigation intent',
  [ENGINE_UNREACHABLE]: 'The XTM One investigation engine cannot be reached',
};
const SUBJECT_INACCESSIBLE_REASON = 'The investigated entity is no longer accessible to the identity of the run';
const SUBJECT_INACCESSIBLE = { reason: SUBJECT_INACCESSIBLE_REASON, code: SUBJECT_INACCESSIBLE_CODE };
// A deleted, locked or expired identity reads nothing any more: the same boundary as a subject it can no longer read.
const IDENTITY_UNAVAILABLE = { reason: 'The identity of the run no longer exists or can no longer use the platform', code: SUBJECT_INACCESSIBLE_CODE };
const MEMBER_RESTRICTED_REASON = 'An entity of the investigation is now restricted to authorized members: Case Autopilot stopped and withheld what it had found';
// Runs whose engine run is stopped after them: cancelled by an analyst, or stopped at a member restriction.
const STOPPED_RUN_STATUSES: string[] = [InvestigationRunStatus.Cancelled, InvestigationRunStatus.Failed];

interface RunExecution {
  run: BasicStoreEntityInvestigationRun;
  runUser: AuthUser;
  policy: BasicStoreEntityInvestigationPolicy;
  liveContext: AuthContext;
  draftContext: AuthContext;
  now: Date;
  // Executed under the run actions lock (ingestion, revalidation): not taken again.
  holdsActions?: boolean;
}

// region helpers

interface WorkState {
  id: string;
  status?: string;
  // What the worker could not ingest; a complete work with errors wrote only part of its bundle.
  errors?: Array<{ message?: string }>;
}

const loadWork = async (context: AuthContext, workId: string): Promise<WorkState | null> => {
  const work = await loadWorkById(context, INVESTIGATION_MANAGER_USER, workId) as WorkState | undefined;
  return work ?? null;
};

// The work an interrupted dispatch created for a connector in the draft of the
// run: dispatches run one at a time under the run actions lock, so a work of
// that connector and draft created since and known to no request is that one.
// With a source, only a work enriching that entity (by standard id) counts.
const findStartedEnrichmentWork = async (exec: RunExecution, current: BasicStoreEntityInvestigationRun, connectorId: string, since: number, sourceId?: string) => {
  if (!current.draft_id) return null;
  const known = new Set([...current.enrichment_requests.flatMap((item) => (item.work_id ? [item.work_id] : [])), ...(current.pending_work_ids ?? [])]);
  const filters = [
    { key: 'draft_context', values: [current.draft_id], operator: 'eq', mode: 'or' },
    ...(sourceId ? [{ key: 'event_source_id', values: [sourceId], operator: 'eq', mode: 'or' }] : []),
  ];
  const works = await worksForConnector(exec.liveContext, INVESTIGATION_MANAGER_USER, connectorId, {
    first: 10,
    filters: { mode: 'and', filters, filterGroups: [] },
  }) as Array<WorkState & { timestamp?: string }>;
  const created = works.find((work) => !known.has(work.id) && !!work.timestamp && new Date(work.timestamp).getTime() >= since - 1000);
  return created?.id ?? null;
};

// Elements by internal or standard id, among the data the user can see.
const findElements = async <T extends BasicStoreEntity = BasicStoreEntity>(
  context: AuthContext,
  user: AuthUser,
  ids: string[],
  opts: { type?: string; withInternal?: boolean } = {},
): Promise<T[]> => {
  if (ids.length === 0) return [];
  const indices = opts.withInternal ? [...READ_DATA_INDICES_WITHOUT_INTERNAL, READ_INDEX_INTERNAL_OBJECTS] : READ_DATA_INDICES_WITHOUT_INTERNAL;
  const options = opts.type ? { type: opts.type } : { indices };
  return await elFindByIds<T>(context, user, ids, options) as T[];
};

// The job an earlier pass started for a queued request and could not record
// (the connector accepted it, then the run was not updated): a run holds one
// live request per entity and connector, so an unknown work of that connector
// on that entity in the run draft, created since the request, is that job.
const findUnrecordedEnrichmentWork = async (exec: RunExecution, current: BasicStoreEntityInvestigationRun, request: InvestigationEnrichmentRequest) => {
  if (!current.draft_id) return null;
  const [entity] = await findElements(exec.draftContext, exec.runUser, [request.entity_id]);
  if (!entity?.standard_id) return null;
  return findStartedEnrichmentWork(exec, current, request.connector_id, new Date(request.created_at).getTime(), entity.standard_id);
};

const draftQuery = (filters?: unknown, first = 500) => ({ indices: [READ_INDEX_DRAFT_OBJECTS], filters: filters as never, first });

const STIX_RELATIONSHIP_TYPES = [ABSTRACT_STIX_CORE_RELATIONSHIP, STIX_SIGHTING_RELATIONSHIP];

const userContext = (user: AuthUser, draftId?: string | null): Promise<AuthContext> => investigationIdentityContext(INVESTIGATION_MANAGER_CONTEXT, user, draftId);

const jwtUserOf = (user: AuthUser) => ({ id: user.id, user_email: user.user_email });

const errorMessage = (error: unknown) => (error instanceof Error ? error.message : String(error)).slice(0, INVESTIGATION_LIMITS.textLength);

const isRelationshipType = (entityType?: string | null) => !!entityType && (entityType.includes('relationship') || entityType === STIX_SIGHTING_RELATIONSHIP);

// Evidence the investigation graph can show: live entities, not relationships.
const isGraphEntity = (evidence: InvestigationEvidence) => isObjectEvidence(evidence) && !evidence.in_draft && !isRelationshipType(evidence.entity_type);

const toTimelineSource = (evidence: InvestigationEvidence): TimelineSource => ({
  id: evidence.id,
  entity_type: evidence.entity_type ?? 'Unknown',
  name: evidence.label,
  created: evidence.created,
  first_seen: evidence.first_seen,
  last_seen: evidence.last_seen,
});

const toAchMeta = (evidence: InvestigationEvidence): AchEvidenceMeta => ({
  id: evidence.id,
  standard_id: evidence.standard_id,
  entity_type: evidence.entity_type,
  name: evidence.label,
  confidence: evidence.confidence,
  author_reliability: evidence.author_reliability,
});

// Reliability of the authors of the evidence, read from their identities.
const loadAuthorReliabilities = async (context: AuthContext, user: AuthUser, elements: object[]) => {
  const authorIds = R.uniq(elements.map((element) => authorIdOf(element)).filter((id): id is string => !!id));
  if (authorIds.length === 0) return new Map<string, string>();
  const authors = await findElements<BasicStoreEntity & { x_opencti_reliability?: string }>(context, user, authorIds);
  return new Map(authors.filter((author) => author.x_opencti_reliability).map((author) => [author.internal_id, author.x_opencti_reliability as string]));
};

const elementEvidence = (elements: object[], reliabilities: Map<string, string>, draftId?: string | null) => {
  return elements.map((element) => {
    const authorId = authorIdOf(element);
    return evidenceFromElement(element, { draftId, authorReliability: authorId ? reliabilities.get(authorId) ?? null : null });
  });
};

const toEngineEntity = (evidence: InvestigationEvidence, description?: string | null): EngineContextEntity => ({
  id: evidence.id,
  standard_id: evidence.standard_id,
  entity_type: evidence.entity_type ?? 'Unknown',
  name: evidence.label,
  description: description ?? null,
  created: evidence.created,
  first_seen: evidence.first_seen,
  last_seen: evidence.last_seen,
  confidence: evidence.confidence,
  author_reliability: evidence.author_reliability,
});

// The gates still open on a run that ends: its pending approvals are rejected
// and its enrichment jobs not started yet are skipped, so nothing of it runs.
const closeOpenGates = (current: BasicStoreEntityInvestigationRun, now: Date, reason: string) => ({
  approvals: current.approvals.map((approval) => (approval.status === InvestigationApprovalStatus.Pending
    ? { ...approval, status: InvestigationApprovalStatus.Rejected, decided_at: now.toISOString(), rejection_reason: reason }
    : approval)),
  enrichment_requests: current.enrichment_requests.map((request) => (request.status === InvestigationEnrichmentRequestStatus.Queued
    || request.status === InvestigationEnrichmentRequestStatus.AwaitingApproval
    ? { ...request, status: InvestigationEnrichmentRequestStatus.Skipped, error: reason, completed_at: now.toISOString() }
    : request)),
});

// An engine run still going when its run fails is stopped as well, and retried
// on later passes until the engine confirms.
const failRun = async (context: AuthContext, runId: string, reason: string, code?: string | null) => {
  const now = new Date();
  let failed = false;
  let engineRunning = false;
  await updateInvestigationRun(context, runId, (current) => {
    if (TERMINAL_RUN_STATUSES.includes(current.run_status)) return null;
    failed = true;
    engineRunning = current.run_phase === InvestigationRunPhase.Investigating && !!current.xtm_investigation_id && !current.budget_cancelled;
    return {
      ...statusTransition(current, InvestigationRunStatus.Failed, InvestigationRunPhase.Done, now, reason),
      end_reason_code: code ?? current.end_reason_code ?? null,
      pending_work_ids: [],
      ...closeOpenGates(current, now, 'Investigation failed'),
      ...(engineRunning ? { xtm_status: ENGINE_CANCEL_PENDING, engine_failures: 0 } : {}),
    };
  });
  if (!failed) return;
  addInvestigationRunOutcomeCount(InvestigationRunStatus.Failed);
  logApp.warn('[CASE AUTOPILOT] Investigation failed', { runId, reason, code });
  if (engineRunning) {
    await stopCancelledEngineRun(context, runId);
  }
};

// A cancellation ends a run under the same run lock as these updates: a phase
// update applies only while the run is still running, so a run cancelled since
// its phase started is never advanced again.
const updateRunningRun = (
  context: AuthContext,
  runId: string,
  mutate: (run: BasicStoreEntityInvestigationRun) => Record<string, unknown> | null,
) => updateInvestigationRun(context, runId, (current) => (current.run_status === InvestigationRunStatus.Running ? mutate(current) : null));

// A call to the engine that failed: an engine that cannot run investigations
// fails the run at once with its reason; a transient failure is retried on the
// next ticks, within a bound.
const handleEngineFailure = async (exec: RunExecution, result: Extract<EngineResult<unknown>, { ok: false }>) => {
  const { run } = exec;
  const permanent = result.failure !== ENGINE_UNREACHABLE;
  const failures = (run.engine_failures ?? 0) + 1;
  if (permanent || failures >= INVESTIGATION_LIMITS.engineFailures) {
    await failRun(exec.liveContext, run.internal_id, ENGINE_FAILURE_REASONS[result.failure] ?? result.message, result.failure);
    return;
  }
  await updateRunningRun(exec.liveContext, run.internal_id, () => ({ engine_failures: failures }));
};

// endregion

// region context

// Relationships around the seed entities and the entities on their other side.
const collectNeighborhood = async (exec: RunExecution, seedIds: string[]) => {
  if (seedIds.length === 0) return { relationships: [] as BasicStoreRelation[], entities: [] as BasicStoreEntity[] };
  const relationships = await topRelationsList<BasicStoreRelation>(exec.draftContext, exec.runUser, STIX_RELATIONSHIP_TYPES, {
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
  const readable = withoutMemberRestricted(entities);
  const readableIds = new Set([...seedIds, ...readable.map((entity) => entity.internal_id)]);
  // A relationship to an entity the run may not read is left out with it, and so
  // is a relationship restricted to authorized members, as the entities are.
  return {
    relationships: withoutMemberRestricted(relationships).filter((relationship) => readableIds.has(relationship.fromId) && readableIds.has(relationship.toId)),
    entities: readable,
  };
};

// Objects of a case (the case of the run or the investigated case).
const collectCaseObjects = async (exec: RunExecution, caseId: string) => {
  const refs = await topRelationsList<BasicStoreRelation>(exec.draftContext, exec.runUser, RELATION_OBJECT, {
    fromId: caseId,
    first: INVESTIGATION_LIMITS.contextEntities,
  }) as unknown as BasicStoreRelation[];
  // A link restricted to authorized members brings nothing into the investigation, whoever the identity.
  const ids = R.uniq(withoutMemberRestricted(refs).map((ref) => ref.toId));
  if (ids.length === 0) return [];
  const objects = await elFindByIds<BasicStoreEntity>(exec.draftContext, exec.runUser, ids, { indices: READ_DATA_INDICES_WITHOUT_INTERNAL }) as BasicStoreEntity[];
  return withoutMemberRestricted(objects);
};

interface CollectedContext {
  engineContext: InvestigationEngineContext;
  contextEvidence: InvestigationEvidence[];
  candidateInfo: Map<string, { name?: string | null; entity_type?: string | null; standard_id?: string | null }>;
  // Everything sent to the engine: the run carries the access of all of it.
  contextElements: BasicStoreCommon[];
}

// The context snapshot sent to the engine: what the knowledge graph already
// says around the investigated entity and its case, as the run identity sees it.
const collectInvestigationContext = async (exec: RunExecution, subject: BasicStoreEntity): Promise<CollectedContext> => {
  const { run, runUser, draftContext } = exec;
  const caseId = run.case_id && run.case_id !== subject.internal_id ? run.case_id : null;
  const caseObjects = caseId ? await collectCaseObjects(exec, caseId) : [];
  const subjectCaseObjects = INVESTIGATION_CASE_SUBJECT_TYPES.includes(subject.entity_type) ? await collectCaseObjects(exec, subject.internal_id) : [];
  const evidenceIds = run.evidence.filter(isObjectEvidence).map((evidence) => evidence.opencti_id as string);
  const seedIds = R.uniq([subject.internal_id, ...caseObjects.map((object) => object.internal_id), ...subjectCaseObjects.map((object) => object.internal_id), ...evidenceIds]);
  const { relationships, entities: neighbors } = await collectNeighborhood(exec, seedIds);
  const knownElements = R.uniqBy((element: BasicStoreEntity) => element.internal_id, [...caseObjects, ...subjectCaseObjects, ...neighbors])
    .filter((element) => element.internal_id !== subject.internal_id);
  // Candidates: threats in the neighborhood and threats one hop further, through relationships the run may use.
  const candidateRelations = withoutMemberRestricted(await topRelationsList<BasicStoreRelation>(draftContext, runUser, ABSTRACT_STIX_CORE_RELATIONSHIP, {
    fromOrToId: R.uniq([...seedIds, ...knownElements.map((element) => element.internal_id)]).slice(0, 100),
    first: INVESTIGATION_LIMITS.contextRelationships,
  }) as unknown as BasicStoreRelation[]);
  const candidateIds = R.uniq([
    ...knownElements.filter((element) => ATTRIBUTION_CANDIDATE_TYPES.includes(element.entity_type)).map((element) => element.internal_id),
    ...candidateRelations.flatMap((relationship) => [
      ATTRIBUTION_CANDIDATE_TYPES.includes(relationship.fromType) ? relationship.fromId : null,
      ATTRIBUTION_CANDIDATE_TYPES.includes(relationship.toType) ? relationship.toId : null,
    ]).filter((id): id is string => !!id),
  ]).slice(0, INVESTIGATION_LIMITS.candidates);
  const knownIds = new Set(knownElements.map((element) => element.internal_id));
  const extraCandidates = withoutMemberRestricted(await findElements(draftContext, runUser, candidateIds.filter((id) => !knownIds.has(id))));
  const candidates = [...knownElements, ...extraCandidates].filter((element) => ATTRIBUTION_CANDIDATE_TYPES.includes(element.entity_type));
  // Courses of action mitigating the techniques in scope.
  const attackPatternIds = knownElements.filter((element) => element.entity_type === ENTITY_TYPE_ATTACK_PATTERN).map((element) => element.internal_id);
  const mitigations = attackPatternIds.length === 0 ? [] : withoutMemberRestricted(await topRelationsList<BasicStoreRelation>(draftContext, runUser, RELATION_MITIGATES, {
    toId: attackPatternIds.slice(0, 100),
    first: INVESTIGATION_LIMITS.coursesOfAction,
  }) as unknown as BasicStoreRelation[]);
  const coaIds = R.uniq([
    ...knownElements.filter((element) => element.entity_type === ENTITY_TYPE_COURSE_OF_ACTION).map((element) => element.internal_id),
    ...mitigations.map((relationship) => relationship.fromId),
  ]).slice(0, INVESTIGATION_LIMITS.coursesOfAction);
  // Recommendations, the note and the report may quote these, so member-restricted ones are left out.
  const coaElements = await findElements<BasicStoreEntity & { x_mitre_id?: string }>(draftContext, runUser, coaIds, { type: ENTITY_TYPE_COURSE_OF_ACTION });
  const coursesOfAction = withoutMemberRestricted(coaElements);
  // PIRs the candidates matter to, among the PIRs the identity can see.
  const pirScores = new Map<string, number>();
  candidates.forEach((candidate) => {
    ((candidate as unknown as { pir_information?: Array<{ pir_id: string; pir_score: number }> }).pir_information ?? []).forEach(({ pir_id, pir_score }) => {
      pirScores.set(pir_id, Math.max(pirScores.get(pir_id) ?? 0, pir_score));
    });
  });
  const pirIds = Array.from(pirScores.keys());
  const pirElements = pirIds.length === 0 ? [] : await internalFindByIds<BasicStoreEntity>(exec.liveContext, runUser, pirIds, { type: ENTITY_TYPE_PIR }) as BasicStoreEntity[];
  const pirs = withoutMemberRestricted(pirElements);
  const reliabilities = await loadAuthorReliabilities(draftContext, runUser, [subject, ...knownElements, ...candidates]);
  const contextEvidence = elementEvidence(knownElements, reliabilities, run.draft_id).slice(0, INVESTIGATION_LIMITS.contextEntities);
  const connectors = await listPolicyEnrichmentConnectors(exec.liveContext, runUser, exec.policy);
  const engineConnectors: EngineEnrichmentConnector[] = connectors.map((connector) => ({
    id: connector.internal_id,
    name: connector.name,
    scope: connector.connector_scope ?? [],
    requires_approval: (exec.policy.approval_connector_ids ?? []).includes(connector.internal_id),
  }));
  const subjectEvidence = elementEvidence([subject], reliabilities, run.draft_id)[0];
  const candidateInfo = new Map(candidates.map((candidate) => [candidate.internal_id, {
    name: representativeNameOf(candidate),
    entity_type: candidate.entity_type,
    standard_id: candidate.standard_id,
  }]));
  const engineContext: InvestigationEngineContext = {
    subject: toEngineEntity(subjectEvidence, (subject as unknown as { description?: string }).description?.slice(0, INVESTIGATION_LIMITS.textLength) ?? null),
    entities: contextEvidence.map((evidence) => toEngineEntity(evidence)),
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
      name: representativeNameOf(candidate) ?? candidate.internal_id,
      aliases: ((candidate as unknown as { aliases?: string[] }).aliases ?? []).slice(0, 10),
    })),
    courses_of_action: coursesOfAction.map((coa) => ({
      id: coa.internal_id,
      standard_id: coa.standard_id,
      name: representativeNameOf(coa) ?? coa.internal_id,
      x_mitre_id: coa.x_mitre_id ?? null,
    })),
    pir: pirs.map((pir) => ({ id: pir.internal_id, name: (pir as unknown as { name: string }).name, score: pirScores.get(pir.internal_id) ?? 0 })),
    connectors: engineConnectors,
    allowed_actions: exec.policy.allowed_actions,
  };
  const sentEntityIds = new Set(contextEvidence.map((evidence) => evidence.id));
  const contextElements: BasicStoreCommon[] = [
    subject,
    ...knownElements.filter((element) => sentEntityIds.has(element.internal_id)),
    ...relationships.slice(0, INVESTIGATION_LIMITS.contextRelationships),
    ...candidates,
    ...coursesOfAction,
    ...pirs,
  ];
  return { engineContext, contextEvidence, candidateInfo, contextElements };
};

// endregion

// region initialization and engine start

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
  const { run, runUser, liveContext } = exec;
  const subject = await storeLoadByIdWithRefs<StoreEntity>(liveContext, runUser, run.subject_id);
  if (!subject) {
    await stopAtCarryBoundary(exec, SUBJECT_INACCESSIBLE);
    return;
  }
  if (!run.case_id && run.create_case) {
    if (!exec.policy.allowed_actions.includes(InvestigationAutonomousAction.CreateCase)) {
      await failRun(liveContext, run.internal_id, 'The policy of the run no longer allows creating its case');
      return;
    }
    const settings = await getEntityFromCache<BasicStoreSettings>(liveContext, INVESTIGATION_MANAGER_USER, ENTITY_TYPE_SETTINGS);
    if (isCreationSharingWidened(runUser, settings, liveContext.user_inside_platform_organization ?? false, organizationIdsOf(subject))) {
      // The platform would share the new case with the organizations of the identity, beyond the ones of the subject.
      await failRun(liveContext, run.internal_id, 'The identity of the investigation cannot restrict the sharing of a new case to the organizations of the investigated entity: pick a case');
      return;
    }
  }
  const patch: Record<string, unknown> = {};
  // What initialization creates is recorded at once: a pass interrupted after a
  // creation is retried with it instead of creating it again.
  const recordCreated = async (fields: Record<string, unknown>) => {
    Object.assign(patch, fields);
    await updateInvestigationRun(liveContext, run.internal_id, () => fields);
  };
  // Draft: every write of the run lands here, nothing reaches the live graph without approval.
  let draftId = run.draft_id ?? null;
  if (!draftId) {
    const draft = await addDraftWorkspace(liveContext, runUser, {
      name: run.name,
      description: 'Draft of a Case Autopilot investigation: the evidence, the report, the notes and the relationships it proposes.',
      entity_id: subject.internal_id,
    });
    draftId = draft.id;
    await recordCreated({ draft_id: draftId });
  }
  const draftContext = await userContext(runUser, draftId);
  // Case: the investigated case, the case picked at launch, a new case for an
  // indicator or an observable, or for an incident the latest case holding it.
  if (!run.case_id) {
    if (INVESTIGATION_CASE_SUBJECT_TYPES.includes(subject.entity_type)) {
      patch.case_id = subject.internal_id;
      patch.case_ids = R.uniq([...(run.case_ids ?? []), subject.internal_id, subject.standard_id]);
    } else if (run.create_case) {
      const created = await addCaseIncident(draftContext, runUser, {
        name: `Investigation - ${representativeNameOf(subject) ?? subject.internal_id}`.slice(0, 250),
        description: 'Case opened by a Case Autopilot investigation.',
        objects: [subject.internal_id],
        objectMarking: markingIdsOf(subject),
        objectOrganization: organizationIdsOf(subject),
      });
      await recordCreated({ case_id: created.internal_id, case_ids: R.uniq([...(run.case_ids ?? []), created.internal_id, created.standard_id]) });
    } else if (subject.entity_type === ENTITY_TYPE_INCIDENT) {
      const existingCase = await findCaseContainingSubject(exec, subject.internal_id);
      // A case restricted to authorized members is not read into the investigation.
      if (existingCase && !isMemberRestricted(existingCase)) {
        patch.case_id = existingCase.internal_id;
        patch.case_ids = R.uniq([...(run.case_ids ?? []), existingCase.internal_id, existingCase.standard_id]);
        // Its objects are read into the engine context: the run carries its restrictions from now on.
        patch.objectMarking = R.uniq([...markingIdsOf(run), ...markingIdsOf(existingCase)]);
        patch.objectOrganization = intersectOrganizationIds(organizationIdsOf(run), [existingCase]);
      }
    }
  }
  // Investigation graph, the canvas the analyst opens when the run completes.
  if (!run.workspace_id && isUserHasCapability(runUser, 'INVESTIGATION_INUPDATE')) {
    const execInDraft: RunExecution = { ...exec, run: { ...run, ...patch } as BasicStoreEntityInvestigationRun, draftContext };
    const collected = await collectInvestigationContext(execInDraft, subject);
    const liveEntityIds = [subject.internal_id, ...collected.contextEvidence.filter(isGraphEntity).map((evidence) => evidence.id)];
    const workspace = await addWorkspace(liveContext, runUser, {
      type: 'investigation',
      name: run.name,
      description: 'Investigation graph of a Case Autopilot investigation.',
      investigated_entities_ids: R.uniq(liveEntityIds).slice(0, INVESTIGATION_LIMITS.evidence),
    });
    await recordCreated({ workspace_id: workspace.id });
  }
  patch.run_phase = InvestigationRunPhase.Starting;
  // A run cancelled while it was initialized is not advanced, and keeps the
  // references to what its initialization created, as if cancelled just after.
  await updateInvestigationRun(liveContext, run.internal_id, (current) => (current.run_status === InvestigationRunStatus.Running
    ? patch
    : R.omit(['run_phase'], patch)));
};

// Start one engine run: the first one, or a continuation of the previous one.
const startEngine = async (exec: RunExecution) => {
  const { run, runUser, now, policy } = exec;
  if (isBudgetExhausted(run, now)) {
    await failRun(exec.liveContext, run.internal_id, 'The time budget of the investigation is spent');
    return;
  }
  if (!isXtmOneConfigured()) {
    await failRun(exec.liveContext, run.internal_id, ENGINE_FAILURE_REASONS[ENGINE_NOT_CONFIGURED], ENGINE_NOT_CONFIGURED);
    return;
  }
  const subject = await loadSubject(exec);
  if (!subject) {
    await stopAtCarryBoundary(exec, SUBJECT_INACCESSIBLE);
    return;
  }
  // A continuation starts long after the launch checked the subject and its case.
  const boundary = await findCarryBoundary(exec, []);
  if (boundary) {
    await stopAtCarryBoundary(exec, boundary);
    return;
  }
  const agentSlug = await resolveInvestigationAgent(jwtUserOf(runUser), policy.agent_slug);
  if (!agentSlug) {
    await failRun(exec.liveContext, run.internal_id, ENGINE_FAILURE_REASONS[ENGINE_NO_AGENT], ENGINE_NO_AGENT);
    return;
  }
  const collected = await collectInvestigationContext(exec, subject);
  const allowed = buildAllowedIds(collected.engineContext);
  const body = buildStartBody({
    run,
    policy,
    agentSlug,
    subjectName: representativeNameOf(subject) ?? subject.internal_id,
    context: collected.engineContext,
    allowed,
    remainingMinutes: remainingMinutes(run, now),
    remainingEnrichmentJobs: remainingEnrichmentJobs(run),
    continuesInvestigationId: run.continues_investigation_id ?? null,
  });
  // The engine may use anything of its context without citing it: the run carries the access of all of it.
  const carried = await withLiveVersions(collected.contextElements);
  // Collecting the context takes time: a run cancelled meanwhile starts nothing.
  const beforeStart = await loadInvestigationRun(exec.liveContext, run.internal_id);
  if (!beforeStart || TERMINAL_RUN_STATUSES.includes(beforeStart.run_status)) {
    return;
  }
  const result = await startInvestigation(jwtUserOf(runUser), body, run.draft_id);
  if (!result.ok) {
    await handleEngineFailure(exec, result);
    return;
  }
  const engine = result.value;
  const outcome = { endedMeanwhile: false };
  const recordStarted = (mutate: (current: BasicStoreEntityInvestigationRun) => Record<string, unknown> | null) => updateInvestigationRun(exec.liveContext, run.internal_id, mutate)
    .catch(async (error) => {
      // An engine run the investigation does not know about would run for nothing: a retried start begins a new one.
      await cancelInvestigation(jwtUserOf(runUser), engine.id).catch((cancelError) => {
        logApp.warn('[CASE AUTOPILOT] Unrecorded engine run not stopped', { runId: run.internal_id, investigationId: engine.id, cause: cancelError });
      });
      throw error;
    });
  await recordStarted((current) => {
    if (TERMINAL_RUN_STATUSES.includes(current.run_status)) {
      // Cancelled while the engine was starting: its run is kept in the history and stopped below.
      outcome.endedMeanwhile = true;
      return {
        xtm_investigation_id: engine.id,
        xtm_investigation_ids: R.uniq([...(current.xtm_investigation_ids ?? []), engine.id]),
        xtm_status: ENGINE_CANCEL_PENDING,
        engine_failures: 0,
      };
    }
    return {
      objectMarking: R.uniq([...markingIdsOf(current), ...carried.flatMap((element) => markingIdsOf(element))]),
      objectOrganization: intersectOrganizationIds(organizationIdsOf(current), carried),
      context_ids: R.uniq([...collected.contextElements.map((element) => element.internal_id), ...(current.context_ids ?? [])])
        .slice(0, INVESTIGATION_LIMITS.contextSources),
      agent_slug: agentSlug,
      pack_id: body.pack,
      xtm_investigation_id: engine.id,
      xtm_investigation_ids: R.uniq([...(current.xtm_investigation_ids ?? []), engine.id]),
      xtm_revision: -1,
      xtm_status: engine.status,
      xtm_completed_at: null,
      continues_investigation_id: null,
      budget_cancelled: false,
      engine_failures: 0,
      // Each engine run counts its iterations from 0: a continuation adds to what earlier runs used.
      budget: { ...current.budget, iterations_base: current.budget.used_iterations ?? 0 },
      goal_plan: engine.goal_plan ?? current.goal_plan ?? null,
      end_reason_code: null,
      status_reason: null,
      run_phase: InvestigationRunPhase.Investigating,
    };
  });
  if (outcome.endedMeanwhile) {
    await stopCancelledEngineRun(exec.liveContext, run.internal_id);
  }
};

// endregion

// region enrichment waves

const deltaOf = async (exec: RunExecution, wave: InvestigationEnrichmentWave, requests: InvestigationEnrichmentRequest[]): Promise<InvestigationDeltaObject[]> => {
  const filters = {
    mode: FilterMode.And,
    filters: [{ key: ['updated_at'], values: [wave.requested_at], operator: FilterOperator.Gte }],
    filterGroups: [],
  };
  const query = draftQuery(filters, INVESTIGATION_LIMITS.waveDelta);
  const [entities, relationships] = await Promise.all([
    topEntitiesList<BasicStoreEntity>(exec.draftContext, exec.runUser, [ABSTRACT_STIX_CORE_OBJECT], query),
    topRelationsList<BasicStoreRelation>(exec.draftContext, exec.runUser, STIX_RELATIONSHIP_TYPES, query) as unknown as Promise<BasicStoreRelation[]>,
  ]);
  const connectorNames = R.uniq(requests.map((request) => request.connector_name ?? request.connector_id));
  // A relationship to an entity the run may not read is left out with it, as in the context.
  const endpointIds = R.uniq(relationships.flatMap((relationship) => [relationship.fromId, relationship.toId]));
  const readableEndpoints = new Set(withoutMemberRestricted(await findElements(exec.draftContext, exec.runUser, endpointIds))
    .map((element) => element.internal_id));
  const readableRelationships = relationships.filter((relationship) => readableEndpoints.has(relationship.fromId) && readableEndpoints.has(relationship.toId));
  // Sent to the engine: what is restricted to authorized members stays out, as in the context.
  return withoutMemberRestricted([...entities, ...readableRelationships])
    .filter((element) => (element as unknown as { draft_change?: { draft_operation?: string } }).draft_change?.draft_operation)
    .slice(0, INVESTIGATION_LIMITS.waveDelta)
    .map((element) => ({
      id: element.internal_id,
      standard_id: element.standard_id ?? null,
      entity_type: element.entity_type,
      representative: representativeNameOf(element),
      connector_name: connectorNames.length === 1 ? connectorNames[0] : null,
      action: (element as unknown as { draft_change?: { draft_operation?: string } }).draft_change?.draft_operation === 'create' ? 'created' : 'updated',
      from_id: (element as unknown as { fromId?: string }).fromId ?? null,
      to_id: (element as unknown as { toId?: string }).toId ?? null,
    }));
};

/**
 * Run the enrichment jobs the engine asked for: dispatch the queued ones
 * within the budget, follow the dispatched ones, and once every job of a wave
 * ended, record what the wave brought into the Draft. Returns the run as
 * updated, so the same tick keeps going with it.
 */
const processEnrichments = async (exec: RunExecution): Promise<BasicStoreEntityInvestigationRun> => {
  const { run, runUser, now } = exec;
  const queued = run.enrichment_requests.filter((request) => request.status === InvestigationEnrichmentRequestStatus.Queued);
  const dispatched = run.enrichment_requests.filter((request) => request.status === InvestigationEnrichmentRequestStatus.Dispatched);
  const openWaves = (run.enrichment_waves ?? []).filter((wave) => !wave.delta_computed);
  if (queued.length === 0 && dispatched.length === 0 && openWaves.length === 0) return run;
  const requestPatches = new Map<string, Partial<InvestigationEnrichmentRequest>>();
  // Jobs started by this tick, already recorded on the run.
  const started = new Map<string, Partial<InvestigationEnrichmentRequest>>();
  // Dispatch, within the enrichment budget.
  const canEnrich = isUserHasCapability(runUser, KNOWLEDGE_KNENRICHMENT);
  const budgetLeft = Math.max(0, run.budget.max_enrichment_jobs - run.budget.used_enrichment_jobs);
  let dispatchedCount = 0;
  for (let index = 0; index < queued.length; index += 1) {
    const request = queued[index];
    if (!canEnrich || dispatchedCount >= budgetLeft) {
      requestPatches.set(request.id, {
        status: InvestigationEnrichmentRequestStatus.Skipped,
        error: canEnrich ? 'Enrichment budget exhausted' : 'The identity of the run cannot run enrichments',
        completed_at: now.toISOString(),
      });
    } else {
      // Checked, started and recorded under the lock of the run actions, as a
      // cancellation is: either the cancellation skips the job, or the job starts
      // and is recorded before the cancellation reads it (it may be a paid connector).
      const patch = await withRunActions(exec.liveContext, run.internal_id, async (current) => {
        const stillQueued = ACTIVE_RUN_STATUSES.includes(current.run_status)
          && current.enrichment_requests.some((item) => item.id === request.id && item.status === InvestigationEnrichmentRequestStatus.Queued);
        if (!stillQueued) return null;
        // A job an earlier pass started and could not record is recorded, never started twice.
        let unrecordedWorkId: string | null;
        try {
          unrecordedWorkId = await findUnrecordedEnrichmentWork(exec, current, request);
        } catch (lookupError) {
          logApp.warn('[CASE AUTOPILOT] Works of a queued enrichment not read, dispatch retried on the next pass', { runId: run.internal_id, requestId: request.id, cause: errorMessage(lookupError) });
          return null;
        }
        let requestPatch: Partial<InvestigationEnrichmentRequest>;
        if (unrecordedWorkId) {
          requestPatch = { status: InvestigationEnrichmentRequestStatus.Dispatched, work_id: unrecordedWorkId, dispatched_at: now.toISOString() };
        } else {
          const dispatchStartedAt = Date.now();
          try {
            const works = await askElementEnrichmentForConnectors(exec.draftContext, runUser, request.entity_id, [request.connector_id]);
            const startedWorkId = works?.[0]?.id ?? null;
            requestPatch = startedWorkId
              ? { status: InvestigationEnrichmentRequestStatus.Dispatched, work_id: startedWorkId, dispatched_at: now.toISOString() }
              : { status: InvestigationEnrichmentRequestStatus.Failed, error: 'The connector did not accept the job', completed_at: now.toISOString() };
          } catch (error) {
            // The dispatch may have failed once its work was created or its job pushed: that
            // work is recorded with its budget, as a started job (it completes or times out),
            // so that no job of the run changes its draft untracked.
            const startedWorkId = await findStartedEnrichmentWork(exec, current, request.connector_id, dispatchStartedAt)
              .catch((lookupError: unknown) => {
                logApp.warn('[CASE AUTOPILOT] Works of a failed enrichment dispatch not read', { runId: run.internal_id, cause: errorMessage(lookupError) });
                return null;
              });
            if (startedWorkId) {
              requestPatch = { status: InvestigationEnrichmentRequestStatus.Dispatched, work_id: startedWorkId, dispatched_at: now.toISOString() };
            } else if (isTransientFailure(error)) {
              // Nothing started: the request stays queued for the next pass.
              logApp.warn('[CASE AUTOPILOT] Enrichment dispatch interrupted, retried on the next pass', { runId: run.internal_id, requestId: request.id, cause: errorMessage(error) });
              return null;
            } else {
              requestPatch = { status: InvestigationEnrichmentRequestStatus.Failed, error: errorMessage(error), completed_at: now.toISOString() };
            }
          }
        }
        const workId = requestPatch.work_id;
        await updateInvestigationRun(exec.liveContext, run.internal_id, (fresh) => ({
          enrichment_requests: fresh.enrichment_requests.map((item) => (item.id === request.id ? { ...item, ...requestPatch } : item)),
          ...(workId ? {
            pending_work_ids: R.uniq([...(fresh.pending_work_ids ?? []), workId]),
            budget: { ...fresh.budget, used_enrichment_jobs: fresh.budget.used_enrichment_jobs + 1 },
          } : {}),
        }));
        return requestPatch;
      });
      if (patch) {
        started.set(request.id, patch);
        if (patch.work_id) dispatchedCount += 1;
      }
    }
  }
  addInvestigationEnrichmentJobCount(dispatchedCount);
  // Follow the jobs already running.
  const works = await Promise.all(dispatched.map((request) => (request.work_id ? loadWork(exec.liveContext, request.work_id) : Promise.resolve(null))));
  dispatched.forEach((request, index) => {
    const work = works[index];
    const dispatchedAt = new Date(request.dispatched_at ?? request.created_at).getTime();
    if (work?.status === 'complete') {
      requestPatches.set(request.id, { status: InvestigationEnrichmentRequestStatus.Completed, completed_at: now.toISOString() });
    } else if (now.getTime() - dispatchedAt > ENRICHMENT_WAVE_TIMEOUT_MS) {
      requestPatches.set(request.id, { status: InvestigationEnrichmentRequestStatus.Timeout, completed_at: now.toISOString() });
    }
  });
  const nextRequests = run.enrichment_requests.map((request) => ({ ...request, ...(started.get(request.id) ?? {}), ...(requestPatches.get(request.id) ?? {}) }));
  // Waves whose jobs all ended: what they brought into the Draft.
  const wavePatches = new Map<string, Partial<InvestigationEnrichmentWave>>();
  for (let index = 0; index < openWaves.length; index += 1) {
    const wave = openWaves[index];
    const waveRequests = nextRequests.filter((request) => wave.request_ids.includes(request.id));
    const status = computeWaveStatus(waveRequests);
    const ended = waveRequests.every((request) => isTerminalRequest(request) || request.status === InvestigationEnrichmentRequestStatus.AwaitingApproval);
    if (ended) {
      const delta = waveRequests.some((request) => request.status === InvestigationEnrichmentRequestStatus.Completed) ? await deltaOf(exec, wave, waveRequests) : [];
      const settled = waveRequests.every((request) => isTerminalRequest(request));
      wavePatches.set(wave.id, { status, delta, completed_at: now.toISOString(), delta_computed: settled });
    } else if (status !== wave.status) {
      wavePatches.set(wave.id, { status });
    }
  }
  if (requestPatches.size === 0 && wavePatches.size === 0) {
    return started.size > 0 ? (await loadInvestigationRun(exec.liveContext, run.internal_id)) ?? run : run;
  }
  return updateInvestigationRun(exec.liveContext, run.internal_id, (current) => {
    const pendingWorkIds = new Set(current.pending_work_ids ?? []);
    const enrichmentRequests = current.enrichment_requests.map((request) => {
      const requestPatch = requestPatches.get(request.id);
      // A job a concurrent decision already moved on is left as it is.
      if (!requestPatch || request.status !== run.enrichment_requests.find((r) => r.id === request.id)?.status) return request;
      if (requestPatch.work_id) pendingWorkIds.add(requestPatch.work_id);
      if (requestPatch.status && request.work_id && isTerminalRequest({ status: requestPatch.status })) pendingWorkIds.delete(request.work_id);
      return { ...request, ...requestPatch };
    });
    const enrichmentWaves = (current.enrichment_waves ?? []).map((wave) => (wavePatches.has(wave.id) ? { ...wave, ...wavePatches.get(wave.id) } : wave));
    return {
      enrichment_requests: enrichmentRequests,
      enrichment_waves: enrichmentWaves,
      pending_work_ids: Array.from(pendingWorkIds),
    };
  });
};

// endregion

// region investigating

// The OpenCTI objects an evidence list cites, read in the run Draft for their markings and sharing.
// Everything an engine revision names: its cited objects, the candidates of its
// hypotheses and the courses of action of its recommendations, as the run
// identity reads them. The engine only knows what that identity can read: an
// identifier it cannot read is invented or stale and restricts nothing.
const revisionCitedIds = (evidence: InvestigationEvidence[], conclusion: Record<string, unknown> | null | undefined) => R.uniq([
  ...evidence.filter(isObjectEvidence).map((item) => item.opencti_id as string),
  ...conclusionCandidateIds(conclusion),
  ...conclusionCourseOfActionIds(conclusion),
]).slice(0, INVESTIGATION_LIMITS.evidence + INVESTIGATION_LIMITS.candidates + INVESTIGATION_LIMITS.coursesOfAction);

// The copy a draft holds of a live object keeps the markings and organization
// sharing it had when it was copied: what a run carries also follows the live
// versions, read by the manager whoever they are now hidden from, so access
// tightened on a live object after its copy is carried too.
const withLiveVersions = async (elements: BasicStoreCommon[], extraIds: string[] = []): Promise<BasicStoreCommon[]> => {
  const ids = R.uniq([...extraIds, ...elements.map((element) => element.internal_id)]);
  if (ids.length === 0) return elements;
  const managerContext = await userContext(INVESTIGATION_MANAGER_USER);
  return [...elements, ...await findElements(managerContext, INVESTIGATION_MANAGER_USER, ids)];
};

// What a mirrored revision carries the access of: what it cites, its subject,
// its case and everything else the engine received.
const citedElements = async (exec: RunExecution, evidence: InvestigationEvidence[], conclusion: Record<string, unknown> | null | undefined): Promise<BasicStoreCommon[]> => {
  const ids = revisionCitedIds(evidence, conclusion);
  const cited = ids.length === 0 ? [] : withoutMemberRestricted(await findElements(exec.draftContext, exec.runUser, ids));
  return withLiveVersions(cited, [exec.run.subject_id, exec.run.case_id, ...runReceivedIds(exec.run)].filter((id): id is string => !!id));
};

// A run and its outputs carry markings and organization sharing, never a member
// restriction, and its markings were copied from what its identity read. The
// run stops before anything more is sent to the engine or mirrored once its
// subject or its case is no longer readable by that identity, or once one of
// them, an object the engine received (context or enrichment result) or an
// object it cites is restricted to authorized members.
// Restrictions are read on the live objects by the manager, whoever they hide
// the object from: the copy a draft holds of a live object keeps the
// restrictions it had when it was copied, and a restriction that excludes the
// run identity would hide the object from it.
const findCarryBoundary = async (exec: RunExecution, citedIds: string[]): Promise<{ reason: string; code: string } | null> => {
  const { run } = exec;
  const ids = R.uniq([run.subject_id, run.case_id, ...runReceivedIds(run), ...citedIds].filter((id): id is string => !!id));
  const managerContext = await userContext(INVESTIGATION_MANAGER_USER);
  const [allLive, readableLive, inDraft] = await Promise.all([
    // The PIRs of the context are internal objects.
    findElements(managerContext, INVESTIGATION_MANAGER_USER, ids, { withInternal: true }),
    findElements(exec.liveContext, exec.runUser, [run.subject_id, run.case_id].filter((id): id is string => !!id)),
    findElements(exec.draftContext, exec.runUser, ids),
  ]);
  const idsOf = (elements: BasicStoreCommon[]) => new Set(elements.flatMap((element) => [element.internal_id, element.standard_id]));
  const readableIds = idsOf(readableLive);
  // Only a case the run created exists in its draft alone.
  const caseReadable = !run.case_id || readableIds.has(run.case_id) || (run.create_case && idsOf(inDraft).has(run.case_id));
  if (!readableIds.has(run.subject_id) || !caseReadable) {
    return SUBJECT_INACCESSIBLE;
  }
  const liveIds = idsOf(allLive);
  // Objects the run created exist in its draft alone: their draft version is their only one.
  const draftOnly = inDraft.filter((element) => !liveIds.has(element.internal_id) && !liveIds.has(element.standard_id));
  const restricted = [...allLive, ...draftOnly].filter((element) => isMemberRestricted(element));
  if (restricted.length > 0) {
    logApp.warn('[CASE AUTOPILOT] Investigation stopped at a member restriction', { runId: run.internal_id, ids: restricted.map((element) => element.internal_id) });
    return { reason: MEMBER_RESTRICTED_REASON, code: MEMBER_RESTRICTED_CODE };
  }
  return null;
};

// The draft and the investigation graph of a run stopped at an access boundary
// hold what the run read and derived: from the stop on, only the manager may
// open them; the run keeps each reference until its deletion succeeds, and the
// manager retries a deletion that failed.
// Everything the run derived from what it read is withheld, as it may describe
// what the run can no longer carry: the engine's text, the conclusion OpenCTI
// scored from it, the references to its outputs, its draft, deleted with what
// it wrote there, and its investigation graph, which holds what it read. Gates
// still waiting are rejected, jobs not started skipped. The stop and its cleanup
// run under the run actions lock, as approvals and their effects do: an approval
// either completes before the stop, or finds the run stopped.
const stopRunAtCarryBoundary = async (
  context: AuthContext,
  runId: string,
  boundary: { reason: string; code: string },
  opts: { holdsActions?: boolean } = {},
) => {
  if (!opts.holdsActions) {
    await withRunActions(context, runId, () => stopRunAtCarryBoundary(context, runId, boundary, { holdsActions: true }));
    return;
  }
  const now = new Date();
  const stop: { done: boolean; engineRunning: boolean; draftId: string | null; workspaceId: string | null } = {
    done: false,
    engineRunning: false,
    draftId: null,
    workspaceId: null,
  };
  await updateInvestigationRun(context, runId, (current) => {
    if (TERMINAL_RUN_STATUSES.includes(current.run_status)) return null;
    stop.done = true;
    stop.engineRunning = current.run_phase === InvestigationRunPhase.Investigating && !!current.xtm_investigation_id && !current.budget_cancelled;
    stop.draftId = current.draft_id ?? null;
    stop.workspaceId = current.workspace_id ?? null;
    const withheld = withheldRunContent(current);
    return {
      ...statusTransition(current, InvestigationRunStatus.Failed, InvestigationRunPhase.Done, now, boundary.reason),
      end_reason_code: boundary.code,
      pending_work_ids: [],
      ...withheld,
      ...closeOpenGates({ ...current, ...withheld }, now, 'Investigation stopped'),
      ...(stop.engineRunning ? { xtm_status: ENGINE_CANCEL_PENDING, engine_failures: 0 } : {}),
    };
  });
  if (!stop.done) return;
  addInvestigationRunOutcomeCount(InvestigationRunStatus.Failed);
  if (stop.draftId || stop.workspaceId) {
    await deleteStoppedRunArtifacts(context, runId, { draftId: stop.draftId, workspaceId: stop.workspaceId });
  }
  if (stop.engineRunning) {
    await stopCancelledEngineRun(context, runId);
  }
};

const stopAtCarryBoundary = (exec: RunExecution, boundary: { reason: string; code: string }) => {
  return stopRunAtCarryBoundary(exec.liveContext, exec.run.internal_id, boundary, { holdsActions: exec.holdsActions });
};

// The OpenCTI objects of a revision the run may cite: those its identity sees,
// without a member restriction (the run cannot carry one).
const citableObjectIds = async (exec: RunExecution, evidence: InvestigationEvidence[]): Promise<Set<string>> => {
  const ids = R.uniq(evidence.filter(isObjectEvidence).map((item) => item.opencti_id as string)).slice(0, INVESTIGATION_LIMITS.evidence);
  if (ids.length === 0) return new Set();
  const visible = withoutMemberRestricted(await findElements(exec.draftContext, exec.runUser, ids));
  return new Set(visible.flatMap((element) => [element.internal_id, element.standard_id]));
};

// A revision citing a restricted object restricts the run as soon as it is
// mirrored, before anyone can read its evidence, summary or report: markings
// add up, organization sharing narrows to what every cited object allows.
// Objects the run may not cite are not mirrored as evidence.
const mirrorPatch = (
  current: BasicStoreEntityInvestigationRun,
  engine: EngineInvestigation,
  cited: BasicStoreCommon[],
  citable: Set<string> | null = null,
): Record<string, unknown> => ({
  objectMarking: R.uniq([...markingIdsOf(current), ...cited.flatMap((element) => markingIdsOf(element))]),
  objectOrganization: intersectOrganizationIds(organizationIdsOf(current), cited),
  goal_plan: engine.goal_plan ?? current.goal_plan ?? null,
  steps: mirrorSteps(current.steps ?? [], engine.id, engine.steps),
  evidence: mirrorEvidence(current.evidence ?? [], engine)
    .filter((item) => !citable || !isObjectEvidence(item) || citable.has(item.opencti_id as string)),
  report: engine.report ?? current.report ?? null,
  report_sources: engine.report ? mirrorReportSources(engine) : current.report_sources ?? [],
  summary: (engine.conclusion?.summary as string | undefined)?.slice(0, INVESTIGATION_LIMITS.summaryLength) ?? current.summary ?? null,
  budget: { ...current.budget, used_iterations: Math.max(current.budget.used_iterations ?? 0, (current.budget.iterations_base ?? 0) + engine.iterations_used) },
  xtm_revision: engine.revision,
  xtm_status: engine.status,
  engine_failures: 0,
});

const investigate = async (exec: RunExecution) => {
  // Read on every tick, before any enrichment job is dispatched or the engine
  // polled, whether a revision changed or not.
  const crossed = await findCarryBoundary(exec, runCitedIds(exec.run));
  if (crossed) {
    await stopAtCarryBoundary(exec, crossed);
    return;
  }
  const run = await processEnrichments(exec);
  const { runUser, now } = exec;
  const investigationId = run.xtm_investigation_id;
  if (!investigationId) {
    await updateRunningRun(exec.liveContext, run.internal_id, () => ({ run_phase: InvestigationRunPhase.Starting }));
    return;
  }
  // The time budget is OpenCTI's: once spent, the engine run is cancelled and
  // the investigation concludes with what the engine found.
  let budgetCancelled = run.budget_cancelled;
  if (!budgetCancelled && isBudgetExhausted(run, now)) {
    const cancelled = await cancelInvestigation(jwtUserOf(runUser), investigationId);
    if (!cancelled.ok) {
      // The engine run is not stopped yet: retried on the next tick, bounded like any engine failure.
      await handleEngineFailure({ ...exec, run }, cancelled);
      return;
    }
    budgetCancelled = true;
    await updateRunningRun(exec.liveContext, run.internal_id, () => ({
      budget_cancelled: true,
      wave_started_at: now.toISOString(),
      status_reason: 'The time budget is spent: the investigation concludes with what it found',
    }));
  }
  const result = await getInvestigation(jwtUserOf(runUser), investigationId, run.draft_id);
  if (!result.ok) {
    const graceOver = budgetCancelled && now.getTime() - new Date(run.wave_started_at ?? now.toISOString()).getTime() > BUDGET_CANCEL_GRACE_MS;
    if (graceOver) {
      await updateRunningRun(exec.liveContext, run.internal_id, () => ({ run_phase: InvestigationRunPhase.Ingesting }));
      return;
    }
    await handleEngineFailure({ ...exec, run }, result);
    return;
  }
  const engine = result.value;
  const outcome = engineOutcome(engine.status);
  const changed = engine.revision !== run.xtm_revision || engine.status !== run.xtm_status;
  const revisionEvidence = mirrorEvidence(run.evidence ?? [], engine);
  const mirroring = changed || outcome !== 'running';
  if (mirroring) {
    const boundary = await findCarryBoundary(exec, revisionCitedIds(revisionEvidence, engine.conclusion));
    if (boundary) {
      await stopAtCarryBoundary(exec, boundary);
      return;
    }
  }
  const cited = mirroring ? await citedElements(exec, revisionEvidence, engine.conclusion) : [];
  const citable = mirroring ? await citableObjectIds(exec, revisionEvidence) : null;
  if (outcome === 'failed') {
    await updateRunningRun(exec.liveContext, run.internal_id, (current) => mirrorPatch(current, engine, cited, citable));
    await failRun(exec.liveContext, run.internal_id, `The investigation engine stopped the investigation (${engine.end_reason_code ?? 'aborted'})`, engine.end_reason_code ?? 'engine_aborted');
    return;
  }
  if (outcome === 'cancelled' && !budgetCancelled) {
    await updateInvestigationRun(exec.liveContext, run.internal_id, (current) => {
      if (TERMINAL_RUN_STATUSES.includes(current.run_status)) return null;
      return {
        ...mirrorPatch(current, engine, cited, citable),
        ...statusTransition(current, InvestigationRunStatus.Cancelled, InvestigationRunPhase.Done, now, 'The investigation was cancelled in XTM One'),
        end_reason_code: engine.end_reason_code ?? 'engine_cancelled',
      };
    });
    addInvestigationRunOutcomeCount(InvestigationRunStatus.Cancelled);
    return;
  }
  const graceOver = budgetCancelled && now.getTime() - new Date(run.wave_started_at ?? now.toISOString()).getTime() > BUDGET_CANCEL_GRACE_MS;
  const concluded = outcome === 'cancelled' || graceOver
    || (outcome === 'completed' && !isReportPending(engine, run.xtm_completed_at, now));
  if (!changed && !concluded && !(outcome === 'completed' && !run.xtm_completed_at)) {
    return;
  }
  await updateRunningRun(exec.liveContext, run.internal_id, (current) => ({
    ...mirrorPatch(current, engine, cited, citable),
    xtm_completed_at: outcome === 'completed' ? current.xtm_completed_at ?? now.toISOString() : current.xtm_completed_at ?? null,
    ...(concluded ? { run_phase: InvestigationRunPhase.Ingesting } : {}),
  }));
};

// endregion

// region ingesting

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

interface OutputsResult {
  outputs: InvestigationOutputs;
  caseId: string | null;
  caseIds: string[];
  failures: string[];
}

interface OutputRestrictions {
  markings: string[];
  organizations: string[];
}

// Draft writes of the conclusion, each one allowed by the policy. A
// continuation updates what the first conclusion wrote instead of duplicating it.
const writeOutputs = async (
  exec: RunExecution,
  subject: BasicStoreEntity,
  engine: EngineInvestigation | null,
  restrictions: OutputRestrictions,
): Promise<OutputsResult> => {
  const { run, runUser, draftContext, policy, now } = exec;
  const failures: string[] = [];
  const outputs: InvestigationOutputs = { ...EMPTY_OUTPUTS, ...(run.outputs ?? {}) };
  const { markings, organizations } = restrictions;
  const settings = await getEntityFromCache<BasicStoreSettings>(draftContext, INVESTIGATION_MANAGER_USER, ENTITY_TYPE_SETTINGS);
  if (isCreationSharingWidened(runUser, settings, draftContext.user_inside_platform_organization ?? false, organizations)) {
    // The platform would share what this identity writes with its own organizations, beyond the ones of the evidence.
    failures.push('every output (the identity of the investigation cannot restrict its writes to the organizations of the evidence)');
    return { outputs, caseId: run.case_id ?? null, caseIds: run.case_ids ?? [], failures };
  }
  const allowedAction = (action: InvestigationAutonomousAction) => policy.allowed_actions.includes(action);
  const leading = run.hypotheses.find((hypothesis) => hypothesis.rank === 1) ?? null;
  const subjectName = representativeNameOf(subject) ?? subject.internal_id;
  let caseId = run.case_id ?? null;
  let caseIds = run.case_ids ?? [];
  // A transient failure is left to the retry of the manager, once what was
  // written so far is recorded: the retried pass reuses it. Any other failure
  // leaves that output out and is reported on the run.
  const attempt = async (label: string, fn: () => Promise<void>) => {
    try {
      await fn();
    } catch (error) {
      if (isTransientFailure(error)) {
        await updateRunningRun(exec.liveContext, run.internal_id, () => ({ outputs, case_id: caseId, case_ids: caseIds }))
          .catch((checkpointError: unknown) => logApp.warn('[CASE AUTOPILOT] Investigation outputs not recorded before a retry', { runId: run.internal_id, cause: errorMessage(checkpointError) }));
        throw error;
      }
      failures.push(`${label} (${errorMessage(error)})`);
      logApp.warn('[CASE AUTOPILOT] Investigation output not written', { runId: run.internal_id, output: label, cause: errorMessage(error) });
    }
  };
  // What a failure of one write may leave out, unless the failure is transient.
  const skipUnlessTransient = (message: string, data: Record<string, unknown>) => (error: unknown) => {
    if (isTransientFailure(error)) throw error;
    logApp.debug(message, { ...data, cause: errorMessage(error) });
  };
  // The engine's deterministic knowledge list: observables, their relationships and notes.
  const knowledge = parseEngineKnowledge(engine?.knowledge ?? null);
  if (knowledge.observables.length > 0 && allowedAction(InvestigationAutonomousAction.AddToCase)) {
    await attempt('knowledge', async () => {
      for (let index = 0; index < knowledge.observables.length; index += 1) {
        const observable = knowledge.observables[index];
        if (!outputs.observable_ids[observable.value]) {
          const created = await addStixCyberObservable(draftContext, runUser, {
            type: observable.type,
            [OBSERVABLE_INPUT_KEYS[observable.type]]: { value: observable.value },
            objectMarking: markings,
            objectOrganization: organizations,
          });
          outputs.observable_ids[observable.value] = created.internal_id ?? created.id;
        }
      }
      if (allowedAction(InvestigationAutonomousAction.CreateRelationship)) {
        await BluePromise.map(knowledge.relationships, async (relationship) => {
          const fromId = outputs.observable_ids[relationship.from];
          const toId = outputs.observable_ids[relationship.to];
          if (!fromId || !toId) return;
          await addStixCoreRelationship(draftContext, runUser, {
            relationship_type: relationship.type,
            fromId,
            toId,
            description: relationship.description ?? undefined,
            objectMarking: markings,
            objectOrganization: organizations,
          }).catch(skipUnlessTransient('[CASE AUTOPILOT] Knowledge relationship not written', {}));
        }, { concurrency: 5 });
      }
      if (allowedAction(InvestigationAutonomousAction.CreateNote)) {
        await BluePromise.map(knowledge.notes, async (finding) => {
          const observableId = outputs.observable_ids[finding.value];
          if (!observableId) return;
          // Recorded by value and content, so that a retried pass does not write a finding twice.
          const key = createHash('sha256').update(`${finding.value}\n${finding.content}`).digest('hex').slice(0, 32);
          if (outputs.finding_note_ids?.[key]) return;
          const note = await addNote(draftContext, runUser, {
            attribute_abstract: FINDING_NOTE_ABSTRACT,
            content: finding.content,
            objects: [observableId],
            objectMarking: markings,
            objectOrganization: organizations,
            note_types: ['analysis'],
          });
          outputs.finding_note_ids = { ...(outputs.finding_note_ids ?? {}), [key]: note.internal_id };
        }, { concurrency: 5 });
      }
    });
  }
  const objectIds = R.uniq([
    subject.internal_id,
    ...run.evidence.filter((evidence) => isObjectEvidence(evidence) && !isRelationshipType(evidence.entity_type)).map((evidence) => evidence.opencti_id as string),
    ...Object.values(outputs.observable_ids),
    ...(leading ? [leading.candidate_id] : []),
  ]).slice(0, MAX_CASE_OBJECTS);
  // The case: evidence added to it, or a case created for an incident.
  if (caseId && allowedAction(InvestigationAutonomousAction.AddToCase)) {
    const targetCaseId = caseId;
    await attempt('case', async () => {
      const addObject = (toId: string) => stixDomainObjectAddRelation(draftContext, runUser, targetCaseId, { toId, relationship_type: RELATION_OBJECT })
        .catch(skipUnlessTransient('[CASE AUTOPILOT] Object not added to the case', { toId }));
      await BluePromise.map(objectIds.filter((id) => id !== targetCaseId), addObject, { concurrency: 5 });
    });
  } else if (!caseId && subject.entity_type === ENTITY_TYPE_INCIDENT && allowedAction(InvestigationAutonomousAction.CreateCase)) {
    await attempt('case', async () => {
      const created = await addCaseIncident(draftContext, runUser, {
        name: `Investigation - ${subjectName}`.slice(0, 250),
        description: run.summary?.slice(0, INVESTIGATION_LIMITS.textLength) ?? 'Case opened by a Case Autopilot investigation.',
        // The evidence goes into the new case only when the policy also allows adding to a case.
        objects: allowedAction(InvestigationAutonomousAction.AddToCase) ? objectIds : [subject.internal_id],
        objectMarking: markings,
        objectOrganization: organizations,
      });
      caseId = created.internal_id;
      caseIds = R.uniq([...caseIds, created.internal_id, created.standard_id]);
    });
  }
  const containers = R.uniq([subject.internal_id, ...(caseId ? [caseId] : [])]);
  // A continuation may cite more restricted objects than the first conclusion:
  // an output is edited in place only while it carries the restrictions of
  // what it now quotes, else it is written again in the draft with them.
  const keepsRestrictions = async (id: string, type: string) => {
    const current = await storeLoadByIdWithRefs<StoreEntity>(draftContext, runUser, id, { type });
    if (!current) return false;
    const currentMarkings = markingIdsOf(current);
    const currentOrganizations = organizationIdsOf(current);
    if (markings.every((marking) => currentMarkings.includes(marking))
      && currentOrganizations.length === organizations.length
      && currentOrganizations.every((organization) => organizations.includes(organization))) {
      return true;
    }
    await deleteElementById(draftContext, runUser, id, type);
    return false;
  };
  if (allowedAction(InvestigationAutonomousAction.CreateNote)) {
    // The investigation summary note: hypotheses, recommendations, timeline, indicators.
    await attempt('note', async () => {
      const content = buildInvestigationNoteContent(run);
      if (outputs.note_id && await keepsRestrictions(outputs.note_id, ENTITY_TYPE_CONTAINER_NOTE)) {
        await stixDomainObjectEditField(draftContext, runUser, outputs.note_id, [{ key: 'content', value: [content] }]);
        return;
      }
      const note = await addNote(draftContext, runUser, {
        attribute_abstract: NOTE_ABSTRACT,
        content,
        objects: containers,
        objectMarking: markings,
        objectOrganization: organizations,
        note_types: ['analysis'],
        confidence: leading?.confidence ?? undefined,
      });
      outputs.note_id = note.internal_id;
      outputs.note_standard_id = note.standard_id;
    });
    // The engine's cited report, as a Report. Its numbered sources stay in the
    // report text: an external reference carries no marking or sharing of its
    // own and would let anyone read what a restricted investigation cites.
    if (run.report) {
      await attempt('report', async () => {
        const description = buildInvestigationReportSections(run).report.slice(0, INVESTIGATION_LIMITS.reportLength);
        if (outputs.report_id && await keepsRestrictions(outputs.report_id, ENTITY_TYPE_CONTAINER_REPORT)) {
          await stixDomainObjectEditField(draftContext, runUser, outputs.report_id, [{ key: 'description', value: [description] }]);
          return;
        }
        const report = await addReport(draftContext, runUser, {
          name: `Investigation report - ${subjectName}`.slice(0, 250),
          description,
          published: now.toISOString(),
          objects: R.uniq([...containers, ...objectIds]).slice(0, MAX_CASE_OBJECTS),
          objectMarking: markings,
          objectOrganization: organizations,
          confidence: leading?.confidence ?? undefined,
        });
        outputs.report_id = report.internal_id;
        outputs.report_standard_id = report.standard_id;
      });
    }
  }
  // The attribution, written only above the policy threshold.
  if (leading && leading.confidence !== null && allowedAction(InvestigationAutonomousAction.CreateRelationship)
    && leading.confidence >= policy.attribution_min_confidence
    && !outputs.attributed_candidate_ids.includes(leading.candidate_id)) {
    const incidents = subject.entity_type === ENTITY_TYPE_INCIDENT
      ? [subject.internal_id]
      : run.evidence
          .filter((evidence) => evidence.entity_type === ENTITY_TYPE_INCIDENT && evidence.opencti_id)
          .map((evidence) => evidence.opencti_id as string)
          .slice(0, MAX_ATTRIBUTED_INCIDENTS);
    const candidateType = leading.candidate_type ?? '';
    const relationshipType = checkStixCoreRelationshipMapping(ENTITY_TYPE_INCIDENT, candidateType, RELATION_ATTRIBUTED_TO) ? RELATION_ATTRIBUTED_TO : RELATION_RELATED_TO;
    await attempt('attribution', async () => {
      await BluePromise.map(incidents, (fromId) => addStixCoreRelationship(draftContext, runUser, {
        relationship_type: relationshipType,
        fromId,
        toId: leading.candidate_id,
        confidence: leading.confidence,
        description: leading.explanation,
        objectMarking: markings,
        objectOrganization: organizations,
      }), { concurrency: 2 });
      if (incidents.length > 0) outputs.attributed_candidate_ids = R.uniq([...outputs.attributed_candidate_ids, leading.candidate_id]);
    });
  }
  return { outputs, caseId, caseIds, failures };
};

const DRAFT_TYPES_PAGE = 500;

const listDraftChanges = async (exec: RunExecution): Promise<DraftChanges> => {
  const draftContext = await userContext(INVESTIGATION_MANAGER_USER, exec.run.draft_id);
  const page = draftQuery(undefined, DRAFT_TYPES_PAGE);
  const [entities, relationships] = await Promise.all([
    topEntitiesList<BasicStoreEntity>(draftContext, INVESTIGATION_MANAGER_USER, [ABSTRACT_STIX_CORE_OBJECT], page),
    topRelationsList<BasicStoreRelation>(draftContext, INVESTIGATION_MANAGER_USER, STIX_RELATIONSHIP_TYPES, page) as unknown as Promise<BasicStoreRelation[]>,
  ]);
  // The investigated entity is loaded in the draft at creation without being changed.
  const changed = [...entities, ...relationships].filter((element) => element.internal_id !== exec.run.subject_id
    || (element as unknown as { draft_change?: { draft_operation?: string } }).draft_change?.draft_operation);
  return {
    types: R.uniq(changed.map((element) => element.entity_type)),
    complete: entities.length < DRAFT_TYPES_PAGE && relationships.length < DRAFT_TYPES_PAGE,
  };
};

// Markings and organization sharing of everything the run read or wrote about,
// so its text never outlives their restrictions: the cited objects, the case
// and every candidate threat its hypotheses or its conclusion name, as the run
// identity reads them (an identifier it cannot read restricts nothing), with
// the access their live versions and the live subject have now, on top of the
// access the run already carries (its whole engine context among others).
const collectRunRestrictions = async (exec: RunExecution, subject: BasicStoreEntity, caseId: string | null, candidateIds: string[]): Promise<OutputRestrictions> => {
  const ids = R.uniq([
    ...exec.run.evidence.filter(isObjectEvidence).map((evidence) => evidence.opencti_id as string),
    ...exec.run.hypotheses.map((hypothesis) => hypothesis.candidate_id),
    ...exec.run.recommendations.flatMap((recommendation) => (recommendation.course_of_action_id ? [recommendation.course_of_action_id] : [])),
    ...candidateIds,
    ...(caseId ? [caseId] : []),
  ]).slice(0, INVESTIGATION_LIMITS.evidence + INVESTIGATION_LIMITS.candidates + INVESTIGATION_LIMITS.coursesOfAction + 1);
  const elements = await withLiveVersions(await findElements(exec.draftContext, exec.runUser, ids), [subject.internal_id]);
  return {
    markings: R.uniq([...markingIdsOf(exec.run), ...markingIdsOf(subject), ...elements.flatMap((element) => markingIdsOf(element))]),
    organizations: intersectOrganizationIds(organizationIdsOf(exec.run), [subject, ...elements]),
  };
};

const ingestRun = async (exec: RunExecution) => {
  const { run, runUser, now, policy } = exec;
  const subject = await loadSubject(exec);
  if (!subject) {
    await stopAtCarryBoundary(exec, SUBJECT_INACCESSIBLE);
    return;
  }
  // The final state of the engine run; what was mirrored when it cannot be read.
  let engine: EngineInvestigation | null = null;
  if (run.xtm_investigation_id) {
    const result = await getInvestigation(jwtUserOf(runUser), run.xtm_investigation_id, run.draft_id);
    if (result.ok) {
      engine = result.value;
    } else if (result.failure === ENGINE_UNREACHABLE && (run.engine_failures ?? 0) + 1 < INVESTIGATION_LIMITS.engineFailures) {
      await updateRunningRun(exec.liveContext, run.internal_id, (current) => ({ engine_failures: (current.engine_failures ?? 0) + 1 }));
      return;
    }
  }
  // The markings and sharing of the run are recomputed below from everything it cites.
  const mirrored = engine ? { ...run, ...mirrorPatch(run, engine, []) } as BasicStoreEntityInvestigationRun : run;
  const boundary = await findCarryBoundary(exec, revisionCitedIds(mirrored.evidence, engine?.conclusion));
  if (boundary) {
    await stopAtCarryBoundary(exec, boundary);
    return;
  }
  // OpenCTI objects the engine cites, as the run identity sees them, with the attributes ACH weights them by.
  const objectIds = mirrored.evidence.filter(isObjectEvidence).map((evidence) => evidence.opencti_id as string);
  // An object restricted to authorized members is not cited either: the run and its outputs cannot carry the restriction.
  const elements = withoutMemberRestricted(await findElements(exec.draftContext, runUser, objectIds));
  const reliabilities = await loadAuthorReliabilities(exec.draftContext, runUser, elements);
  const fresh = new Map(elementEvidence(elements, reliabilities, run.draft_id).map((evidence) => [evidence.id, evidence]));
  const evidence = mirrored.evidence
    // An object the run identity cannot see is never cited back.
    .filter((item) => !isObjectEvidence(item) || fresh.has(item.opencti_id as string))
    .map((item) => {
      const meta = isObjectEvidence(item) ? fresh.get(item.opencti_id as string) : null;
      return meta ? { ...meta, investigation_id: item.investigation_id, n: item.n, quote: item.quote, label: item.label || meta.label } : item;
    });
  // Ground the conclusion against what the run may cite.
  const collected = await collectInvestigationContext({ ...exec, run: { ...mirrored, evidence } }, subject);
  const candidateInfo = new Map(collected.candidateInfo);
  elements.filter((element) => ATTRIBUTION_CANDIDATE_TYPES.includes(element.entity_type)).forEach((element) => {
    candidateInfo.set(element.internal_id, { name: representativeNameOf(element), entity_type: element.entity_type, standard_id: element.standard_id });
  });
  const allowed = buildAllowedIds(collected.engineContext, evidence.filter(isObjectEvidence).map((item) => ({ id: item.id, standard_id: item.standard_id })));
  evidence.forEach((item) => allowed.evidence.add(item.id));
  candidateInfo.forEach((info, id) => {
    allowed.candidates.add(id);
    allowed.aliases.set(id, id);
    if (info.standard_id) allowed.aliases.set(info.standard_id, id);
  });
  const grounded = groundConclusion(engine?.conclusion ?? null, allowed, candidateInfo, evidence, mirrored.xtm_investigation_id ?? '');
  const evidenceMeta = new Map<string, AchEvidenceMeta>(evidence.map((item) => [item.id, toAchMeta(item)]));
  const hypotheses = grounded.hypotheses.length > 0 ? scoreAchMatrix(grounded.hypotheses, evidenceMeta) : mirrored.hypotheses;
  const timeline = buildTimeline(evidence.filter(isObjectEvidence).map(toTimelineSource));
  const recommendations = mergeRecommendations(mirrored.recommendations, grounded.recommendations);
  const finalRun: BasicStoreEntityInvestigationRun = {
    ...mirrored,
    evidence,
    hypotheses,
    recommendations,
    timeline,
    summary: grounded.summary ?? mirrored.summary ?? null,
  };
  // Every output may quote what the run cites: it carries the markings and the sharing of all of it.
  // Candidates and courses of action the conclusion names: its text may quote them.
  const namedCandidates = [...conclusionCandidateIds(engine?.conclusion), ...conclusionCourseOfActionIds(engine?.conclusion)];
  const outputRestrictions = await collectRunRestrictions({ ...exec, run: finalRun }, subject, finalRun.case_id ?? null, namedCandidates);
  // Written once per engine run and recorded at once: a pass interrupted after
  // the writes is retried with what they wrote instead of writing it again.
  const engineRunId = run.xtm_investigation_id ?? null;
  const recorded = engineRunId && run.outputs?.written_for === engineRunId ? run.outputs : null;
  const written = recorded
    ? { outputs: recorded, caseId: run.case_id ?? null, caseIds: run.case_ids ?? [], failures: recorded.write_failures ?? [] }
    : await writeOutputs({ ...exec, run: finalRun }, subject, engine, outputRestrictions);
  if (!recorded) {
    await updateRunningRun(exec.liveContext, run.internal_id, () => ({
      outputs: { ...written.outputs, written_for: engineRunId, write_failures: written.failures },
      case_id: written.caseId,
      case_ids: written.caseIds,
    }));
  }
  const { outputs, caseId, caseIds, failures } = written;
  const restrictions = await collectRunRestrictions({ ...exec, run: finalRun }, subject, caseId, namedCandidates);
  const recommendationApprovals: InvestigationApproval[] = recommendations
    .filter((recommendation) => recommendation.status === InvestigationRecommendationStatus.AwaitingApproval
      && !run.approvals.some((approval) => approval.recommendation_id === recommendation.id && approval.status === InvestigationApprovalStatus.Pending))
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
  const draftChanges: DraftChanges = run.draft_id ? await listDraftChanges(exec) : { types: [], complete: true };
  const draftTypes = draftChanges.types;
  const leadingConfidence = hypotheses[0]?.confidence ?? null;
  let validationWorkId: string | null = null;
  let nextStatus = InvestigationRunStatus.AwaitingApproval;
  let nextPhase = InvestigationRunPhase.AwaitingValidation;
  const reasons = [
    run.budget_cancelled ? 'The time budget was spent: the investigation concluded with what it found' : null,
    grounded.dropped > 0 ? `${grounded.dropped} item(s) of the conclusion cited what the investigation cannot use and were dropped` : null,
    failures.length > 0 ? `Not written to the draft: ${failures.join(', ')}` : null,
  ].filter((reason): reason is string => !!reason);
  const draftApproval: InvestigationApproval[] = [];
  if (!run.draft_id || draftTypes.length === 0) {
    nextStatus = InvestigationRunStatus.Completed;
    nextPhase = InvestigationRunPhase.Done;
  } else if (canAutoApproveDraft(policy, draftChanges, leadingConfidence)) {
    // Only low-risk objects (notes, observed data) above the confidence threshold.
    const work = await validateDraftWorkspace(exec.liveContext, runUser, run.draft_id);
    validationWorkId = work?.id ?? null;
    nextStatus = InvestigationRunStatus.Running;
    nextPhase = InvestigationRunPhase.Validating;
    reasons.push('Low-risk draft approved automatically by the policy');
  } else {
    reasons.push('The investigation draft is waiting for an approval');
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
  const finalized = await updateInvestigationRun(exec.liveContext, run.internal_id, (current) => (TERMINAL_RUN_STATUSES.includes(current.run_status) ? null : {
    ...(engine ? mirrorPatch(current, engine, []) : {}),
    ...statusTransition(current, nextStatus, nextPhase, now, reasons.join('. ') || null),
    evidence,
    hypotheses,
    recommendations,
    timeline,
    summary: finalRun.summary,
    outputs,
    case_id: caseId,
    case_ids: caseIds,
    objectMarking: restrictions.markings,
    objectOrganization: organizationIdsOf(current).filter((id) => restrictions.organizations.includes(id)),
    validation_work_id: validationWorkId,
    wave_started_at: now.toISOString(),
    approvals: boundApprovals([...current.approvals, ...recommendationApprovals, ...draftApproval]),
  }));
  if (nextStatus === InvestigationRunStatus.Completed && finalized.run_status === InvestigationRunStatus.Completed) {
    addInvestigationRunOutcomeCount(InvestigationRunStatus.Completed);
  }
};

// Ingestion writes the draft and may approve it: it runs under the lock of the
// run actions, as a cancellation or a decision does, against a fresh run.
const ingest = async (exec: RunExecution) => withRunActions(exec.liveContext, exec.run.internal_id, async (run) => {
  if (run.run_status !== InvestigationRunStatus.Running || run.run_phase !== InvestigationRunPhase.Ingesting) return;
  await ingestRun({ ...exec, run, holdsActions: true });
});

// endregion

// region validation

// What the run wrote in its draft gets a live version, under a new internal id,
// once the validation work ingested it: it is read by its standard id as well.
const validationCitedIds = (run: BasicStoreEntityInvestigationRun) => R.uniq([
  ...runCitedIds(run),
  ...run.evidence.filter((evidence) => evidence.in_draft && evidence.standard_id).map((evidence) => evidence.standard_id as string),
]);

const completeValidation = async (exec: RunExecution) => {
  const { run, runUser, now } = exec;
  // Read on every tick while the validation is processed, as in the other
  // phases of a running run: a run is never completed beyond its boundary.
  const crossed = await findCarryBoundary(exec, validationCitedIds(run));
  if (crossed) {
    await stopAtCarryBoundary(exec, crossed);
    return;
  }
  const work = run.validation_work_id ? await loadWork(exec.liveContext, run.validation_work_id) : null;
  const startedAt = run.wave_started_at ? new Date(run.wave_started_at).getTime() : now.getTime();
  const timedOut = now.getTime() - startedAt > VALIDATION_TIMEOUT_MS;
  const confirmed = work?.status === 'complete';
  // Until the platform confirms the approved changes (or the bound passes), the
  // run keeps validating, so its boundary is watched while they are written.
  if (!confirmed && !timedOut) {
    return;
  }
  const writeErrors = (confirmed && work?.errors) || [];
  let failure: { code: string; reason: string } | null = null;
  if (!confirmed) {
    failure = {
      code: DRAFT_VALIDATION_UNCONFIRMED_CODE,
      reason: `The platform did not confirm within ${VALIDATION_TIMEOUT_MS / 60000} minutes that the approved changes were written to the case`,
    };
  } else if (writeErrors.length > 0) {
    const first = writeErrors.find((error) => error.message)?.message;
    failure = {
      code: DRAFT_VALIDATION_FAILED_CODE,
      reason: `The platform reported ${writeErrors.length} error(s) writing the approved changes to the case${first ? ` (${first})` : ''}`.slice(0, INVESTIGATION_LIMITS.textLength),
    };
  }
  // Draft objects got new internal ids in the live graph: resolve them by standard id.
  const outputs: InvestigationOutputs = { ...EMPTY_OUTPUTS, ...(run.outputs ?? {}) };
  const draftEvidence = run.evidence.filter((evidence) => evidence.in_draft && evidence.standard_id);
  const standardIds = R.uniq([
    ...draftEvidence.map((evidence) => evidence.standard_id as string),
    ...(run.case_ids ?? []),
    ...(outputs.report_standard_id ? [outputs.report_standard_id] : []),
    ...(outputs.note_standard_id ? [outputs.note_standard_id] : []),
  ]);
  const liveElements = await findElements(exec.liveContext, runUser, standardIds);
  const liveByStandard = new Map<string, string>(liveElements.map((element) => [element.standard_id as string, element.internal_id]));
  const evidence = run.evidence.map((item) => (item.in_draft && item.standard_id && liveByStandard.has(item.standard_id)
    ? { ...item, id: liveByStandard.get(item.standard_id) as string, opencti_id: liveByStandard.get(item.standard_id) as string, in_draft: false }
    : item));
  const idMap = new Map(run.evidence.map((item, index) => [item.id, evidence[index].id]));
  const hypotheses = run.hypotheses.map((hypothesis) => ({
    ...hypothesis,
    evidence: hypothesis.evidence.map((cell) => ({ ...cell, evidence_id: idMap.get(cell.evidence_id) ?? cell.evidence_id })),
  }));
  const liveCase = liveElements.find((element) => (run.case_ids ?? []).includes(element.standard_id as string) && INVESTIGATION_CASE_SUBJECT_TYPES.includes(element.entity_type));
  const liveOutputs: InvestigationOutputs = {
    ...outputs,
    report_id: (outputs.report_standard_id && liveByStandard.get(outputs.report_standard_id)) || outputs.report_id || null,
    note_id: (outputs.note_standard_id && liveByStandard.get(outputs.note_standard_id)) || outputs.note_id || null,
  };
  const reasons: string[] = failure ? [failure.reason] : [];
  if (run.workspace_id) {
    const entityIds = R.uniq([run.subject_id, ...evidence.filter(isGraphEntity).map((item) => item.id)]).slice(0, INVESTIGATION_LIMITS.evidence);
    try {
      await workspaceEditField(exec.liveContext, runUser, run.workspace_id, [{ key: 'investigated_entities_ids', value: entityIds, operation: 'replace' as never }]);
    } catch (error) {
      reasons.push(`Investigation graph not updated (${errorMessage(error)})`);
    }
  }
  // A cancellation during the validation stays: the run only ends here while still active.
  const outcome = failure ? InvestigationRunStatus.Failed : InvestigationRunStatus.Completed;
  let ended = false;
  await updateInvestigationRun(exec.liveContext, run.internal_id, (current) => {
    if (TERMINAL_RUN_STATUSES.includes(current.run_status)) return null;
    ended = true;
    return {
      ...statusTransition(current, outcome, InvestigationRunPhase.Done, now, reasons.length > 0 ? reasons.join('. ') : null),
      ...(failure ? { end_reason_code: failure.code, ...closeOpenGates(current, now, 'Investigation failed') } : {}),
      evidence,
      hypotheses,
      outputs: liveOutputs,
      case_id: liveCase?.internal_id ?? current.case_id ?? null,
      case_ids: R.uniq([...(current.case_ids ?? []), ...(liveCase ? [liveCase.internal_id] : [])]),
    };
  });
  if (!ended) return;
  addInvestigationRunOutcomeCount(outcome);
  if (failure) {
    logApp.warn('[CASE AUTOPILOT] Investigation failed', { runId: run.internal_id, reason: failure.reason, code: failure.code });
  }
};

// endregion

/**
 * Advance one run by one phase. Errors fail the run with their message,
 * never the manager; a transient failure of the platform is retried on the
 * next passes, within a bound, every phase reusing what an interrupted pass
 * already recorded.
 */
export const processInvestigationRun = async (context: AuthContext, runId: string) => {
  const run = await loadInvestigationRun(context, runId);
  if (run && run.run_status === InvestigationRunStatus.Failed && (run.draft_id || run.workspace_id) && CARRY_BOUNDARY_CODES.includes(run.end_reason_code ?? '')) {
    await deleteStoppedRunArtifacts(context, runId, { draftId: run.draft_id ?? null, workspaceId: run.workspace_id ?? null });
  }
  if (run && STOPPED_RUN_STATUSES.includes(run.run_status) && run.xtm_status === ENGINE_CANCEL_PENDING) {
    await stopCancelledEngineRun(context, runId);
    return;
  }
  if (!run || TERMINAL_RUN_STATUSES.includes(run.run_status) || run.run_status === InvestigationRunStatus.AwaitingApproval) {
    return;
  }
  try {
    const runUser = await resolveRunIdentity(context, run.run_as_id);
    if (!runUser) {
      await stopRunAtCarryBoundary(context, runId, IDENTITY_UNAVAILABLE);
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
    switch (current.run_phase) {
      case InvestigationRunPhase.Initializing:
        await initializeRun(exec);
        break;
      case InvestigationRunPhase.Starting:
        await startEngine(exec);
        break;
      case InvestigationRunPhase.Investigating:
        await investigate(exec);
        break;
      case InvestigationRunPhase.Ingesting:
        await ingest(exec);
        break;
      case InvestigationRunPhase.Validating:
        await completeValidation(exec);
        break;
      default:
        break;
    }
    // Whatever state the complete pass left the run in: a pass that ends the run or makes it wait for an approval counts too.
    if ((run.step_failures ?? 0) > 0) {
      await updateInvestigationRun(context, runId, (current) => ((current.step_failures ?? 0) > 0 ? { step_failures: 0 } : null));
    }
  } catch (error) {
    const failures = (run.step_failures ?? 0) + 1;
    if (isTransientFailure(error) && failures < INVESTIGATION_LIMITS.stepFailures) {
      logApp.warn('[CASE AUTOPILOT] Investigation step interrupted, retried on the next pass', { runId, failures, cause: error });
      try {
        await updateRunningRun(context, runId, () => ({ step_failures: failures }));
      } catch (recordError) {
        logApp.warn('[CASE AUTOPILOT] Interrupted investigation step not recorded', { runId, cause: recordError });
      }
      return;
    }
    logApp.error('[CASE AUTOPILOT] Investigation step error', { runId, cause: error });
    await failRun(context, runId, errorMessage(error));
  }
};

/**
 * A run waiting for approval still shows what it derived. Its access boundary
 * is read again on every pass of the manager, under the actions lock of the
 * run so that no approval is being applied meanwhile: once its subject, its
 * case or what it cites is restricted to authorized members, or its subject or
 * case is no longer readable by its identity, the run stops with everything it
 * derived withheld and its draft deleted.
 */
export const revalidateAwaitingInvestigationRun = async (context: AuthContext, runId: string) => {
  try {
    await withRunActions(context, runId, async (run) => {
      if (run.run_status !== InvestigationRunStatus.AwaitingApproval) return;
      const runUser = await resolveRunIdentity(context, run.run_as_id);
      if (!runUser) {
        await stopRunAtCarryBoundary(context, runId, IDENTITY_UNAVAILABLE, { holdsActions: true });
        return;
      }
      const policy = run.policy_id ? await loadInvestigationPolicy(context, run.policy_id) : null;
      if (!policy) return;
      const exec: RunExecution = {
        run,
        runUser,
        policy,
        liveContext: await userContext(runUser),
        draftContext: await userContext(runUser, run.draft_id),
        now: new Date(),
        holdsActions: true,
      };
      const boundary = await findCarryBoundary(exec, runCitedIds(run));
      if (boundary) {
        await stopAtCarryBoundary(exec, boundary);
      }
    });
  } catch (error) {
    logApp.error('[CASE AUTOPILOT] Access boundary of an investigation waiting for approval not read', { runId, cause: error });
  }
};

const nextAwaitingRunsWindow = createRunWindow<BasicStoreEntityInvestigationRun>();

/**
 * The next runs waiting for approval whose access boundary is read again,
 * oldest first, resuming where the previous tick stopped, apart from the
 * active runs so that they never wait behind the runs under review.
 */
export const listAwaitingInvestigationRunsToRevalidate = (context: AuthContext, limit: number) => nextAwaitingRunsWindow(async (after) => {
  const connection = await pageEntitiesConnection<BasicStoreEntityInvestigationRun>(context, INVESTIGATION_MANAGER_USER, [ENTITY_TYPE_INVESTIGATION_RUN], {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['run_status'], values: [InvestigationRunStatus.AwaitingApproval] }],
      filterGroups: [],
    },
    noFiltersChecking: true,
    orderBy: 'created_at',
    orderMode: 'asc' as never,
    first: limit,
    after,
  });
  return {
    items: connection.edges.map((edge) => edge.node),
    endCursor: connection.pageInfo.endCursor ?? null,
    hasNextPage: connection.pageInfo.hasNextPage,
  };
});

const nextRunsWindow = createRunWindow<BasicStoreEntityInvestigationRun>();

/**
 * The next runs to advance, oldest first, resuming where the previous tick
 * stopped: the active runs, the cancelled or stopped runs whose engine run is
 * not confirmed stopped yet, and the runs stopped at an access boundary whose
 * draft or investigation graph is not deleted yet.
 */
export const listInvestigationRunsToProcess = (context: AuthContext, limit: number) => nextRunsWindow(async (after) => {
  const connection = await pageEntitiesConnection<BasicStoreEntityInvestigationRun>(context, INVESTIGATION_MANAGER_USER, [ENTITY_TYPE_INVESTIGATION_RUN], {
    filters: {
      mode: FilterMode.Or,
      filters: [{ key: ['run_status'], values: [InvestigationRunStatus.Planned, InvestigationRunStatus.Running] }],
      filterGroups: [{
        mode: FilterMode.And,
        filters: [
          { key: ['run_status'], values: STOPPED_RUN_STATUSES },
          { key: ['xtm_status'], values: [ENGINE_CANCEL_PENDING] },
        ],
        filterGroups: [],
      }, {
        mode: FilterMode.And,
        filters: [
          { key: ['run_status'], values: [InvestigationRunStatus.Failed] },
          { key: ['end_reason_code'], values: CARRY_BOUNDARY_CODES },
        ],
        filterGroups: [{
          mode: FilterMode.Or,
          filters: [
            { key: ['draft_id'], values: [], operator: FilterOperator.NotNil },
            { key: ['workspace_id'], values: [], operator: FilterOperator.NotNil },
          ],
          filterGroups: [],
        }],
      }],
    },
    noFiltersChecking: true,
    orderBy: 'created_at',
    orderMode: 'asc' as never,
    first: limit,
    after,
  });
  return {
    items: connection.edges.map((edge) => edge.node),
    endCursor: connection.pageInfo.endCursor ?? null,
    hasNextPage: connection.pageInfo.hasNextPage,
  };
});
