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
  InvestigationEvidenceKind,
  InvestigationRecommendationStatus,
  InvestigationRunPhase,
  InvestigationRunStatus,
} from '../../generated/graphql';
import { logApp } from '../../config/conf';
import { elFindByIds } from '../../database/engine';
import { internalFindByIds, pageEntitiesConnection, topEntitiesList, topRelationsList } from '../../database/middleware-loader';
import { deleteElementById, storeLoadByIdWithRefs } from '../../database/middleware';
import { getEntityFromCache } from '../../database/cache';
import { READ_DATA_INDICES_WITHOUT_INTERNAL, READ_INDEX_DRAFT_OBJECTS, READ_RELATIONSHIPS_INDICES } from '../../database/utils';
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
import { executionContext, INVESTIGATION_MANAGER_USER, isUserHasCapability, isUserInPlatformOrganization, KNOWLEDGE_KNENRICHMENT } from '../../utils/access';
import { resolveUserByIdFromCache } from '../user/user-domain';
import { addDraftWorkspace, deleteDraftWorkspace, validateDraftWorkspace } from '../draftWorkspace/draftWorkspace-domain';
import { addWorkspace, workspaceEditField } from '../workspace/workspace-domain';
import { askElementEnrichmentForConnectors } from '../../domain/stixCoreObject';
import { loadWorkById } from '../../domain/work';
import { addNote } from '../../domain/note';
import { addReport } from '../../domain/report';
import { addStixCyberObservable } from '../../domain/stixCyberObservable';
import { addStixCoreRelationship } from '../../domain/stixCoreRelationship';
import { stixDomainObjectAddRelation, stixDomainObjectEditField } from '../../domain/stixDomainObject';
import { addCaseIncident } from '../case/case-incident/case-incident-domain';
import { addInvestigationEnrichmentJobCount, addInvestigationRunOutcomeCount } from '../../manager/telemetryManager';
import { isXtmOneConfigured } from '../playbook/components/ai-agent-shared';
import {
  EMPTY_OUTPUTS,
  ENGINE_CANCEL_PENDING,
  ENGINE_NO_AGENT,
  ENGINE_NOT_CONFIGURED,
  ENGINE_UNAVAILABLE,
  ENGINE_UNREACHABLE,
  ENTITY_TYPE_INVESTIGATION_RUN,
  INVESTIGATION_CASE_SUBJECT_TYPES,
  INVESTIGATION_LIMITS,
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
import { listPolicyEnrichmentConnectors, loadInvestigationRun, stopCancelledEngineRun, updateInvestigationRun, withRunActions } from './investigationRun-domain';
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
  markingIdsOf,
  organizationIdsOf,
  representativeNameOf,
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
const MEMBER_RESTRICTED_CODE = 'member_restricted';
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

const jwtUserOf = (user: AuthUser) => ({ id: user.id, user_email: user.user_email });

const errorMessage = (error: unknown) => (error instanceof Error ? error.message : String(error)).slice(0, INVESTIGATION_LIMITS.textLength);

const isObjectEvidence = (evidence: InvestigationEvidence) => evidence.kind === InvestigationEvidenceKind.OpenctiObject && !!evidence.opencti_id;

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

const failRun = async (context: AuthContext, runId: string, reason: string, code?: string | null) => {
  const now = new Date();
  const updated = await updateInvestigationRun(context, runId, (current) => {
    if (TERMINAL_RUN_STATUSES.includes(current.run_status)) return null;
    return {
      ...statusTransition(current, InvestigationRunStatus.Failed, InvestigationRunPhase.Done, now, reason),
      end_reason_code: code ?? current.end_reason_code ?? null,
      pending_work_ids: [],
    };
  });
  if (updated.run_status === InvestigationRunStatus.Failed) {
    addInvestigationRunOutcomeCount(InvestigationRunStatus.Failed);
  }
  logApp.warn('[CASE AUTOPILOT] Investigation failed', { runId, reason, code });
};

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
  await updateInvestigationRun(exec.liveContext, run.internal_id, () => ({ engine_failures: failures }));
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
  // A relationship to an entity the run may not read is left out with it.
  return { relationships: relationships.filter((relationship) => readableIds.has(relationship.fromId) && readableIds.has(relationship.toId)), entities: readable };
};

// Objects of a case (the case of the run or the investigated case).
const collectCaseObjects = async (exec: RunExecution, caseId: string) => {
  const refs = await topRelationsList<BasicStoreRelation>(exec.draftContext, exec.runUser, RELATION_OBJECT, {
    fromId: caseId,
    first: INVESTIGATION_LIMITS.contextEntities,
  }) as unknown as BasicStoreRelation[];
  const ids = R.uniq(refs.map((ref) => ref.toId));
  if (ids.length === 0) return [];
  const objects = await elFindByIds<BasicStoreEntity>(exec.draftContext, exec.runUser, ids, { indices: READ_DATA_INDICES_WITHOUT_INTERNAL }) as BasicStoreEntity[];
  return withoutMemberRestricted(objects);
};

interface CollectedContext {
  engineContext: InvestigationEngineContext;
  contextEvidence: InvestigationEvidence[];
  candidateInfo: Map<string, { name?: string | null; entity_type?: string | null; standard_id?: string | null }>;
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
  const extraCandidates = withoutMemberRestricted(await findElements(draftContext, runUser, candidateIds.filter((id) => !knownIds.has(id))));
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
  return { engineContext, contextEvidence, candidateInfo };
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
    await stopAtCarryBoundary(exec, { reason: SUBJECT_INACCESSIBLE_REASON, code: null });
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
  // Draft: every write of the run lands here, nothing reaches the live graph without approval.
  let draftId = run.draft_id ?? null;
  if (!draftId) {
    const draft = await addDraftWorkspace(liveContext, runUser, {
      name: run.name,
      description: 'Draft of a Case Autopilot investigation: the evidence, the report, the notes and the relationships it proposes.',
      entity_id: subject.internal_id,
    });
    draftId = draft.id;
    patch.draft_id = draftId;
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
      patch.case_id = created.internal_id;
      patch.case_ids = R.uniq([...(run.case_ids ?? []), created.internal_id, created.standard_id]);
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
    patch.workspace_id = workspace.id;
  }
  patch.run_phase = InvestigationRunPhase.Starting;
  await updateInvestigationRun(liveContext, run.internal_id, () => patch);
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
    await stopAtCarryBoundary(exec, { reason: SUBJECT_INACCESSIBLE_REASON, code: null });
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
  await updateInvestigationRun(exec.liveContext, run.internal_id, (current) => {
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
  // Sent to the engine: what is restricted to authorized members stays out, as in the context.
  return withoutMemberRestricted([...entities, ...relationships])
    .filter((element) => (element as unknown as { draft_change?: { draft_operation?: string } }).draft_change?.draft_operation)
    .slice(0, INVESTIGATION_LIMITS.waveDelta)
    .map((element) => ({
      id: element.internal_id,
      standard_id: element.standard_id ?? null,
      entity_type: element.entity_type,
      representative: representativeNameOf(element),
      connector_name: connectorNames.length === 1 ? connectorNames[0] : null,
      action: (element as unknown as { draft_change?: { draft_operation?: string } }).draft_change?.draft_operation === 'create' ? 'created' : 'updated',
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
        let requestPatch: Partial<InvestigationEnrichmentRequest>;
        try {
          const works = await askElementEnrichmentForConnectors(exec.draftContext, runUser, request.entity_id, [request.connector_id]);
          const startedWorkId = works?.[0]?.id ?? null;
          requestPatch = startedWorkId
            ? { status: InvestigationEnrichmentRequestStatus.Dispatched, work_id: startedWorkId, dispatched_at: now.toISOString() }
            : { status: InvestigationEnrichmentRequestStatus.Failed, error: 'The connector did not accept the job', completed_at: now.toISOString() };
        } catch (error) {
          requestPatch = { status: InvestigationEnrichmentRequestStatus.Failed, error: errorMessage(error), completed_at: now.toISOString() };
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

const citedElements = async (exec: RunExecution, evidence: InvestigationEvidence[], conclusion: Record<string, unknown> | null | undefined): Promise<BasicStoreCommon[]> => {
  const ids = revisionCitedIds(evidence, conclusion);
  if (ids.length === 0) return [];
  return withoutMemberRestricted(await findElements(exec.draftContext, exec.runUser, ids));
};

// A run and its outputs carry markings and organization sharing, never a member
// restriction, and its markings were copied from what its identity read. The
// run stops before anything more is sent to the engine or mirrored once its
// subject or its case is no longer readable by that identity, or once one of
// them, or an object the engine cites, is restricted to authorized members.
// Restrictions are read on the live objects by the manager, whoever they hide
// the object from: the copy a draft holds of a live object keeps the
// restrictions it had when it was copied, and a restriction that excludes the
// run identity would hide the object from it.
const findCarryBoundary = async (exec: RunExecution, citedIds: string[]): Promise<{ reason: string; code: string | null } | null> => {
  const { run } = exec;
  const ids = R.uniq([run.subject_id, run.case_id, ...citedIds].filter((id): id is string => !!id));
  const managerContext = await userContext(INVESTIGATION_MANAGER_USER);
  const [allLive, readableLive, inDraft] = await Promise.all([
    findElements(managerContext, INVESTIGATION_MANAGER_USER, ids),
    findElements(exec.liveContext, exec.runUser, [run.subject_id, run.case_id].filter((id): id is string => !!id)),
    findElements(exec.draftContext, exec.runUser, ids),
  ]);
  const idsOf = (elements: BasicStoreCommon[]) => new Set(elements.flatMap((element) => [element.internal_id, element.standard_id]));
  const readableIds = idsOf(readableLive);
  // Only a case the run created exists in its draft alone.
  const caseReadable = !run.case_id || readableIds.has(run.case_id) || (run.create_case && idsOf(inDraft).has(run.case_id));
  if (!readableIds.has(run.subject_id) || !caseReadable) {
    return { reason: SUBJECT_INACCESSIBLE_REASON, code: null };
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

// Everything the run derived from what it read is withheld, as it may describe
// what the run can no longer carry: the engine's text, the conclusion OpenCTI
// scored from it, the references to its outputs, and its draft, deleted with
// what it wrote there. Gates still waiting are rejected, jobs not started skipped.
const stopAtCarryBoundary = async (exec: RunExecution, boundary: { reason: string; code: string | null }) => {
  const now = new Date();
  const stop: { done: boolean; engineRunning: boolean; draftId: string | null } = { done: false, engineRunning: false, draftId: null };
  await updateInvestigationRun(exec.liveContext, exec.run.internal_id, (current) => {
    if (TERMINAL_RUN_STATUSES.includes(current.run_status)) return null;
    stop.done = true;
    stop.engineRunning = current.run_phase === InvestigationRunPhase.Investigating && !!current.xtm_investigation_id && !current.budget_cancelled;
    stop.draftId = current.draft_id ?? null;
    return {
      ...statusTransition(current, InvestigationRunStatus.Failed, InvestigationRunPhase.Done, now, boundary.reason),
      end_reason_code: boundary.code,
      pending_work_ids: [],
      goal_plan: null,
      steps: (current.steps ?? []).map((step) => ({ ...step, action: null, detail_params: null })),
      evidence: [],
      hypotheses: [],
      timeline: [],
      recommendations: [],
      summary: null,
      report: null,
      report_sources: [],
      outputs: EMPTY_OUTPUTS,
      draft_id: null,
      approvals: current.approvals.map((approval) => (approval.status === InvestigationApprovalStatus.Pending
        ? { ...approval, status: InvestigationApprovalStatus.Rejected, decided_at: now.toISOString(), rejection_reason: 'Investigation stopped' }
        : approval)),
      enrichment_requests: current.enrichment_requests.map((request) => (request.status === InvestigationEnrichmentRequestStatus.Queued
        || request.status === InvestigationEnrichmentRequestStatus.AwaitingApproval
        ? { ...request, status: InvestigationEnrichmentRequestStatus.Skipped, error: 'Investigation stopped', completed_at: now.toISOString() }
        : request)),
      enrichment_waves: (current.enrichment_waves ?? []).map((wave) => ({ ...wave, delta: [] })),
      ...(stop.engineRunning ? { xtm_status: ENGINE_CANCEL_PENDING, engine_failures: 0 } : {}),
    };
  });
  if (!stop.done) return;
  addInvestigationRunOutcomeCount(InvestigationRunStatus.Failed);
  if (stop.draftId) {
    try {
      await deleteDraftWorkspace(exec.liveContext, INVESTIGATION_MANAGER_USER, stop.draftId);
    } catch (cause) {
      logApp.error('[CASE AUTOPILOT] Draft of a stopped investigation not deleted', { runId: exec.run.internal_id, draftId: stop.draftId, cause });
    }
  }
  if (stop.engineRunning) {
    await stopCancelledEngineRun(exec.liveContext, exec.run.internal_id);
  }
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
  const run = await processEnrichments(exec);
  const { runUser, now } = exec;
  const investigationId = run.xtm_investigation_id;
  if (!investigationId) {
    await updateInvestigationRun(exec.liveContext, run.internal_id, () => ({ run_phase: InvestigationRunPhase.Starting }));
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
    await updateInvestigationRun(exec.liveContext, run.internal_id, () => ({
      budget_cancelled: true,
      wave_started_at: now.toISOString(),
      status_reason: 'The time budget is spent: the investigation concludes with what it found',
    }));
  }
  const result = await getInvestigation(jwtUserOf(runUser), investigationId, run.draft_id);
  if (!result.ok) {
    const graceOver = budgetCancelled && now.getTime() - new Date(run.wave_started_at ?? now.toISOString()).getTime() > BUDGET_CANCEL_GRACE_MS;
    if (graceOver) {
      await updateInvestigationRun(exec.liveContext, run.internal_id, () => ({ run_phase: InvestigationRunPhase.Ingesting }));
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
    await updateInvestigationRun(exec.liveContext, run.internal_id, (current) => mirrorPatch(current, engine, cited, citable));
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
  await updateInvestigationRun(exec.liveContext, run.internal_id, (current) => ({
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
  const attempt = async (label: string, fn: () => Promise<void>) => {
    try {
      await fn();
    } catch (error) {
      failures.push(`${label} (${errorMessage(error)})`);
      logApp.warn('[CASE AUTOPILOT] Investigation output not written', { runId: run.internal_id, output: label, cause: errorMessage(error) });
    }
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
          }).catch((error: unknown) => logApp.debug('[CASE AUTOPILOT] Knowledge relationship not written', { cause: errorMessage(error) }));
        }, { concurrency: 5 });
      }
      if (allowedAction(InvestigationAutonomousAction.CreateNote)) {
        await BluePromise.map(knowledge.notes, async (finding) => {
          const observableId = outputs.observable_ids[finding.value];
          if (!observableId) return;
          await addNote(draftContext, runUser, {
            attribute_abstract: FINDING_NOTE_ABSTRACT,
            content: finding.content,
            objects: [observableId],
            objectMarking: markings,
            objectOrganization: organizations,
            note_types: ['analysis'],
          });
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
        .catch((error: unknown) => logApp.debug('[CASE AUTOPILOT] Object not added to the case', { toId, cause: errorMessage(error) }));
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
// identity reads them (an identifier it cannot read restricts nothing).
const collectRunRestrictions = async (exec: RunExecution, subject: BasicStoreEntity, caseId: string | null, candidateIds: string[]): Promise<OutputRestrictions> => {
  const ids = R.uniq([
    ...exec.run.evidence.filter(isObjectEvidence).map((evidence) => evidence.opencti_id as string),
    ...exec.run.hypotheses.map((hypothesis) => hypothesis.candidate_id),
    ...exec.run.recommendations.flatMap((recommendation) => (recommendation.course_of_action_id ? [recommendation.course_of_action_id] : [])),
    ...candidateIds,
    ...(caseId ? [caseId] : []),
  ]).slice(0, INVESTIGATION_LIMITS.evidence + INVESTIGATION_LIMITS.candidates + INVESTIGATION_LIMITS.coursesOfAction + 1);
  const elements = await findElements(exec.draftContext, exec.runUser, ids);
  return {
    markings: R.uniq([...markingIdsOf(subject), ...elements.flatMap((element) => markingIdsOf(element))]),
    organizations: intersectOrganizationIds(organizationIdsOf(subject), elements),
  };
};

const ingestRun = async (exec: RunExecution) => {
  const { run, runUser, now, policy } = exec;
  const subject = await loadSubject(exec);
  if (!subject) {
    await stopAtCarryBoundary(exec, { reason: SUBJECT_INACCESSIBLE_REASON, code: null });
    return;
  }
  // The final state of the engine run; what was mirrored when it cannot be read.
  let engine: EngineInvestigation | null = null;
  if (run.xtm_investigation_id) {
    const result = await getInvestigation(jwtUserOf(runUser), run.xtm_investigation_id, run.draft_id);
    if (result.ok) {
      engine = result.value;
    } else if (result.failure === ENGINE_UNREACHABLE && (run.engine_failures ?? 0) + 1 < INVESTIGATION_LIMITS.engineFailures) {
      await updateInvestigationRun(exec.liveContext, run.internal_id, (current) => ({ engine_failures: (current.engine_failures ?? 0) + 1 }));
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
  const { outputs, caseId, caseIds, failures } = await writeOutputs({ ...exec, run: finalRun }, subject, engine, outputRestrictions);
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
  await ingestRun({ ...exec, run });
});

// endregion

// region validation

const completeValidation = async (exec: RunExecution) => {
  const { run, runUser, now } = exec;
  const work = run.validation_work_id ? await loadWork(exec.liveContext, run.validation_work_id) : null;
  const startedAt = run.wave_started_at ? new Date(run.wave_started_at).getTime() : now.getTime();
  const timedOut = now.getTime() - startedAt > VALIDATION_TIMEOUT_MS;
  if (work && work.status !== 'complete' && !timedOut) {
    return; // The validation work is still being processed.
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
  const reasons: string[] = [];
  if (work?.status !== 'complete') reasons.push('Draft validation not confirmed in time, ids resolved with what is available');
  if (run.workspace_id) {
    const entityIds = R.uniq([run.subject_id, ...evidence.filter(isGraphEntity).map((item) => item.id)]).slice(0, INVESTIGATION_LIMITS.evidence);
    try {
      await workspaceEditField(exec.liveContext, runUser, run.workspace_id, [{ key: 'investigated_entities_ids', value: entityIds, operation: 'replace' as never }]);
    } catch (error) {
      reasons.push(`Investigation graph not updated (${errorMessage(error)})`);
    }
  }
  // A cancellation during the validation stays: the run is only completed while still active.
  const finalized = await updateInvestigationRun(exec.liveContext, run.internal_id, (current) => (TERMINAL_RUN_STATUSES.includes(current.run_status) ? null : {
    ...statusTransition(current, InvestigationRunStatus.Completed, InvestigationRunPhase.Done, now, reasons.length > 0 ? reasons.join('. ') : null),
    evidence,
    hypotheses,
    outputs: liveOutputs,
    case_id: liveCase?.internal_id ?? current.case_id ?? null,
    case_ids: R.uniq([...(current.case_ids ?? []), ...(liveCase ? [liveCase.internal_id] : [])]),
  }));
  if (finalized.run_status === InvestigationRunStatus.Completed) {
    addInvestigationRunOutcomeCount(InvestigationRunStatus.Completed);
  }
};

// endregion

/**
 * Advance one run by one phase. Errors fail the run with their message,
 * never the manager.
 */
export const processInvestigationRun = async (context: AuthContext, runId: string) => {
  const run = await loadInvestigationRun(context, runId);
  if (run && STOPPED_RUN_STATUSES.includes(run.run_status) && run.xtm_status === ENGINE_CANCEL_PENDING) {
    await stopCancelledEngineRun(context, runId);
    return;
  }
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
  } catch (error) {
    logApp.error('[CASE AUTOPILOT] Investigation step error', { runId, cause: error });
    await failRun(context, runId, errorMessage(error));
  }
};

const nextRunsWindow = createRunWindow<BasicStoreEntityInvestigationRun>();

/**
 * The next runs to advance, oldest first, resuming where the previous tick
 * stopped: the active runs, and the cancelled or stopped runs whose engine run
 * is not confirmed stopped yet.
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
