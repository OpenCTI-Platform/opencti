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

import { v4 as uuidv4 } from 'uuid';
import { Promise as BluePromise } from 'bluebird';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreCommon, BasicStoreEntity, BasicStoreRelation, StoreEntity } from '../../types/store';
import {
  FilterMode,
  FilterOperator,
  InvestigationApprovalKind,
  InvestigationApprovalStatus,
  InvestigationAutonomousAction,
  InvestigationEnrichmentRequestStatus,
  InvestigationFeedbackDecision,
  InvestigationFeedbackItemType,
  InvestigationRecommendationActionKind,
  InvestigationRecommendationApplyMode,
  InvestigationRecommendationStatus,
  InvestigationRunPhase,
  InvestigationRunStatus,
  InvestigationRunTrigger,
  OrderingMode,
  type InvestigationRunEnrichmentRequestInput,
  type InvestigationRunFeedbackInput,
  type QueryInvestigationRunsArgs,
} from '../../generated/graphql';
import { checkEnterpriseEdition, isEnterpriseEdition } from '../../enterprise-edition/ee';
import { elFindByIds } from '../../database/engine';
import { internalLoadById, pageEntitiesConnection, storeLoadById, topEntitiesList, topRelationsList } from '../../database/middleware-loader';
import { createEntity, patchAttribute, storeLoadByIdWithRefs } from '../../database/middleware';
import { deleteInternalObject } from '../../domain/internalObject';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { ForbiddenAccess, FunctionalError } from '../../config/errors';
import { lockResources } from '../../lock/master-lock';
import { READ_DATA_INDICES_WITHOUT_INTERNAL, READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { extractEntityRepresentativeName } from '../../database/entity-representative';
import {
  executionContext,
  INVESTIGATION_MANAGER_USER,
  isBypassUser,
  isUserHasCapability,
  isUserInPlatformOrganization,
  KNOWLEDGE_KNENRICHMENT,
  KNOWLEDGE_KNUPDATE,
  KNOWLEDGE_KNUPDATE_KNDELETE,
  MEMBER_ACCESS_RIGHT_ADMIN,
} from '../../utils/access';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { RELATION_OBJECT, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { buildRefRelationKey } from '../../schema/general';
import { iAliasedIds, xOpenctiStixIds } from '../../schema/attribute-definition';
import { stixDomainObjectAddRelation, stixDomainObjectEditField } from '../../domain/stixDomainObject';
import { taskAdd } from '../task/task-domain';
import { deleteDraftWorkspace, draftWorkspaceEditAuthorizedMembers, findById as findDraftById, validateDraftWorkspace } from '../draftWorkspace/draftWorkspace-domain';
import { findById as findWorkspaceById, workspaceDelete, workspaceEditAuthorizedMembers } from '../workspace/workspace-domain';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../draftWorkspace/draftWorkspace-types';
import { ENTITY_TYPE_WORKSPACE } from '../workspace/workspace-types';
import { registerWithheldElements, type WithheldElementsProvider } from '../../utils/withheldElements';
import { connectorsForEnrichment } from '../../database/repository';
import { isUserAccountValid, resolveUserByIdFromCache } from '../user/user-domain';
import { ENTITY_TYPE_CONTAINER_CASE } from '../case/case-types';
import { addInvestigationFeedbackCount, addInvestigationRunCount, addInvestigationRunOutcomeCount } from '../../manager/telemetryManager';
import {
  ACTIVE_RUN_STATUSES,
  CARRY_BOUNDARY_CODES,
  EMPTY_OUTPUTS,
  ENGINE_CANCEL_FAILED,
  ENGINE_CANCEL_PENDING,
  ENGINE_DISABLED,
  ENGINE_NOT_CONFIGURED,
  ENGINE_UNAVAILABLE,
  ENTITY_TYPE_INVESTIGATION_RUN,
  INVESTIGATION_CASE_SUBJECT_TYPES,
  INVESTIGATION_DEFAULT_AGENT_SLUG,
  INVESTIGATION_LIMITS,
  INVESTIGATION_SUBJECT_TYPES,
  INVESTIGATION_TAB_SUBJECT_TYPES,
  MEMBER_RESTRICTED_CODE,
  SOURCE_INACCESSIBLE_CODE,
  TERMINAL_RUN_STATUSES,
  type BasicStoreEntityInvestigationPolicy,
  type BasicStoreEntityInvestigationRun,
  type InvestigationApproval,
  type InvestigationEnrichmentRequest,
  type InvestigationEnrichmentWave,
  type InvestigationFeedback,
  type InvestigationRecommendation,
  type StoreEntityInvestigationRun,
} from './investigationRun-types';
import { applyInvestigationPolicyAcceptanceDelta, getDefaultInvestigationPolicy, loadInvestigationPolicy, policyUsageLockKey } from './investigationPolicy-domain';
import {
  boundApprovals,
  buildBudget,
  computeWaveStatus,
  evaluateEnrichmentRequest,
  feedbackCounterDelta,
  isEnrichmentRejection,
  remainingIterations,
  remainingMinutes,
  statusTransition,
  upsertFeedback,
} from './investigationRun-state';
import { cancelInvestigation, listInvestigationPacks, pushInvestigationFeedback } from './investigationRun-xtm';
import { notifyInvestigationRunStatus } from './investigationRun-notification';
import {
  intersectOrganizationIds,
  isCreationSharingWidened,
  isMemberRestricted,
  markingIdsOf,
  organizationIdsOf,
  runSourceIds,
  withheldRunContent,
} from './investigationRun-utils';
import { getEntityFromCache } from '../../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import type { BasicStoreSettings } from '../../types/settings';

const runLockKey = (runId: string) => `investigation_run_lock_${runId}`;
const subjectLockKey = (subjectId: string) => `investigation_run_subject_lock_${subjectId}`;
const runActionsLockKey = (runId: string) => `investigation_run_actions_lock_${runId}`;

const outOfDraft = (context: AuthContext): AuthContext => ({ ...context, draft_context: '' });

// region access

export const isInvestigableEntityType = (entityType: string) => {
  return INVESTIGATION_SUBJECT_TYPES.includes(entityType) || isStixCyberObservable(entityType);
};

/**
 * The identity a run acts as, while it may still use the platform: an account
 * deleted, locked or expired since is no identity at all, by the rules applied
 * when it authenticates.
 */
export const resolveRunIdentity = async (context: AuthContext, userId: string): Promise<AuthUser | null> => {
  const user = await resolveUserByIdFromCache(context, userId);
  if (!user) return null;
  const settings = await getEntityFromCache<BasicStoreSettings>(context, INVESTIGATION_MANAGER_USER, ENTITY_TYPE_SETTINGS);
  return isUserAccountValid(user, settings) ? user : null;
};

/**
 * A context of a run identity, read as an authenticated request of that
 * identity would be: organization restrictions depend on its platform
 * organization membership, which a bare execution context leaves unset.
 */
export const investigationIdentityContext = async (source: string, user: AuthUser, draftId?: string | null): Promise<AuthContext> => {
  const context = executionContext(source, user, draftId ?? undefined);
  const settings = await getEntityFromCache<BasicStoreSettings>(context, INVESTIGATION_MANAGER_USER, ENTITY_TYPE_SETTINGS);
  context.user_inside_platform_organization = isUserInPlatformOrganization(user, settings);
  return context;
};

export const loadInvestigationRun = (context: AuthContext, id: string) => {
  return internalLoadById<BasicStoreEntityInvestigationRun>(context, INVESTIGATION_MANAGER_USER, id, { type: ENTITY_TYPE_INVESTIGATION_RUN });
};

const VALIDATION_NOT_CANCELLABLE = 'The approved changes of this investigation are being written to the case: it can no longer be cancelled';
const ENGINE_STOP_UNCONFIRMED = 'XTM One has not confirmed yet that the engine run of this investigation stopped: try deleting it again in a moment';
const ARTIFACTS_NOT_DELETED = 'The draft or the investigation graph of this investigation could not be deleted yet: try deleting it again in a moment';
const FINDINGS_WITHHELD: Record<string, string> = {
  [MEMBER_RESTRICTED_CODE]: 'What this investigation found is withheld: an entity it investigated or cites is now restricted to authorized members',
  [SOURCE_INACCESSIBLE_CODE]: 'What this investigation found is withheld: an entity it investigated or cites is no longer accessible to you',
};
// A run whose findings are already withheld: stopped at an access boundary, or served withheld.
const WITHHELD_CODES = [...CARRY_BOUNDARY_CODES, SOURCE_INACCESSIBLE_CODE];
export const isInvestigationRunWithheld = (run: BasicStoreEntityInvestigationRun) => !!run.end_reason_code && WITHHELD_CODES.includes(run.end_reason_code);

/**
 * A run copies the markings and organization sharing of what it reads, never a
 * member restriction, and the manager refreshes them only while the run is
 * active. What a run derived is therefore served to a reader only while its
 * subject, its case, the context the engine received and every object it
 * cites, as live objects now, are:
 * - not restricted to authorized members, whoever reads;
 * - readable by that reader, so a marking or a sharing tightened on one of
 *   them after the run read it withholds the findings from those it excludes.
 * Read on every read and action, whatever the run status: the manager stops an
 * active run at an access boundary only on its next pass and never revisits an
 * ended one. Its markings are served the same way: those it copied, plus those
 * its sources carry now, so an export ceiling or a reader weighs what its
 * findings describe today. The sources of every run are read at once.
 * What a run's enrichments brought exists only in its draft until the draft
 * is validated (it is then live under its standard id, which the run also
 * carries): a source not found live is read in that draft and checked the
 * same way. A source found in neither is an object deleted since, or a draft
 * object already validated: its absence alone withholds nothing, the run
 * carrying the markings of what it read.
 */
const readRunSources = async (
  context: AuthContext,
  user: AuthUser,
  runs: BasicStoreEntityInvestigationRun[],
): Promise<Array<{ reason: string | null; markingIds: string[] }>> => {
  const isWithheld = isInvestigationRunWithheld;
  const ids = Array.from(new Set(runs.filter((run) => !isWithheld(run)).flatMap((run) => runSourceIds(run))));
  if (ids.length === 0) return runs.map(() => ({ reason: null, markingIds: [] }));
  const liveContext = outOfDraft(context);
  // The PIRs of the context are internal objects.
  const opts = { indices: [...READ_DATA_INDICES_WITHOUT_INTERNAL, READ_INDEX_INTERNAL_OBJECTS], baseData: true };
  // Every id an element is found by, so that a source is never missed for being named by another one.
  const sourceOpts = { ...opts, baseFields: [buildRefRelationKey(RELATION_OBJECT_MARKING), xOpenctiStixIds.name, iAliasedIds.name] };
  const idsOf = (element: BasicStoreEntity) => [
    element.internal_id,
    element.standard_id,
    ...((element as { x_opencti_stix_ids?: string[] }).x_opencti_stix_ids ?? []),
    ...((element as { i_aliases_ids?: string[] }).i_aliases_ids ?? []),
  ];
  const readSources = async (readContext: AuthContext, sourceIds: string[]) => {
    const [found, readable] = await Promise.all([
      elFindByIds<BasicStoreEntity>(readContext, INVESTIGATION_MANAGER_USER, sourceIds, sourceOpts) as Promise<BasicStoreEntity[]>,
      elFindByIds<BasicStoreEntity>(readContext, user, sourceIds, opts) as Promise<BasicStoreEntity[]>,
    ]);
    const readableIds = new Set(readable.map((element) => element.internal_id));
    return {
      found: new Set(found.flatMap(idsOf)),
      restricted: new Set(found.filter((element) => isMemberRestricted(element)).flatMap(idsOf)),
      unreadable: new Set(found.filter((element) => !readableIds.has(element.internal_id)).flatMap(idsOf)),
      markingsOf: new Map(found.flatMap((element) => idsOf(element).map((id) => [id, markingIdsOf(element)] as const))),
    };
  };
  const live = await readSources(liveContext, ids);
  const draftOnlyIds = new Map<string, Set<string>>();
  runs.forEach((run) => {
    if (isWithheld(run) || !run.draft_id) return;
    const missing = runSourceIds(run).filter((id) => !live.found.has(id));
    if (missing.length === 0) return;
    const draftIds = draftOnlyIds.get(run.draft_id) ?? new Set<string>();
    missing.forEach((id) => draftIds.add(id));
    draftOnlyIds.set(run.draft_id, draftIds);
  });
  const drafts = new Map(await Promise.all(Array.from(draftOnlyIds.entries()).map(async ([draftId, draftIds]) => {
    return [draftId, await readSources({ ...liveContext, draft_context: draftId }, Array.from(draftIds))] as const;
  })));
  return runs.map((run) => {
    if (isWithheld(run)) return { reason: null, markingIds: [] };
    const sources = runSourceIds(run);
    const draft = run.draft_id ? drafts.get(run.draft_id) : undefined;
    // Live versions are authoritative for what exists live.
    const readOf = (id: string) => (live.found.has(id) || !draft ? live : draft);
    const markingIds = Array.from(new Set(sources.flatMap((id) => readOf(id).markingsOf.get(id) ?? [])));
    if (sources.some((id) => readOf(id).restricted.has(id))) return { reason: MEMBER_RESTRICTED_CODE, markingIds };
    if (sources.some((id) => readOf(id).unreadable.has(id))) return { reason: SOURCE_INACCESSIBLE_CODE, markingIds };
    return { reason: null, markingIds };
  });
};

/** For each run, why its findings are withheld from the reader, or null. */
export const findInvestigationRunsWithheldReasons = async (context: AuthContext, user: AuthUser, runs: BasicStoreEntityInvestigationRun[]) => {
  return (await readRunSources(context, user, runs)).map(({ reason }) => reason);
};

/**
 * A run as it is served while its findings are withheld from the reader:
 * emptied, with the reason code. Its status reason can carry error details of
 * what it did, so it is withheld too; the code says why.
 */
export const withholdInvestigationRunFindings = (run: BasicStoreEntityInvestigationRun, reason: string): BasicStoreEntityInvestigationRun => ({
  ...run,
  ...withheldRunContent(run),
  status_reason: null,
  end_reason_code: reason,
});

/** The runs as they are served to the reader: findings withheld or not, markings of their sources added. */
export const findServedInvestigationRuns = async (context: AuthContext, user: AuthUser, runs: BasicStoreEntityInvestigationRun[]) => {
  const reads = await readRunSources(context, user, runs);
  return runs.map((run, index) => {
    const { reason, markingIds } = reads[index];
    const view = reason ? withholdInvestigationRunFindings(run, reason) : run;
    const stored = markingIdsOf(run);
    const added = markingIds.filter((id) => !stored.includes(id));
    return added.length > 0 ? { ...view, [RELATION_OBJECT_MARKING]: [...stored, ...added] } : view;
  });
};

const serveInvestigationRun = async (context: AuthContext, user: AuthUser, run: BasicStoreEntityInvestigationRun) => {
  const [served] = await findServedInvestigationRuns(context, user, [run]);
  return served;
};

// Batch loader behind the run resolvers: one read for the runs of a page.
export const batchServedInvestigationRuns = async (context: AuthContext, user: AuthUser, runs: BasicStoreEntityInvestigationRun[]) => {
  return await findServedInvestigationRuns(context, user, runs) as unknown as BasicStoreCommon[];
};

const loadServedRun = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkEnterpriseEdition(context);
  const run = await storeLoadById<BasicStoreEntityInvestigationRun>(outOfDraft(context), user, id, ENTITY_TYPE_INVESTIGATION_RUN);
  if (!run) return null;
  const [served] = await findServedInvestigationRuns(context, user, [run]);
  const withheld = served.end_reason_code !== run.end_reason_code ? served.end_reason_code ?? null : null;
  return { run: served, withheld };
};

// The markings and organizations of the investigated entity are copied on
// the run: the engine only returns it to users who can see the entity.
export const findInvestigationRunById = async (context: AuthContext, user: AuthUser, id: string) => {
  const served = await loadServedRun(context, user, id);
  return served?.run ?? null;
};

// A run the user acts on. An action on what it found (feedback, a
// recommendation, an approval, a continuation, an enrichment) is refused while
// that is withheld; cancelling and deleting it stay possible.
const findAccessibleRun = async (context: AuthContext, user: AuthUser, id: string, opts: { onFindings?: boolean } = {}) => {
  const served = await loadServedRun(context, user, id);
  if (!served) {
    throw FunctionalError('Investigation run not found', { id });
  }
  if (opts.onFindings && served.withheld) {
    throw FunctionalError(FINDINGS_WITHHELD[served.withheld], { id });
  }
  return served.run;
};

// The same refusal, read again on the fresh run an action executes on.
const assertFindingsServed = async (context: AuthContext, user: AuthUser, run: BasicStoreEntityInvestigationRun) => {
  const [withheld] = await findInvestigationRunsWithheldReasons(context, user, [run]);
  if (withheld) {
    throw FunctionalError(FINDINGS_WITHHELD[withheld], { id: run.internal_id });
  }
};

const emptyConnection = () => ({ edges: [], pageInfo: { startCursor: '', endCursor: '', hasNextPage: false, hasPreviousPage: false, globalCount: 0 } });

export const findInvestigationRunsPaginated = async (context: AuthContext, user: AuthUser, args: QueryInvestigationRunsArgs) => {
  await checkEnterpriseEdition(context);
  const { subjectId, caseId, ...listArgs } = args;
  const liveContext = outOfDraft(context);
  let { filters } = listArgs;
  if (subjectId) {
    const subject = await internalLoadById<BasicStoreEntity>(liveContext, user, subjectId);
    if (!subject) return emptyConnection();
    filters = addFilter(filters, 'subject_id', [subject.internal_id]);
  }
  if (caseId) {
    const caseEntity = await internalLoadById<BasicStoreEntity>(liveContext, user, caseId, { type: ENTITY_TYPE_CONTAINER_CASE });
    if (!caseEntity) return emptyConnection();
    filters = addFilter(filters, 'case_ids', [caseEntity.internal_id, caseEntity.standard_id]);
  }
  return pageEntitiesConnection<BasicStoreEntityInvestigationRun>(liveContext, user, [ENTITY_TYPE_INVESTIGATION_RUN], {
    ...listArgs,
    filters,
    orderBy: listArgs.orderBy ?? 'created_at',
    orderMode: listArgs.orderMode ?? OrderingMode.Desc,
  });
};

const LATEST_RUNS_PAGE = 500;
const LATEST_RUNS_ROUNDS = 5;
const LATEST_RUNS_CONCURRENCY = 5;

// Batch loader behind the run badges of case and incident lists: one query for
// the page. When that page is full, a few cases with many runs may have hidden
// the others: those are resolved together, round after round, each round
// leaving out the cases resolved so far (a page that is not full proves the
// rest have none), and only what is left after the rounds one by one, a few
// at a time.
// Outside the Enterprise Edition the field is null, so case queries keep working.
// What a run beyond its access boundary derived is withheld by the run
// resolvers, as for every other path that resolves a run.
export const batchLatestInvestigationRuns = async (context: AuthContext, user: AuthUser, entityIds: string[]) => {
  if (!(await isEnterpriseEdition(context))) {
    return entityIds.map(() => null) as unknown as BasicStoreCommon[];
  }
  const liveContext = outOfDraft(context);
  const ids = Array.from(new Set(entityIds));
  const filtersFor = (values: string[]) => ({
    mode: FilterMode.Or,
    filters: [{ key: ['case_ids'], values }, { key: ['subject_id'], values }],
    filterGroups: [],
  });
  const latestRuns = (values: string[], first: number) => topEntitiesList<BasicStoreEntityInvestigationRun>(liveContext, user, [ENTITY_TYPE_INVESTIGATION_RUN], {
    filters: filtersFor(values),
    orderBy: 'created_at',
    orderMode: 'desc' as never,
    first,
  });
  const byId = new Map<string, BasicStoreEntityInvestigationRun | null>();
  const resolveFrom = (runs: BasicStoreEntityInvestigationRun[], values: string[]) => values.forEach((id) => {
    const latest = runs.find((run) => run.subject_id === id || (run.case_ids ?? []).includes(id));
    if (latest) byId.set(id, latest);
  });
  let page = await latestRuns(ids, LATEST_RUNS_PAGE);
  resolveFrom(page, ids);
  let missing = ids.filter((id) => !byId.has(id));
  for (let round = 0; page.length >= LATEST_RUNS_PAGE && missing.length > 0 && round < LATEST_RUNS_ROUNDS; round += 1) {
    page = await latestRuns(missing, LATEST_RUNS_PAGE);
    resolveFrom(page, missing);
    missing = missing.filter((id) => !byId.has(id));
  }
  if (page.length >= LATEST_RUNS_PAGE && missing.length > 0) {
    await BluePromise.map(missing, async (id) => {
      const [run] = await latestRuns([id], 1);
      if (run) byId.set(id, run);
    }, { concurrency: LATEST_RUNS_CONCURRENCY });
  }
  return entityIds.map((id) => byId.get(id) ?? null) as unknown as BasicStoreCommon[];
};

// endregion

// region updates

/**
 * Read-modify-write of a run under its own lock. Every writer (manager,
 * analysts, agent tools) goes through here so concurrent updates never lose
 * a ledger entry or a decision. The lock is held only for the update itself,
 * never during an agent call or an enrichment wait.
 */
export const updateInvestigationRun = async (
  context: AuthContext,
  runId: string,
  mutate: (run: BasicStoreEntityInvestigationRun) => Promise<Record<string, unknown> | null> | Record<string, unknown> | null,
): Promise<BasicStoreEntityInvestigationRun> => {
  const lock = await lockResources([runLockKey(runId)]);
  let previous: BasicStoreEntityInvestigationRun;
  let updated: BasicStoreEntityInvestigationRun;
  try {
    const run = await loadInvestigationRun(outOfDraft(context), runId);
    if (!run) {
      throw FunctionalError('Investigation run not found', { id: runId });
    }
    const patch = await mutate(run);
    if (!patch || Object.keys(patch).length === 0) {
      return run;
    }
    const { element } = await patchAttribute<StoreEntityInvestigationRun>(outOfDraft(context), INVESTIGATION_MANAGER_USER, runId, ENTITY_TYPE_INVESTIGATION_RUN, patch);
    await notify(BUS_TOPICS[ENTITY_TYPE_INVESTIGATION_RUN].EDIT_TOPIC, element, INVESTIGATION_MANAGER_USER);
    previous = run;
    updated = element as unknown as BasicStoreEntityInvestigationRun;
  } finally {
    await lock.unlock();
  }
  // Outside the lock: delivering to the live triggers reads every listening user.
  await notifyInvestigationRunStatus(outOfDraft(context), previous, updated, serveInvestigationRun);
  return updated;
};

// endregion

// region creation

export interface InvestigationRunAddOptions {
  trigger?: InvestigationRunTrigger;
  // Identity the run acts as when it is not the caller (playbooks, hooks).
  runAsUserId?: string | null;
  // The case an indicator or an observable is investigated in; without one,
  // a new Case-Incident is created in the run's Draft.
  caseId?: string | null;
}

export const findActiveInvestigationRunForSubject = async (context: AuthContext, subjectId: string) => {
  const [run] = await topEntitiesList<BasicStoreEntityInvestigationRun>(outOfDraft(context), INVESTIGATION_MANAGER_USER, [ENTITY_TYPE_INVESTIGATION_RUN], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['subject_id'], values: [subjectId] },
        { key: ['run_status'], values: ACTIVE_RUN_STATUSES },
      ],
      filterGroups: [],
    },
    first: 1,
  });
  return run ?? null;
};

const resolveRunAsUser = async (context: AuthContext, user: AuthUser, runAsUserId?: string | null): Promise<AuthUser> => {
  if (!runAsUserId || runAsUserId === user.id) {
    return user;
  }
  const runAsUser = await resolveRunIdentity(context, runAsUserId);
  if (!runAsUser) {
    throw FunctionalError('The run-as user of the investigation cannot be found or can no longer use the platform', { runAsUserId });
  }
  return runAsUser;
};

export const addInvestigationRun = async (
  context: AuthContext,
  user: AuthUser,
  subjectId: string,
  policyId?: string | null,
  opts: InvestigationRunAddOptions = {},
): Promise<BasicStoreEntityInvestigationRun> => {
  await checkEnterpriseEdition(context);
  const liveContext = outOfDraft(context);
  const trigger = opts.trigger ?? InvestigationRunTrigger.Manual;
  // The policy identity is for automatic launches only: a launch through the API
  // acts as its caller, never reading through another account.
  const runUser = await resolveRunAsUser(liveContext, user, opts.runAsUserId);
  // The run sees what its identity sees: the caller must be able to see the subject too.
  const subject = await storeLoadByIdWithRefs<StoreEntity>(liveContext, runUser, subjectId);
  const callerSees = subject && (runUser.id === user.id || await internalLoadById(liveContext, user, subject.internal_id));
  if (!subject || !callerSees) {
    throw FunctionalError('The entity to investigate cannot be found', { subjectId });
  }
  if (!isInvestigableEntityType(subject.entity_type)) {
    throw FunctionalError('Case Autopilot investigates incidents, cases, indicators and observables only', { entityType: subject.entity_type });
  }
  if (!isUserHasCapability(runUser, KNOWLEDGE_KNUPDATE)) {
    throw ForbiddenAccess('The identity of the investigation must be allowed to update knowledge');
  }
  const policy = policyId ? await loadInvestigationPolicy(liveContext, policyId) : await getDefaultInvestigationPolicy(liveContext);
  if (!policy) {
    throw FunctionalError('Investigation policy not found', { policyId });
  }
  // Playbooks and requests for information launch here without the capability
  // checks of the API: the identity of the run must run what its policy allows.
  if (policy.allowed_actions.includes(InvestigationAutonomousAction.Enrichment) && !isUserHasCapability(runUser, KNOWLEDGE_KNENRICHMENT)) {
    throw ForbiddenAccess('The identity of the investigation must be allowed to enrich knowledge, as its policy runs enrichments');
  }
  const isCase = INVESTIGATION_CASE_SUBJECT_TYPES.includes(subject.entity_type);
  const subjectName = extractEntityRepresentativeName(subject) || subject.internal_id;
  // Indicators and observables are investigated inside a case, so the results
  // always live in an Autopilot tab.
  let targetCase: BasicStoreEntity | null = null;
  if (!isCase && opts.caseId) {
    targetCase = await internalLoadById<BasicStoreEntity>(liveContext, runUser, opts.caseId, { type: ENTITY_TYPE_CONTAINER_CASE });
    const callerSeesCase = targetCase && (runUser.id === user.id || await internalLoadById(liveContext, user, targetCase.internal_id));
    if (!targetCase || !callerSeesCase) {
      throw FunctionalError('The case of the investigation cannot be found', { caseId: opts.caseId });
    }
  }
  // A run and its outputs carry markings and organization sharing but no member
  // restriction: an entity restricted to authorized members is not investigated.
  const memberRestricted = [subject, targetCase].find((element) => isMemberRestricted(element));
  if (memberRestricted) {
    throw FunctionalError('Case Autopilot does not investigate an entity restricted to authorized members', { id: memberRestricted.internal_id });
  }
  const needsCase = !INVESTIGATION_TAB_SUBJECT_TYPES.includes(subject.entity_type);
  const createCase = needsCase && !targetCase;
  if (createCase && !policy.allowed_actions.includes(InvestigationAutonomousAction.CreateCase)) {
    throw FunctionalError('The investigation policy does not allow creating a case: pick the case of the investigation', { policyId: policy.internal_id });
  }
  let caseIds: string[] = [];
  if (isCase) {
    caseIds = [subject.internal_id, subject.standard_id];
  } else if (targetCase) {
    caseIds = [targetCase.internal_id, targetCase.standard_id];
  }
  const runInput = {
    name: `Case Autopilot - ${subjectName}`.slice(0, 250),
    subject_id: subject.internal_id,
    subject_type: subject.entity_type,
    case_id: (isCase ? subject.internal_id : targetCase?.internal_id) ?? null,
    case_ids: caseIds,
    create_case: createCase,
    policy_id: policy.internal_id,
    agent_slug: policy.agent_slug || INVESTIGATION_DEFAULT_AGENT_SLUG,
    pack_id: policy.pack_id || null,
    xtm_investigation_ids: [],
    xtm_revision: -1,
    budget_cancelled: false,
    run_trigger: trigger,
    run_status: InvestigationRunStatus.Planned,
    run_phase: InvestigationRunPhase.Initializing,
    active_ms: 0,
    engine_failures: 0,
    run_as_id: runUser.id,
    pending_work_ids: [],
    steps: [],
    evidence: [],
    hypotheses: [],
    timeline: [],
    recommendations: [],
    analyst_feedback: [],
    approvals: [],
    enrichment_requests: [],
    enrichment_waves: [],
    report_sources: [],
    outputs: EMPTY_OUTPUTS,
    budget: buildBudget(policy),
    // The engine context reads the case too, so the run starts with the
    // restrictions of both, as restrictive as every later revision.
    objectMarking: Array.from(new Set([...markingIdsOf(subject), ...(targetCase ? markingIdsOf(targetCase) : [])])),
    objectOrganization: intersectOrganizationIds(organizationIdsOf(subject), targetCase ? [targetCase] : []),
  };
  // Dedupe on the subject: one active investigation at a time, checked and
  // created under a per-subject lock so concurrent launches never race. The
  // policy lock keeps the policy from being deleted under the new run.
  const subjectLock = await lockResources([subjectLockKey(subject.internal_id), policyUsageLockKey(policy.internal_id)]);
  let created: BasicStoreEntityInvestigationRun;
  try {
    if (!(await loadInvestigationPolicy(liveContext, policy.internal_id))) {
      throw FunctionalError('Investigation policy not found', { policyId: policy.internal_id });
    }
    const active = await findActiveInvestigationRunForSubject(liveContext, subject.internal_id);
    if (active) {
      // The active run is returned only as the caller may read it.
      const visible = await findInvestigationRunById(liveContext, user, active.internal_id);
      if (!visible) {
        throw FunctionalError('An investigation of this entity is already running', { subjectId: subject.internal_id });
      }
      return visible;
    }
    created = await createEntity(liveContext, INVESTIGATION_MANAGER_USER, runInput, ENTITY_TYPE_INVESTIGATION_RUN) as unknown as BasicStoreEntityInvestigationRun;
  } finally {
    await subjectLock.unlock();
  }
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `launches Case Autopilot on \`${subjectName}\``,
    context_data: { id: subject.internal_id, entity_type: subject.entity_type, input: { run_id: created.internal_id, policy_id: policy.internal_id, trigger } },
  });
  addInvestigationRunCount(trigger);
  return notify(BUS_TOPICS[ENTITY_TYPE_INVESTIGATION_RUN].ADDED_TOPIC, created, user);
};

// endregion

// region analyst actions

/**
 * Stop the engine run of a cancelled run, as the identity of the run. Until
 * XTM One confirms it, the cancellation stays pending and the manager asks
 * again, a bounded number of times.
 */
export const stopCancelledEngineRun = async (context: AuthContext, runId: string, fallbackUser: AuthUser | null = null) => {
  const run = await loadInvestigationRun(outOfDraft(context), runId);
  if (!run || run.xtm_status !== ENGINE_CANCEL_PENDING || !run.xtm_investigation_id) return null;
  const runUser = (await resolveUserByIdFromCache(context, run.run_as_id)) ?? fallbackUser;
  const result = runUser ? await cancelInvestigation({ id: runUser.id, user_email: runUser.user_email }, run.xtm_investigation_id) : null;
  await updateInvestigationRun(context, runId, (current) => {
    if (current.xtm_status !== ENGINE_CANCEL_PENDING) return null;
    if (result?.ok) return { xtm_status: 'cancelled', engine_failures: 0 };
    const attempts = (current.engine_failures ?? 0) + 1;
    logApp.warn('[CASE AUTOPILOT] Engine run not cancelled yet', { runId, attempts, failure: result?.failure ?? 'no identity' });
    return { engine_failures: attempts, ...(attempts >= INVESTIGATION_LIMITS.engineFailures ? { xtm_status: ENGINE_CANCEL_FAILED } : {}) };
  });
  return result;
};

// Only the manager: an empty list of members would leave the artifact open to everyone.
const STOPPED_RUN_ARTIFACT_MEMBERS = [{ id: INVESTIGATION_MANAGER_USER.id, access_right: MEMBER_ACCESS_RIGHT_ADMIN }];

const restrictStoppedRunArtifact = async (context: AuthContext, artifact: { draftId: string } | { workspaceId: string }) => {
  const options = { skipAdminValidation: true };
  if ('draftId' in artifact) {
    await draftWorkspaceEditAuthorizedMembers(context, INVESTIGATION_MANAGER_USER, artifact.draftId, STOPPED_RUN_ARTIFACT_MEMBERS, options);
  } else {
    await workspaceEditAuthorizedMembers(context, INVESTIGATION_MANAGER_USER, artifact.workspaceId, STOPPED_RUN_ARTIFACT_MEMBERS, options);
  }
};

/**
 * Delete the draft and the investigation graph of a run stopped at an access
 * boundary, with what it wrote and read there. Each is first restricted to the
 * manager, so that a reader who kept its id reads nothing even while its
 * deletion fails; nothing is deleted before that restriction succeeded, as a
 * deletion that fails halfway would leave the rest under its old members. What
 * could not be restricted or deleted keeps its reference on the run, so that
 * the manager, or a deletion of the run, tries again.
 */
export const deleteStoppedRunArtifacts = async (context: AuthContext, runId: string, artifacts: { draftId: string | null; workspaceId: string | null }) => {
  const deleted = { draft: false, workspace: false };
  const { draftId, workspaceId } = artifacts;
  if (draftId) {
    try {
      if (await findDraftById(context, INVESTIGATION_MANAGER_USER, draftId)) {
        await restrictStoppedRunArtifact(context, { draftId });
        await deleteDraftWorkspace(context, INVESTIGATION_MANAGER_USER, draftId);
      }
      deleted.draft = true;
    } catch (cause) {
      logApp.error('[CASE AUTOPILOT] Draft of a stopped investigation not deleted, retried on the next tick', { runId, draftId, cause });
    }
  }
  if (workspaceId) {
    try {
      if (await findWorkspaceById(context, INVESTIGATION_MANAGER_USER, workspaceId)) {
        await restrictStoppedRunArtifact(context, { workspaceId });
        await workspaceDelete(context, INVESTIGATION_MANAGER_USER, workspaceId);
      }
      deleted.workspace = true;
    } catch (cause) {
      logApp.error('[CASE AUTOPILOT] Investigation graph of a stopped investigation not deleted, retried on the next tick', { runId, workspaceId, cause });
    }
  }
  if (!deleted.draft && !deleted.workspace) return;
  await updateInvestigationRun(context, runId, (current) => {
    const patch: Record<string, null> = {};
    if (deleted.draft && current.draft_id === draftId) patch.draft_id = null;
    if (deleted.workspace && current.workspace_id === workspaceId) patch.workspace_id = null;
    return Object.keys(patch).length > 0 ? patch : null;
  });
};

// From the moment a run stops at an access boundary until its draft and investigation graph are deleted, both are
// withheld from every reader but the manager and the users who bypass access restrictions, whether or not their
// restriction succeeded yet: the stopped run, stored first, is what says so.
const withheldStoppedRunArtifacts = (field: 'draft_id' | 'workspace_id'): WithheldElementsProvider => async (context, user) => {
  if (user.id === INVESTIGATION_MANAGER_USER.id || isBypassUser(user) || !(await isEnterpriseEdition(context))) {
    return [];
  }
  const runs = await topEntitiesList<BasicStoreEntityInvestigationRun>(outOfDraft(context), INVESTIGATION_MANAGER_USER, [ENTITY_TYPE_INVESTIGATION_RUN], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['run_status'], values: [InvestigationRunStatus.Failed] },
        { key: ['end_reason_code'], values: CARRY_BOUNDARY_CODES },
        { key: [field], values: [], operator: FilterOperator.NotNil },
      ],
      filterGroups: [],
    },
    noFiltersChecking: true,
    first: 500,
  });
  return runs.map((run) => run[field]).filter((id): id is string => !!id);
};
registerWithheldElements(ENTITY_TYPE_DRAFT_WORKSPACE, withheldStoppedRunArtifacts('draft_id'));
registerWithheldElements(ENTITY_TYPE_WORKSPACE, withheldStoppedRunArtifacts('workspace_id'));

export const cancelInvestigationRun = async (context: AuthContext, user: AuthUser, id: string) => {
  const run = await findAccessibleRun(context, user, id);
  // Cancelling rejects the gates of the run and stops its engine run: reading it is not enough.
  if (!isUserHasCapability(user, KNOWLEDGE_KNUPDATE)) {
    throw ForbiddenAccess();
  }
  if (TERMINAL_RUN_STATUSES.includes(run.run_status)) {
    return run;
  }
  // Under the actions lock, then the run lock: an approval being applied (a task,
  // a draft validation) finishes before its gate can be rejected, and an engine
  // run recorded just before the cancellation is stopped too.
  const cancellation: { done: boolean; validating: boolean; engineId: string | null } = { done: false, validating: false, engineId: null };
  const updated = await withRunActions(context, id, () => updateInvestigationRun(context, id, (current) => {
    if (!ACTIVE_RUN_STATUSES.includes(current.run_status)) return null;
    // The approved draft is already with the worker that writes it into the knowledge, which
    // cannot be recalled: the run keeps tracking that work until it ends.
    if (current.run_phase === InvestigationRunPhase.Validating) {
      cancellation.validating = true;
      return null;
    }
    cancellation.done = true;
    cancellation.engineId = current.run_phase === InvestigationRunPhase.Investigating ? current.xtm_investigation_id ?? null : null;
    const now = new Date();
    return {
      ...statusTransition(current, InvestigationRunStatus.Cancelled, InvestigationRunPhase.Done, now, `Cancelled by ${user.name}`),
      ...(cancellation.engineId ? { xtm_status: ENGINE_CANCEL_PENDING, engine_failures: 0 } : {}),
      pending_work_ids: [],
      approvals: current.approvals.map((approval) => (approval.status === InvestigationApprovalStatus.Pending
        ? { ...approval, status: InvestigationApprovalStatus.Rejected, decided_at: now.toISOString(), decided_by: user.id, rejection_reason: 'Run cancelled' }
        : approval)),
      // Jobs not started yet never start: the dispatch checks them again just before.
      enrichment_requests: current.enrichment_requests.map((request) => (request.status === InvestigationEnrichmentRequestStatus.Queued
        || request.status === InvestigationEnrichmentRequestStatus.AwaitingApproval
        ? { ...request, status: InvestigationEnrichmentRequestStatus.Skipped, error: 'Run cancelled', completed_at: now.toISOString() }
        : request)),
    };
  }));
  if (cancellation.validating) {
    throw FunctionalError(VALIDATION_NOT_CANCELLABLE, { id });
  }
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'extended',
    message: `cancels Case Autopilot run \`${run.name}\``,
    context_data: { id: run.subject_id, entity_type: run.subject_type, input: { run_id: id } },
  });
  if (cancellation.done) {
    addInvestigationRunOutcomeCount(InvestigationRunStatus.Cancelled);
    if (cancellation.engineId) {
      await stopCancelledEngineRun(context, id, user);
    }
  }
  return updated;
};

// Answers after which XTM One holds no engine run this platform can still stop:
// no longer connected, without the investigation routes or the run, or no
// longer running investigations.
const ENGINE_GONE_FAILURES: string[] = [ENGINE_NOT_CONFIGURED, ENGINE_UNAVAILABLE, ENGINE_DISABLED];

/**
 * A stopped run is the record its cleanup is retried from: a deletion
 * completes that cleanup first (the stop of its engine run, asked again when
 * the manager gave up on it, and the deletion of the draft and investigation
 * graph of a run stopped at an access boundary) and keeps the run while it
 * cannot.
 */
const completeStoppedRunCleanup = async (context: AuthContext, user: AuthUser, id: string) => {
  const liveContext = outOfDraft(context);
  const run = await loadInvestigationRun(liveContext, id);
  if (!run) return;
  if (run.xtm_status === ENGINE_CANCEL_FAILED) {
    await updateInvestigationRun(liveContext, id, (current) => (current.xtm_status === ENGINE_CANCEL_FAILED ? { xtm_status: ENGINE_CANCEL_PENDING, engine_failures: 0 } : null));
  }
  if (run.xtm_status === ENGINE_CANCEL_PENDING || run.xtm_status === ENGINE_CANCEL_FAILED) {
    const result = await stopCancelledEngineRun(liveContext, id, user);
    if (result && !result.ok && !ENGINE_GONE_FAILURES.includes(result.failure)) {
      throw FunctionalError(ENGINE_STOP_UNCONFIRMED, { id });
    }
  }
  if (run.run_status === InvestigationRunStatus.Failed && CARRY_BOUNDARY_CODES.includes(run.end_reason_code ?? '') && (run.draft_id || run.workspace_id)) {
    await deleteStoppedRunArtifacts(liveContext, id, { draftId: run.draft_id ?? null, workspaceId: run.workspace_id ?? null });
    const cleaned = await loadInvestigationRun(liveContext, id);
    if (cleaned && (cleaned.draft_id || cleaned.workspace_id)) {
      throw FunctionalError(ARTIFACTS_NOT_DELETED, { id });
    }
  }
};

export const deleteInvestigationRun = async (context: AuthContext, user: AuthUser, id: string) => {
  const run = await findAccessibleRun(context, user, id);
  if (ACTIVE_RUN_STATUSES.includes(run.run_status)) {
    throw FunctionalError('Cancel the investigation before deleting it', { id });
  }
  await completeStoppedRunCleanup(context, user, id);
  await deleteInternalObject(outOfDraft(context), user, id, ENTITY_TYPE_INVESTIGATION_RUN);
  await notify(BUS_TOPICS[ENTITY_TYPE_INVESTIGATION_RUN].DELETE_TOPIC, run, user);
  return id;
};

const feedbackItemLabel = (run: BasicStoreEntityInvestigationRun, itemType: InvestigationFeedbackItemType, itemRef: string) => {
  if (itemType === InvestigationFeedbackItemType.Hypothesis) {
    const hypothesis = run.hypotheses.find((h) => h.candidate_id === itemRef);
    return hypothesis ? { label: hypothesis.candidate_name ?? itemRef, hypothesis } : null;
  }
  const recommendation = run.recommendations.find((r) => r.id === itemRef);
  return recommendation ? { label: recommendation.text, recommendation } : null;
};

const sendFeedbackToXtmOne = (user: AuthUser, run: BasicStoreEntityInvestigationRun, entries: InvestigationFeedback[]) => {
  const decisions = entries.map((entry) => {
    const item = feedbackItemLabel(run, entry.item_type, entry.item_ref);
    if (entry.item_type === InvestigationFeedbackItemType.Hypothesis && item && 'hypothesis' in item && item.hypothesis) {
      const { hypothesis } = item;
      return {
        item_type: entry.item_type,
        item_ref: entry.item_ref,
        label: item.label,
        candidate_type: hypothesis.candidate_type,
        decision: entry.decision,
        comment: entry.comment ?? null,
        probability: hypothesis.probability,
        confidence_label: hypothesis.confidence_label,
        evidence_categories: Array.from(new Set(hypothesis.evidence.map((cell) => cell.category))),
      };
    }
    const recommendation = item && 'recommendation' in item ? item.recommendation : null;
    return {
      item_type: entry.item_type,
      item_ref: entry.item_ref,
      label: item?.label ?? entry.item_ref,
      action_kind: recommendation?.action_kind ?? null,
      decision: entry.decision,
      comment: entry.comment ?? null,
    };
  });
  pushInvestigationFeedback(
    { id: user.id, user_email: user.user_email },
    {
      agent_slug: run.agent_slug || INVESTIGATION_DEFAULT_AGENT_SLUG,
      run_id: run.internal_id,
      subject: { id: run.subject_id, entity_type: run.subject_type, name: run.name },
      decisions,
    },
  ).catch((cause) => logApp.warn('[CASE AUTOPILOT] Feedback push failed', { cause }));
};

const recordFeedback = async (
  context: AuthContext,
  user: AuthUser,
  run: BasicStoreEntityInvestigationRun,
  entry: InvestigationFeedback,
  extraPatch: (current: BasicStoreEntityInvestigationRun) => Record<string, unknown> = () => ({}),
) => {
  const holder: { previous: InvestigationFeedback | null } = { previous: null };
  const updated = await updateInvestigationRun(context, run.internal_id, (current) => {
    const result = upsertFeedback(current.analyst_feedback, entry);
    holder.previous = result.previous;
    return { analyst_feedback: result.feedback, ...extraPatch(current) };
  });
  if (run.policy_id) {
    // A repeated identical decision yields a null delta, which is skipped.
    await applyInvestigationPolicyAcceptanceDelta(context, run.policy_id, feedbackCounterDelta(holder.previous, entry));
  }
  addInvestigationFeedbackCount(entry.item_type, entry.decision);
  sendFeedbackToXtmOne(user, updated, [entry]);
  return updated;
};

export const addInvestigationRunFeedback = async (context: AuthContext, user: AuthUser, id: string, input: InvestigationRunFeedbackInput) => {
  const run = await findAccessibleRun(context, user, id, { onFindings: true });
  if (!feedbackItemLabel(run, input.item_type, input.item_ref)) {
    throw FunctionalError('Unknown hypothesis or recommendation', { id, itemRef: input.item_ref });
  }
  const entry: InvestigationFeedback = {
    item_type: input.item_type,
    item_ref: input.item_ref,
    decision: input.decision,
    comment: input.comment?.trim().slice(0, INVESTIGATION_LIMITS.textLength) || null,
    user_id: user.id,
    ts: new Date().toISOString(),
  };
  const updated = await recordFeedback(context, user, run, entry);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'extended',
    message: `${input.decision === InvestigationFeedbackDecision.Accepted ? 'accepts' : 'rejects'} a Case Autopilot ${input.item_type} of \`${run.name}\``,
    context_data: { id: run.subject_id, entity_type: run.subject_type, input },
  });
  return updated;
};

// The live case of a run: the investigated case, the case found at start, or
// the case the run created once its draft was validated.
export const resolveLiveCase = async (context: AuthContext, user: AuthUser, run: BasicStoreEntityInvestigationRun) => {
  const caseIds = run.case_ids ?? [];
  if (caseIds.length === 0) return null;
  const cases = await elFindByIds<BasicStoreEntity>(outOfDraft(context), user, caseIds, { type: ENTITY_TYPE_CONTAINER_CASE }) as BasicStoreEntity[];
  return cases[0] ?? null;
};

/**
 * Analyst actions with side effects outside the run (tasks, relations, draft
 * validation) are checked and executed under this lock against a fresh run, so
 * a repeated click or a concurrent approval never applies an action twice.
 * Taken before the run lock, never while holding it.
 */
export const withRunActions = async <T>(
  context: AuthContext,
  runId: string,
  execute: (run: BasicStoreEntityInvestigationRun) => Promise<T>,
): Promise<T> => {
  const lock = await lockResources([runActionsLockKey(runId)]);
  try {
    const run = await loadInvestigationRun(outOfDraft(context), runId);
    if (!run) {
      throw FunctionalError('Investigation run not found', { id: runId });
    }
    return await execute(run);
  } finally {
    await lock.unlock();
  }
};

const createRecommendationTask = async (
  context: AuthContext,
  user: AuthUser,
  run: BasicStoreEntityInvestigationRun,
  recommendation: InvestigationRecommendation,
  liveCase: BasicStoreEntity | null,
) => {
  const anchor = liveCase ?? await internalLoadById<BasicStoreEntity>(outOfDraft(context), user, run.subject_id);
  if (!anchor) {
    throw FunctionalError('The investigated entity is no longer accessible', { id: run.internal_id });
  }
  const description = [
    recommendation.rationale ?? '',
    '',
    `Recommended by Case Autopilot (${recommendation.priority}, ${recommendation.action_kind.replace(/_/g, ' ')}) in the investigation "${run.name}".`,
  ].join('\n').trim();
  // The recommendation may quote what the run cites: the task carries the run markings and sharing too.
  const organizations = organizationIdsOf(anchor).filter((id) => organizationIdsOf(run).includes(id));
  const settings = await getEntityFromCache<BasicStoreSettings>(context, INVESTIGATION_MANAGER_USER, ENTITY_TYPE_SETTINGS);
  if (isCreationSharingWidened(user, settings, context.user_inside_platform_organization ?? false, organizations)) {
    throw FunctionalError('The task would be shared with your organizations beyond the sharing of the investigation: a user who can restrict the sharing of what they create must apply it', { id: run.internal_id });
  }
  const task = await taskAdd(outOfDraft(context), user, {
    name: recommendation.text.slice(0, 250),
    description,
    objects: [anchor.internal_id],
    objectMarking: Array.from(new Set([...markingIdsOf(anchor), ...markingIdsOf(run)])),
    objectOrganization: organizations,
  });
  return task.internal_id ?? task.id;
};

export const applyInvestigationRecommendation = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
  recommendationId: string,
  mode: InvestigationRecommendationApplyMode,
) => {
  const accessible = await findAccessibleRun(context, user, id, { onFindings: true });
  const { run, updated } = await withRunActions(context, accessible.internal_id, async (fresh) => {
    await assertFindingsServed(context, user, fresh);
    const recommendation = fresh.recommendations.find((r) => r.id === recommendationId);
    if (!recommendation) {
      throw FunctionalError('Unknown recommendation', { id, recommendationId });
    }
    if (recommendation.status !== InvestigationRecommendationStatus.Proposed) {
      throw FunctionalError('This recommendation was already handled or is waiting for an approval', { id, recommendationId, status: recommendation.status });
    }
    const liveCase = await resolveLiveCase(context, user, fresh);
    let statusPatch: Partial<InvestigationRecommendation>;
    if (mode === InvestigationRecommendationApplyMode.CourseOfAction) {
      if (!recommendation.course_of_action_id) {
        throw FunctionalError('This recommendation does not reference a course of action', { id, recommendationId });
      }
      if (!liveCase) {
        throw FunctionalError('Approve the investigation draft first: the course of action is applied to the case', { id });
      }
      await stixDomainObjectAddRelation(outOfDraft(context), user, liveCase.internal_id, { toId: recommendation.course_of_action_id, relationship_type: RELATION_OBJECT });
      statusPatch = { status: InvestigationRecommendationStatus.Applied };
    } else {
      const taskId = await createRecommendationTask(context, user, fresh, recommendation, liveCase);
      statusPatch = { status: InvestigationRecommendationStatus.TaskCreated, task_id: taskId };
    }
    // Applying a recommendation is the strongest acceptance signal: recorded as such.
    const entry: InvestigationFeedback = {
      item_type: InvestigationFeedbackItemType.Recommendation,
      item_ref: recommendationId,
      decision: InvestigationFeedbackDecision.Accepted,
      comment: null,
      user_id: user.id,
      ts: new Date().toISOString(),
    };
    const recorded = await recordFeedback(context, user, fresh, entry, (current) => ({
      recommendations: current.recommendations.map((r) => (r.id === recommendationId ? { ...r, ...statusPatch } : r)),
    }));
    return { run: fresh, updated: recorded };
  });
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'extended',
    message: `applies a Case Autopilot recommendation of \`${run.name}\``,
    context_data: { id: run.subject_id, entity_type: run.subject_type, input: { recommendationId, mode } },
  });
  return updated;
};

// endregion

// region approvals (surfaced through the chatbot approval route)

export interface InvestigationApprovalDecisionInput {
  tool_call_id: string;
  decision: 'approve' | 'approve_always' | 'reject';
  rejection_reason?: string | null;
}

export interface InvestigationApprovalOutcome {
  decided: number;
  run: BasicStoreEntityInvestigationRun;
}

const requiredCapabilityFor = (approval: InvestigationApproval) => {
  if (approval.kind === InvestigationApprovalKind.Enrichment) return KNOWLEDGE_KNENRICHMENT;
  if (approval.kind === InvestigationApprovalKind.DraftValidation) return KNOWLEDGE_KNUPDATE_KNDELETE;
  return KNOWLEDGE_KNUPDATE;
};

const executeApprovedRecommendation = async (
  context: AuthContext,
  user: AuthUser,
  run: BasicStoreEntityInvestigationRun,
  recommendation: InvestigationRecommendation,
): Promise<Partial<InvestigationRecommendation>> => {
  const liveCase = await resolveLiveCase(context, user, run);
  if (recommendation.action_kind === InvestigationRecommendationActionKind.SeverityChange && recommendation.severity && liveCase) {
    await stixDomainObjectEditField(outOfDraft(context), user, liveCase.internal_id, [{ key: 'severity', value: [recommendation.severity] }]);
    return { status: InvestigationRecommendationStatus.Applied };
  }
  // Autopilot never shares, notifies or closes by itself: the approved action
  // becomes a task the analyst carries out with the full context.
  const taskId = await createRecommendationTask(context, user, run, recommendation, liveCase);
  return { status: InvestigationRecommendationStatus.TaskCreated, task_id: taskId };
};

const decideApprovalsOf = async (
  context: AuthContext,
  user: AuthUser,
  runId: string,
  run: BasicStoreEntityInvestigationRun,
  decisions: InvestigationApprovalDecisionInput[],
): Promise<InvestigationApprovalOutcome> => {
  // A failed or cancelled investigation executes nothing more; a completed one keeps its recommendation gates open.
  if (run.run_status === InvestigationRunStatus.Failed || run.run_status === InvestigationRunStatus.Cancelled) {
    throw FunctionalError('This investigation has ended: its approvals can no longer be decided', { id: runId, run_status: run.run_status });
  }
  const now = new Date();
  const decided: Array<{ approval: InvestigationApproval; approved: boolean; reason: string | null }> = [];
  decisions.forEach((decision) => {
    const approval = run.approvals.find((a) => a.id === decision.tool_call_id && a.status === InvestigationApprovalStatus.Pending);
    // An approval repeated in the same request is decided once, by its first decision.
    if (!approval || decided.some((d) => d.approval.id === approval.id)) return;
    const approved = decision.decision === 'approve' || decision.decision === 'approve_always';
    decided.push({ approval, approved, reason: decision.rejection_reason?.slice(0, INVESTIGATION_LIMITS.textLength) ?? null });
    // "Approve always" extends the decision to the other pending requests of the same connector.
    if (decision.decision === 'approve_always' && approval.kind === InvestigationApprovalKind.Enrichment) {
      run.approvals
        .filter((other) => other.id !== approval.id && other.status === InvestigationApprovalStatus.Pending
          && other.kind === InvestigationApprovalKind.Enrichment && other.connector_id === approval.connector_id)
        .forEach((other) => {
          if (!decided.some((d) => d.approval.id === other.id)) decided.push({ approval: other, approved: true, reason: null });
        });
    }
  });
  if (decided.length === 0) {
    return { decided: 0, run };
  }
  const missing = decided.find(({ approval }) => !isUserHasCapability(user, requiredCapabilityFor(approval)));
  if (missing) {
    throw ForbiddenAccess('You are not allowed to decide this approval', { kind: missing.approval.kind });
  }
  // Side effects run with the approver's identity: an approval is their consent.
  // When one fails, the decisions already carried out are recorded before the
  // error is returned, so that a retry never carries them out twice.
  const recommendationPatches = new Map<string, Partial<InvestigationRecommendation>>();
  let validationWorkId: string | null = null;
  const applied: typeof decided = [];
  let failure: unknown = null;
  for (let index = 0; index < decided.length && !failure; index += 1) {
    const { approval, approved } = decided[index];
    try {
      if (approval.kind === InvestigationApprovalKind.Recommendation && approval.recommendation_id) {
        const recommendation = run.recommendations.find((r) => r.id === approval.recommendation_id);
        if (recommendation) {
          recommendationPatches.set(recommendation.id, approved
            ? await executeApprovedRecommendation(context, user, run, recommendation)
            : { status: InvestigationRecommendationStatus.Dismissed });
        }
      }
      if (approval.kind === InvestigationApprovalKind.DraftValidation && approved && run.draft_id) {
        const work = await validateDraftWorkspace(outOfDraft(context), user, run.draft_id);
        validationWorkId = work?.id ?? null;
      }
      applied.push(decided[index]);
    } catch (error) {
      failure = error;
    }
  }
  if (failure && applied.length === 0) throw failure;
  const decidedIds = new Map(applied.map((d) => [d.approval.id, d]));
  const updated = await updateInvestigationRun(context, runId, (current) => {
    const approvals = current.approvals.map((approval) => {
      const decision = decidedIds.get(approval.id);
      if (!decision || approval.status !== InvestigationApprovalStatus.Pending) return approval;
      return {
        ...approval,
        status: decision.approved ? InvestigationApprovalStatus.Approved : InvestigationApprovalStatus.Rejected,
        decided_at: now.toISOString(),
        decided_by: user.id,
        rejection_reason: decision.approved ? null : decision.reason,
      };
    });
    const enrichmentRequests = current.enrichment_requests.map((request) => {
      const approval = approvals.find((a) => a.kind === InvestigationApprovalKind.Enrichment && a.entity_id === request.entity_id
        && a.connector_id === request.connector_id && decidedIds.has(a.id));
      if (!approval || request.status !== InvestigationEnrichmentRequestStatus.AwaitingApproval) return request;
      const approved = approval.status === InvestigationApprovalStatus.Approved;
      return { ...request, status: approved ? InvestigationEnrichmentRequestStatus.Queued : InvestigationEnrichmentRequestStatus.Rejected };
    });
    const recommendations = current.recommendations.map((r) => (recommendationPatches.has(r.id) ? { ...r, ...recommendationPatches.get(r.id) } : r));
    const patch: Record<string, unknown> = { approvals, enrichment_requests: enrichmentRequests, recommendations };
    const draftDecision = applied.find(({ approval }) => approval.kind === InvestigationApprovalKind.DraftValidation);
    if (draftDecision && current.run_status === InvestigationRunStatus.AwaitingApproval) {
      if (draftDecision.approved) {
        Object.assign(patch, statusTransition(current, InvestigationRunStatus.Running, InvestigationRunPhase.Validating, now), {
          validation_work_id: validationWorkId,
          wave_started_at: now.toISOString(),
        });
      } else {
        Object.assign(patch, statusTransition(current, InvestigationRunStatus.Completed, InvestigationRunPhase.Done, now, 'The investigation draft was not approved, it stays open for review'));
      }
    } else if (current.run_status === InvestigationRunStatus.AwaitingApproval
      && current.run_phase !== InvestigationRunPhase.AwaitingValidation
      && approvals.every((approval) => approval.status !== InvestigationApprovalStatus.Pending)) {
      // Nothing is waiting any more: the manager resumes the run.
      Object.assign(patch, statusTransition(current, InvestigationRunStatus.Running, current.run_phase, now));
    }
    return patch;
  });
  if (updated.run_status === InvestigationRunStatus.Completed && run.run_status !== InvestigationRunStatus.Completed) {
    addInvestigationRunOutcomeCount(InvestigationRunStatus.Completed);
  }
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'extended',
    message: `decides ${applied.length} Case Autopilot approval(s) of \`${run.name}\``,
    context_data: {
      id: run.subject_id,
      entity_type: run.subject_type,
      input: { run_id: runId, decisions: applied.map(({ approval, approved }) => ({ id: approval.id, kind: approval.kind, approved })) },
    },
  });
  if (failure) throw failure;
  return { decided: applied.length, run: updated };
};

export const decideInvestigationApprovals = async (
  context: AuthContext,
  user: AuthUser,
  runId: string,
  decisions: InvestigationApprovalDecisionInput[],
): Promise<InvestigationApprovalOutcome> => {
  const accessible = await findAccessibleRun(context, user, runId, { onFindings: true });
  if (!isUserHasCapability(user, KNOWLEDGE_KNUPDATE)) {
    throw ForbiddenAccess();
  }
  // Pending approvals are read again under the lock: a concurrent decision on
  // the same approval finds it decided and executes nothing.
  return withRunActions(context, accessible.internal_id, async (run) => {
    await assertFindingsServed(context, user, run);
    return decideApprovalsOf(context, user, runId, run, decisions);
  });
};

// endregion

// region engine queries (the investigation engine calls them as the run identity)

const loadRunForEngine = async (context: AuthContext, user: AuthUser, id: string) => {
  const run = await findAccessibleRun(context, user, id, { onFindings: true });
  if (run.run_as_id !== user.id) {
    throw ForbiddenAccess('Only the identity of the investigation can act for its engine');
  }
  return run;
};

const runContextFor = (context: AuthContext, run: BasicStoreEntityInvestigationRun): AuthContext => ({
  ...context,
  draft_context: run.draft_id ?? '',
});

export const listPolicyEnrichmentConnectors = async (context: AuthContext, user: AuthUser, policy: BasicStoreEntityInvestigationPolicy) => {
  const connectors = await connectorsForEnrichment(outOfDraft(context), user, null, true) as Array<{ internal_id: string; name: string; connector_scope?: string[] }>;
  const allowList = policy.enrichment_connector_ids ?? [];
  return connectors.filter((connector) => allowList.length === 0 || allowList.includes(connector.internal_id));
};

/**
 * Enrichment jobs the engine's `opencti_enrichment` querier asks for. Each
 * call is one wave the engine then follows with
 * `investigationRunEnrichmentWave`. The policy allow-list, the budget and the
 * paid-connector approvals apply; a job already asked for by this run is
 * reused rather than run twice.
 */
/**
 * What an investigation may enrich: its subject, the objects of its case, the
 * OpenCTI objects it cites and what its earlier waves brought into its draft.
 * The engine never extends an enrichment to the rest of the graph.
 */
const enrichmentScopeOf = async (context: AuthContext, run: BasicStoreEntityInvestigationRun): Promise<Set<string>> => {
  const scope = new Set<string>([run.subject_id]);
  (run.evidence ?? []).forEach((item) => {
    if (item.opencti_id) scope.add(item.opencti_id);
    if (item.standard_id) scope.add(item.standard_id);
  });
  (run.enrichment_waves ?? []).forEach((wave) => (wave.delta ?? []).forEach((item) => {
    scope.add(item.id);
    if (item.standard_id) scope.add(item.standard_id);
  }));
  const caseIds = Array.from(new Set([run.subject_id, ...(run.case_id ? [run.case_id] : [])]));
  const refs = await topRelationsList<BasicStoreRelation>(runContextFor(context, run), INVESTIGATION_MANAGER_USER, RELATION_OBJECT, {
    fromId: caseIds,
    first: INVESTIGATION_LIMITS.contextEntities,
  }) as unknown as BasicStoreRelation[];
  refs.forEach((ref) => scope.add(ref.toId));
  return scope;
};

export const requestInvestigationEnrichment = async (context: AuthContext, user: AuthUser, id: string, input: InvestigationRunEnrichmentRequestInput) => {
  const run = await loadRunForEngine(context, user, id);
  const policy = run.policy_id ? await loadInvestigationPolicy(outOfDraft(context), run.policy_id) : null;
  if (!policy) {
    throw FunctionalError('The policy of the investigation cannot be found', { id });
  }
  const connectors = await listPolicyEnrichmentConnectors(context, user, policy);
  const connectorNames = new Map(connectors.map((connector) => [connector.internal_id, connector.name]));
  const allowedConnectorIds = new Set(connectors.map((connector) => connector.internal_id));
  const entityIds = Array.from(new Set(input.entity_ids)).slice(0, INVESTIGATION_LIMITS.enrichmentRequestsPerCall);
  const connectorIds = Array.from(new Set(input.connector_ids)).slice(0, INVESTIGATION_LIMITS.enrichmentRequestsPerCall);
  // Entities of the investigation's scope the identity of the run can see in
  // its draft, by internal or standard id. An entity restricted to authorized
  // members is never investigated, so never enriched either.
  const scope = await enrichmentScopeOf(context, run);
  const visible = await elFindByIds<BasicStoreEntity>(runContextFor(context, run), user, entityIds, { indices: READ_DATA_INDICES_WITHOUT_INTERNAL }) as BasicStoreEntity[];
  const resolvedIds = new Map<string, string>();
  visible
    .filter((element) => !isMemberRestricted(element))
    .filter((element) => scope.has(element.internal_id) || (!!element.standard_id && scope.has(element.standard_id)))
    .forEach((element) => {
      resolvedIds.set(element.internal_id, element.internal_id);
      if (element.standard_id) resolvedIds.set(element.standard_id, element.internal_id);
    });
  const accepted: Array<{ entity_id: string; connector_id: string; status: InvestigationEnrichmentRequestStatus }> = [];
  const rejected: Array<{ entity_id: string; connector_id: string; reason: string }> = [];
  const waveId = uuidv4();
  const now = new Date();
  await updateInvestigationRun(context, id, (current) => {
    const newRequests: InvestigationEnrichmentRequest[] = [];
    const newApprovals: InvestigationApproval[] = [];
    const waveRequestIds: string[] = [];
    const allowedEntityIds = new Set(resolvedIds.values());
    entityIds.forEach((rawEntityId) => {
      connectorIds.forEach((connectorId) => {
        const entityId = resolvedIds.get(rawEntityId) ?? rawEntityId;
        const verdict = evaluateEnrichmentRequest({
          run: { ...current, enrichment_requests: [...current.enrichment_requests, ...newRequests] },
          policy,
          allowedConnectorIds,
          allowedEntityIds,
          entityId,
          connectorId,
          alreadyAccepted: 0,
        });
        if (verdict === 'duplicate') {
          const existing = current.enrichment_requests.find((request) => request.entity_id === entityId && request.connector_id === connectorId
            && request.status !== InvestigationEnrichmentRequestStatus.Rejected && request.status !== InvestigationEnrichmentRequestStatus.Failed);
          if (existing) {
            waveRequestIds.push(existing.id);
            accepted.push({ entity_id: rawEntityId, connector_id: connectorId, status: existing.status });
            return;
          }
        }
        if (isEnrichmentRejection(verdict)) {
          rejected.push({ entity_id: rawEntityId, connector_id: connectorId, reason: verdict });
          return;
        }
        const request: InvestigationEnrichmentRequest = {
          id: uuidv4(),
          wave_id: waveId,
          entity_id: entityId,
          connector_id: connectorId,
          connector_name: connectorNames.get(connectorId) ?? null,
          reason: input.reason?.slice(0, INVESTIGATION_LIMITS.textLength) ?? null,
          status: verdict,
          requested_by: 'engine',
          work_id: null,
          error: null,
          created_at: now.toISOString(),
          dispatched_at: null,
          completed_at: null,
        };
        newRequests.push(request);
        waveRequestIds.push(request.id);
        if (verdict === InvestigationEnrichmentRequestStatus.AwaitingApproval) {
          newApprovals.push({
            id: uuidv4(),
            kind: InvestigationApprovalKind.Enrichment,
            status: InvestigationApprovalStatus.Pending,
            description: `Run ${request.connector_name ?? connectorId} on ${entityId}`,
            reason: request.reason,
            connector_id: connectorId,
            entity_id: entityId,
            recommendation_id: null,
            created_at: now.toISOString(),
          });
        }
        accepted.push({ entity_id: rawEntityId, connector_id: connectorId, status: verdict });
      });
    });
    const allRequests = [...current.enrichment_requests, ...newRequests];
    const wave: InvestigationEnrichmentWave = {
      id: waveId,
      status: computeWaveStatus(allRequests.filter((request) => waveRequestIds.includes(request.id))),
      requested_at: now.toISOString(),
      completed_at: null,
      request_ids: waveRequestIds,
      delta: [],
      delta_computed: waveRequestIds.length === 0,
    };
    return {
      enrichment_requests: allRequests,
      enrichment_waves: [...(current.enrichment_waves ?? []), wave].slice(-INVESTIGATION_LIMITS.enrichmentWaves),
      approvals: boundApprovals([...current.approvals, ...newApprovals]),
    };
  });
  return { wave_id: waveId, accepted, rejected };
};

/** One wave of enrichment jobs: their status and what they brought into the run's Draft. */
export const findInvestigationRunEnrichmentWave = async (context: AuthContext, user: AuthUser, id: string, waveId: string) => {
  const run = await findAccessibleRun(context, user, id);
  const wave = (run.enrichment_waves ?? []).find((item) => item.id === waveId);
  if (!wave) return null;
  // The jobs and the delta were recorded as the run identity: each reader gets
  // only the ones naming objects it may read (markings, organizations, members).
  const waveJobs = run.enrichment_requests.filter((request) => wave.request_ids.includes(request.id));
  const jobs = await filterReadableRunRecords(context, user, run, waveJobs);
  const collected = wave.delta ?? [];
  const readable = collected.length === 0 ? [] : await elFindByIds<BasicStoreEntity>(
    runContextFor(context, run),
    user,
    collected.map((item) => item.id),
    { indices: READ_DATA_INDICES_WITHOUT_INTERNAL, baseData: true },
  ) as BasicStoreEntity[];
  const readableIds = new Set(readable.map((element) => element.internal_id));
  return {
    id: wave.id,
    status: wave.delta_computed ? wave.status : computeWaveStatus(waveJobs),
    requested_at: wave.requested_at,
    completed_at: wave.completed_at ?? null,
    jobs: jobs.map((job) => ({
      connector_id: job.connector_id,
      connector_name: job.connector_name ?? job.connector_id,
      entity_id: job.entity_id,
      work_id: job.work_id ?? null,
      status: job.status,
      error: job.error ?? null,
    })),
    delta: collected.filter((item) => readableIds.has(item.id)),
  };
};

/**
 * The entities the enrichment jobs and the approvals of a run name, as the
 * reader sees them: in the run draft when the reader may open it, else live.
 * An entity the reader cannot see is left out, never named.
 */
// The entities of a run a reader may read, in its draft while the reader can
// open it, else in the live graph: by internal and standard id.
const readableRunEntityIds = async (context: AuthContext, user: AuthUser, run: BasicStoreEntityInvestigationRun, ids: string[]) => {
  const unique = Array.from(new Set(ids));
  if (unique.length === 0) return new Set<string>();
  const draft = run.draft_id ? await findDraftById(outOfDraft(context), user, run.draft_id) : null;
  const readContext = draft ? runContextFor(context, run) : outOfDraft(context);
  const elements = await elFindByIds<BasicStoreEntity>(readContext, user, unique, { indices: READ_DATA_INDICES_WITHOUT_INTERNAL, baseData: true }) as BasicStoreEntity[];
  return new Set(elements.flatMap((element) => [element.internal_id, element.standard_id]));
};

/**
 * Records of a run that name an entity (approvals, enrichment requests, wave
 * jobs) were written as the run identity, which may read more than a reader:
 * a reader gets only those whose entity it may read, or that name none.
 */
export const filterReadableRunRecords = async <T extends { entity_id?: string | null }>(
  context: AuthContext,
  user: AuthUser,
  run: BasicStoreEntityInvestigationRun,
  records: T[],
): Promise<T[]> => {
  const named = records.flatMap((record) => (record.entity_id ? [record.entity_id] : []));
  if (named.length === 0) return records;
  const readable = await readableRunEntityIds(context, user, run, named);
  return records.filter((record) => !record.entity_id || readable.has(record.entity_id));
};

export const findInvestigationRunEnrichmentEntities = async (context: AuthContext, user: AuthUser, run: BasicStoreEntityInvestigationRun) => {
  const ids = Array.from(new Set([
    ...(run.enrichment_requests ?? []).map((request) => request.entity_id),
    ...(run.approvals ?? []).flatMap((approval) => (approval.entity_id ? [approval.entity_id] : [])),
  ])).slice(0, INVESTIGATION_LIMITS.enrichmentEntities);
  if (ids.length === 0) return [];
  const draft = run.draft_id ? await findDraftById(outOfDraft(context), user, run.draft_id) : null;
  const readContext = draft ? runContextFor(context, run) : outOfDraft(context);
  const elements = await elFindByIds<BasicStoreEntity>(readContext, user, ids, { indices: READ_DATA_INDICES_WITHOUT_INTERNAL }) as BasicStoreEntity[];
  return elements.map((element) => ({
    id: element.internal_id,
    entity_type: element.entity_type,
    name: extractEntityRepresentativeName(element),
  }));
};

// endregion

// region continuation and engine catalog

// An analyst may continue an investigation whose engine run ended, while its
// draft is still open and time and iterations are left: typically after
// approving an enrichment it held. Neither budget is replenished.
export const canContinueInvestigationRun = (run: BasicStoreEntityInvestigationRun) => {
  if (!run.xtm_investigation_id || !run.draft_id) return false;
  if (run.end_reason_code && WITHHELD_CODES.includes(run.end_reason_code)) return false;
  const awaitingDraft = run.run_status === InvestigationRunStatus.AwaitingApproval && run.run_phase === InvestigationRunPhase.AwaitingValidation;
  return awaitingDraft && remainingMinutes(run, new Date()) > 0 && remainingIterations(run) > 0;
};

export const continueInvestigationRun = async (context: AuthContext, user: AuthUser, id: string) => {
  const run = await findAccessibleRun(context, user, id, { onFindings: true });
  // The run continues under its own identity: the caller must be allowed to
  // run the enrichments of its policy as well.
  const policy = run.policy_id ? await loadInvestigationPolicy(outOfDraft(context), run.policy_id) : null;
  if (policy?.allowed_actions.includes(InvestigationAutonomousAction.Enrichment) && !isUserHasCapability(user, KNOWLEDGE_KNENRICHMENT)) {
    throw ForbiddenAccess('Continuing this investigation runs the enrichments of its policy: you must be allowed to enrich knowledge');
  }
  if (!canContinueInvestigationRun(run)) {
    throw FunctionalError('This investigation cannot be continued: its draft is no longer waiting, or its time or iteration budget is spent', { id });
  }
  const now = new Date();
  // Under the actions lock: a draft approval being decided finishes first, and
  // then the run is no longer waiting for its draft, so it cannot be continued.
  const updated = await withRunActions(context, run.internal_id, () => updateInvestigationRun(context, id, (current) => {
    if (!canContinueInvestigationRun(current)) return null;
    return {
      ...statusTransition(current, InvestigationRunStatus.Running, InvestigationRunPhase.Starting, now, null),
      continues_investigation_id: current.xtm_investigation_id,
      approvals: current.approvals.map((approval) => (approval.status === InvestigationApprovalStatus.Pending && approval.kind === InvestigationApprovalKind.DraftValidation
        ? { ...approval, status: InvestigationApprovalStatus.Rejected, decided_at: now.toISOString(), decided_by: user.id, rejection_reason: 'Investigation continued' }
        : approval)),
    };
  }));
  if (updated.run_status !== InvestigationRunStatus.Running || updated.run_phase !== InvestigationRunPhase.Starting) {
    throw FunctionalError('This investigation cannot be continued: its draft is no longer waiting, or its time or iteration budget is spent', { id });
  }
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'extended',
    message: `continues Case Autopilot investigation \`${run.name}\``,
    context_data: { id: run.subject_id, entity_type: run.subject_type, input: { run_id: id, continues_investigation_id: run.xtm_investigation_id } },
  });
  return updated;
};

/** Whether the connected XTM One runs investigations, and the packs the caller may name in a policy. */
export const findInvestigationPackCatalog = async (context: AuthContext, user: AuthUser) => {
  await checkEnterpriseEdition(context);
  const result = await listInvestigationPacks({ id: user.id, user_email: user.user_email });
  if (!result.ok) {
    return { available: false, reason: result.failure ?? ENGINE_NOT_CONFIGURED, packs: [] };
  }
  return { available: true, reason: null, packs: result.value };
};

// endregion
