import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase } from '../../types/store';
import { FunctionalError, ForbiddenAccess } from '../../config/errors';
import { logApp } from '../../config/conf';
import { patchAttribute } from '../../database/middleware';
import { internalFindByIds, storeLoadById, type EntityOptions } from '../../database/middleware-loader';
import { elAggregationCount, elCount, elUpdate } from '../../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS, wait } from '../../database/utils';
import { redisCurationDeleteApplicationResult, redisCurationGetApplicationResult, redisCurationSetApplicationResult } from '../../database/redis';
import { SYSTEM_USER } from '../../utils/access';
import { publishUserAction } from '../../listener/UserActionListener';
import { createListTask, ACTION_TYPE_CURATION_APPLY } from '../../domain/backgroundTask-common';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { addCurationProposalAcceptedCount, addCurationProposalAutoAppliedCount, addCurationProposalRejectedCount } from '../../manager/telemetryManager';
import { now } from '../../utils/format';
import {
  ACTION_FIX_DATES,
  ACTION_MERGE,
  ACTION_UNMERGE,
  type AppliedPatch,
  type BasicStoreEntityCurationPolicy,
  type BasicStoreEntityCurationProposal,
  type BasicStoreEntityMergeRecord,
  type CurationAdjudication,
  type CurationDecision,
  type CurationSettings,
  DECISION_ALIAS,
  DECISION_DISTINCT,
  DECISION_MERGE,
  ENTITY_TYPE_CURATION_PROPOSAL,
  ENTITY_TYPE_MERGE_RECORD,
  IRREVERSIBLE_MERGE_INTERRUPTED,
  IRREVERSIBLE_MERGE_RERUN,
  MERGE_STATUS_ACTIVE,
  MERGE_STATUS_IRREVERSIBLE,
  MERGE_STATUS_PARTIALLY_REVERTED,
  MERGE_STATUS_PENDING,
  MERGE_STATUS_REVERTED,
  PROPOSAL_KIND_MERGE,
  PROPOSAL_STATUS_ACCEPTED,
  PROPOSAL_STATUS_AUTO_APPLIED,
  PROPOSAL_STATUS_OPEN,
  PROPOSAL_STATUS_REJECTED,
  CURATION_DETECTORS,
} from './curation-types';
import {
  type ApplyResult,
  executeProposalAction,
  findLatestMergeRecordForProposal,
  hasInterruptedMergeForProposal,
  reconcilePlannedApplication,
  revertAppliedPatch,
} from './curation-apply';
import { findMergeRecordById, settlePendingMergeRecord, unmergeFromRecord } from './curation-merge-record';
import { getCurationSettings, getCurationSettingsId, saveCurationSettings, validateFieldAuthorityRules } from './curation-settings';
import { ADJUDICATED_PROPOSAL_KINDS, adjudicateProposal, adjudicationDecisionsFor, isAdjudicationAvailable } from './curation-adjudication';
import { adjudicationDecidesAction, canUserApplyPolicy, canUserApplyProposal, canUserRevertProposal, effectiveProposalAction, isProposalChoiceRequired } from './curation-access';
import { evaluatePolicyEligibility, findPolicyById, loadPolicyFacts } from './curation-policies';
import { createHealthSnapshot, findLatestHealthSnapshot } from './curation-health';
import { currentMergeConfidence, isGraphSimilarityAvailable } from './curation-scan';
import { getTaxonomyMetadata } from './curation-taxonomy';
import { CURATION_MANAGER_ENABLED, CURATION_SCAN_INTERVAL_MS, CURATION_SNAPSHOT_INTERVAL_MS, isCurationRunning, nextRunDate } from './curation-schedule';
import { withProposalTransitionLock } from './curation-locks';
import { keepWithReadableParticipants, pageWithReadableParticipants } from './curation-readability';
import { markProposalReverted, payloadElementIds } from './curation-proposals';

const MAX_BULK = 500;

// region queries
// The proposals follow the restrictions of their subjects and of the elements their action names (the attributions of
// an attribution conflict, the relationship whose procedure is kept, the merge record a split reverts), so the platform
// filters and counts them; the participant check guards the moments before a refresh, for reads and for every decision
// alike.
const proposalSubjectIds = (proposal: BasicStoreEntityCurationProposal) => R.uniq([
  ...(proposal.subject_ids ?? []),
  ...payloadElementIds(proposal.action_payload),
]);

export const findProposalById = async (context: AuthContext, user: AuthUser, id: string) => {
  const proposal = await storeLoadById<BasicStoreEntityCurationProposal>(context, user, id, ENTITY_TYPE_CURATION_PROPOSAL);
  if (!proposal) return proposal;
  const [readable] = await keepWithReadableParticipants(context, user, [proposal], proposalSubjectIds);
  return readable;
};

export const findProposalsPaginated = async (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityCurationProposal>) => {
  return pageWithReadableParticipants<BasicStoreEntityCurationProposal>(context, user, ENTITY_TYPE_CURATION_PROPOSAL, opts, proposalSubjectIds);
};

export const findProposalsForEntity = async (context: AuthContext, user: AuthUser, entityId: string, statuses?: string[] | null) => {
  const filters = [{ key: ['subject_ids'], values: [entityId], operator: FilterOperator.Eq }];
  const wanted = statuses && statuses.length > 0 ? statuses : [PROPOSAL_STATUS_OPEN];
  filters.push({ key: ['proposal_status'], values: wanted, operator: FilterOperator.Eq });
  const page = await pageWithReadableParticipants<BasicStoreEntityCurationProposal>(context, user, ENTITY_TYPE_CURATION_PROPOSAL, {
    filters: { mode: FilterMode.And, filters, filterGroups: [] },
    orderBy: 'confidence_score',
    orderMode: 'desc' as any,
    first: 50,
  }, proposalSubjectIds);
  return page.edges.map((edge) => edge.node);
};

export const resolveProposalSubjects = async (context: AuthContext, user: AuthUser, proposal: BasicStoreEntityCurationProposal) => {
  const found = await internalFindByIds(context, user, proposal.subject_ids) as BasicStoreBase[];
  const byId = new Map(found.map((element) => [element.internal_id, element]));
  return proposal.subject_ids.map((id) => byId.get(id)).filter((element): element is BasicStoreBase => element !== undefined);
};

// Counted by the search engine from the stored restrictions of each record (see pageWithReadableParticipants).
export const curationStatistics = async (context: AuthContext, user: AuthUser) => {
  const openFilter = { mode: FilterMode.And, filters: [{ key: ['proposal_status'], values: [PROPOSAL_STATUS_OPEN] }], filterGroups: [] };
  const [openCount, ambiguousCount, openByKind, byStatus, activeMergeRecords, latest, settings] = await Promise.all([
    elCount(context, user, READ_INDEX_INTERNAL_OBJECTS, { types: [ENTITY_TYPE_CURATION_PROPOSAL], filters: openFilter }),
    elCount(context, user, READ_INDEX_INTERNAL_OBJECTS, {
      types: [ENTITY_TYPE_CURATION_PROPOSAL],
      filters: { mode: FilterMode.And, filters: [{ key: ['proposal_status'], values: [PROPOSAL_STATUS_OPEN] }, { key: ['in_ambiguous_band'], values: ['true'] }], filterGroups: [] },
    }),
    elAggregationCount(context, user, READ_INDEX_INTERNAL_OBJECTS, { types: [ENTITY_TYPE_CURATION_PROPOSAL], field: 'proposal_kind', filters: openFilter }),
    elAggregationCount(context, user, READ_INDEX_INTERNAL_OBJECTS, { types: [ENTITY_TYPE_CURATION_PROPOSAL], field: 'proposal_status' }),
    elCount(context, user, READ_INDEX_INTERNAL_OBJECTS, {
      types: [ENTITY_TYPE_MERGE_RECORD],
      filters: { mode: FilterMode.And, filters: [{ key: ['merge_status'], values: [MERGE_STATUS_ACTIVE, MERGE_STATUS_PARTIALLY_REVERTED] }], filterGroups: [] },
    }),
    findLatestHealthSnapshot(context, user),
    getCurationSettings(context),
  ]);
  const asEntries = (aggregation: Array<{ label: string; value: number }>) => aggregation.map(({ label, value }) => ({ key: label, count: value }));
  const scanScheduled = isCurationRunning(settings.curation_enabled);
  return {
    open_count: openCount,
    ambiguous_count: ambiguousCount,
    open_by_kind: asEntries(openByKind as Array<{ label: string; value: number }>),
    decided_by_status: asEntries((byStatus as Array<{ label: string; value: number }>).filter((entry) => entry.label !== PROPOSAL_STATUS_OPEN)),
    active_merge_records_count: activeMergeRecords,
    latest_health_score: latest?.health_score ?? null,
    last_scan_date: settings.last_scan_date,
    curation_enabled: settings.curation_enabled,
    next_scan_date: scanScheduled ? nextRunDate(settings.force_scan ? null : settings.last_scan_date, CURATION_SCAN_INTERVAL_MS) : null,
    next_snapshot_date: CURATION_MANAGER_ENABLED
      ? nextRunDate(settings.last_snapshot_date ?? latest?.snapshot_date, CURATION_SNAPSHOT_INTERVAL_MS)
      : null,
  };
};
// endregion

// region decisions
const loadOpenProposal = async (context: AuthContext, user: AuthUser, id: string) => {
  const proposal = await findProposalById(context, user, id);
  if (!proposal) {
    throw FunctionalError('Curation proposal not found', { id });
  }
  if (proposal.proposal_status !== PROPOSAL_STATUS_OPEN) {
    throw FunctionalError('This curation proposal is already decided', { id, status: proposal.proposal_status });
  }
  return proposal;
};

const withProposalLock = withProposalTransitionLock;

// A decision taken on the proposal as it was read: refused when a detector or a decision changed it since. Once its
// application started, detections leave a proposal as it is: the start itself is then the only change, never refused.
const checkProposalRevision = (proposal: BasicStoreEntityCurationProposal, expectedUpdatedAt?: string | Date | null) => {
  if (!expectedUpdatedAt || proposal.application_started_at) return;
  if (new Date(proposal.updated_at).getTime() !== new Date(expectedUpdatedAt).getTime()) {
    throw FunctionalError('This curation proposal changed since it was read: read it again before deciding on it', {
      id: proposal.internal_id,
      updated_at: proposal.updated_at,
    });
  }
};

const parseJsonPayload = (payload?: string | null): Record<string, unknown> | null => {
  if (!payload) return null;
  try {
    const parsed = JSON.parse(payload);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    throw FunctionalError('The action payload must be a JSON object');
  }
};

interface ApplyDecisionInput {
  status: typeof PROPOSAL_STATUS_ACCEPTED | typeof PROPOSAL_STATUS_AUTO_APPLIED;
  rationale?: string | null;
  targetId?: string | null;
  payload?: Record<string, unknown> | null;
  decision?: CurationDecision | null;
  policyId?: string | null;
  adjudication?: CurationAdjudication | null;
  expectedUpdatedAt?: string | Date | null;
}

interface ProposalApplication extends ApplyResult {
  targetId: string | null;
  /** Kept before the graph changed: what of it was applied is read back from the graph. */
  planned?: boolean;
}

interface UnrecordedApplication {
  application: ProposalApplication | null;
  complete: boolean;
}

const DECISION_RECORD_ATTEMPTS = 3;

const mergePatches = (first: AppliedPatch | null, second: AppliedPatch | null): AppliedPatch | null => {
  if (!first || !second) return second ?? first;
  return {
    operations: [...first.operations, ...second.operations],
    created_ids: R.uniq([...(first.created_ids ?? []), ...(second.created_ids ?? [])]),
    deleted_ids: R.uniq([...(first.deleted_ids ?? []), ...(second.deleted_ids ?? [])]),
    delete_operation_ids: { ...(first.delete_operation_ids ?? {}), ...(second.delete_operation_ids ?? {}) },
    applied_at: second.applied_at,
  };
};

const mergeApplications = (first: ProposalApplication | null, second: ProposalApplication): ProposalApplication => ({
  appliedPatch: mergePatches(first?.appliedPatch ?? null, second.appliedPatch),
  mergeRecordId: second.mergeRecordId ?? first?.mergeRecordId ?? null,
  targetId: second.targetId ?? first?.targetId ?? null,
});

/**
 * The application a previous attempt made but could not record (the proposal is marked as being applied and still
 * open): its result kept aside, the part of its planned change found in the graph, or the merge record of a merge,
 * which names the proposal it applies. Not complete when the previous attempt changed nothing that can be found, or
 * only part of what it planned: the action runs again (it skips what is already changed).
 */
const findUnrecordedApplication = async (context: AuthContext, proposal: BasicStoreEntityCurationProposal): Promise<UnrecordedApplication> => {
  if (!proposal.application_started_at) return { application: null, complete: false };
  const kept = await redisCurationGetApplicationResult<ProposalApplication>(proposal.internal_id);
  if (kept && !kept.planned) return { application: kept, complete: true };
  if (kept?.planned) {
    const { result, complete } = await reconcilePlannedApplication(context, kept);
    if (result) return { application: { ...result, targetId: kept.targetId }, complete };
  }
  let record: BasicStoreEntityMergeRecord | null = await findLatestMergeRecordForProposal(context, proposal.internal_id);
  if (record?.merge_status === MERGE_STATUS_PENDING) {
    // Written before the merge starts: what the merge did is read from the graph. A merge that never started is run again.
    const outcome = await settlePendingMergeRecord(context, record);
    record = outcome === 'discarded' ? null : await findLatestMergeRecordForProposal(context, proposal.internal_id);
  }
  if (record && record.irreversible_reason !== IRREVERSIBLE_MERGE_INTERRUPTED) {
    return { application: { appliedPatch: null, mergeRecordId: record.internal_id, targetId: record.merge_target_id }, complete: true };
  }
  return { application: null, complete: false };
};

/**
 * A merge applies a duplicate finding. When a subject changed since the proposal was raised (renamed, aliases or
 * identifiers edited), the detectors run again on the subjects as they are now, and the merge is refused when they no
 * longer find the pair. A subject that is gone is left to the merge, which says what remains to merge.
 */
const checkMergeFindingHolds = async (context: AuthContext, settings: CurationSettings, proposal: BasicStoreEntityCurationProposal) => {
  const subjects = await internalFindByIds(context, SYSTEM_USER, proposal.subject_ids) as BasicStoreBase[];
  if (subjects.length < 2) return;
  const raisedAt = new Date(proposal.created_at).getTime();
  if (!subjects.some((subject) => new Date(subject.updated_at).getTime() > raisedAt)) return;
  const confidence = await currentMergeConfidence(context, settings, { subject_ids: subjects.map((subject) => subject.internal_id) });
  if (confidence === null) {
    throw FunctionalError('These entities changed since the proposal was raised and the detectors no longer find them duplicates: reject the proposal', {
      id: proposal.internal_id,
    });
  }
};

const applyAndRecord = async (
  context: AuthContext,
  user: AuthUser,
  loadedProposal: BasicStoreEntityCurationProposal,
  settings: CurationSettings,
  input: ApplyDecisionInput,
) => withProposalLock(loadedProposal.internal_id, async () => {
  const proposal = await loadOpenProposal(context, user, loadedProposal.internal_id);
  checkProposalRevision(proposal, input.expectedUpdatedAt);
  if (!canUserApplyProposal(user, proposal, input.decision)) {
    throw ForbiddenAccess('You are not allowed to apply this curation proposal');
  }
  // A policy checks the finding at its own threshold before applying it; a retry completes a merge already started.
  if (!input.policyId && !proposal.application_started_at && proposal.proposal_kind === PROPOSAL_KIND_MERGE
    && effectiveProposalAction(proposal, input.decision) === ACTION_MERGE) {
    await checkMergeFindingHolds(context, settings, proposal);
  }
  // A retry after a change that could not be recorded records that change, instead of applying the action again.
  const unrecorded = await findUnrecordedApplication(context, proposal);
  let application = unrecorded.complete ? unrecorded.application : null;
  if (!application) {
    await patchAttribute(context, SYSTEM_USER, proposal.internal_id, ENTITY_TYPE_CURATION_PROPOSAL, { application_started_at: now() });
    const recovered = unrecorded.application;
    const targetId = input.targetId ?? recovered?.targetId ?? null;
    const result = await executeProposalAction(context, user, proposal, settings, {
      targetId,
      payload: input.payload ?? null,
      decision: input.decision ?? null,
      // Kept before the graph changes, so an attempt that stops after the change can still record it and revert it.
      onBeforeChange: (plan) => redisCurationSetApplicationResult(proposal.internal_id, { ...mergeApplications(recovered, { ...plan, targetId }), planned: true }),
    });
    application = mergeApplications(recovered, { ...result, targetId });
  }
  // A merge run again after an interrupted one snapshots the graph the interrupted one already changed: undoing it would
  // not restore that part, so it is not reversible either. Checked on every retry, so a failed marking is made again;
  // its own reason keeps a later retry from taking it for an interrupted merge and running it a third time.
  if (proposal.application_started_at && application.mergeRecordId
    && await hasInterruptedMergeForProposal(context, proposal.internal_id, application.mergeRecordId)) {
    await patchAttribute(context, SYSTEM_USER, application.mergeRecordId, ENTITY_TYPE_MERGE_RECORD, {
      merge_status: MERGE_STATUS_IRREVERSIBLE,
      irreversible_reason: IRREVERSIBLE_MERGE_RERUN,
    });
  }
  const patch: Record<string, unknown> = {
    proposal_status: input.status,
    decided_at: now(),
    decided_by_id: user.id,
    decision_rationale: input.rationale ?? null,
    applied_patch: application.appliedPatch,
    merge_record_id: application.mergeRecordId,
  };
  if (application.targetId) patch.target_id = application.targetId;
  if (input.policyId) patch.policy_id = input.policyId;
  if (input.adjudication) {
    patch.curation_adjudication = { ...input.adjudication, applied: true };
  } else if (proposal.curation_adjudication
    && adjudicationDecidesAction(proposal.curation_adjudication.decision, effectiveProposalAction(proposal, input.decision))) {
    // Accepting another action than the one the adjudication decided leaves it advisory.
    patch.curation_adjudication = { ...proposal.curation_adjudication, applied: true };
  }
  let element;
  for (let attempt = 1; !element; attempt += 1) {
    try {
      ({ element } = await patchAttribute(context, SYSTEM_USER, proposal.internal_id, ENTITY_TYPE_CURATION_PROPOSAL, patch));
    } catch (error) {
      if (attempt < DECISION_RECORD_ATTEMPTS) {
        await wait(attempt * 250);
        continue;
      }
      // The graph is changed but the proposal still reads open: the result is kept for the next attempt to record.
      await redisCurationSetApplicationResult(proposal.internal_id, application).catch((keepError) => {
        logApp.error('[CURATION] Result of an unrecorded proposal application cannot be kept', { cause: keepError, proposal_id: proposal.internal_id });
      });
      logApp.error('[CURATION] Proposal applied but its decision could not be recorded', {
        cause: error,
        proposal_id: proposal.internal_id,
        merge_record_id: application.mergeRecordId,
      });
      throw FunctionalError('The change was applied but the proposal could not be updated: accept it again to record it', { id: proposal.internal_id });
    }
  }
  await redisCurationDeleteApplicationResult(proposal.internal_id).catch(() => undefined);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'extended',
    message: `${input.status === PROPOSAL_STATUS_AUTO_APPLIED ? 'auto-applies' : 'accepts'} curation proposal \`${proposal.name}\` (${proposal.proposal_kind}: ${proposal.recommended_action})`,
    context_data: {
      id: proposal.internal_id,
      entity_type: ENTITY_TYPE_CURATION_PROPOSAL,
      input: { subject_ids: proposal.subject_ids, policy_id: input.policyId ?? null, merge_record_id: application.mergeRecordId },
    },
  });
  if (input.status === PROPOSAL_STATUS_AUTO_APPLIED) addCurationProposalAutoAppliedCount();
  else addCurationProposalAcceptedCount();
  return element as unknown as BasicStoreEntityCurationProposal;
});

/**
 * Acceptance by an analyst. Detectors refresh an open proposal in place (its recommendation, target and payload): with
 * expected_updated_at, the acceptance only applies the proposal as the analyst read it (checked under the transition lock).
 */
export const acceptProposal = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
  input?: { target_id?: string | null; rationale?: string | null; action_payload?: string | null; expected_updated_at?: string | Date | null } | null,
) => {
  const proposal = await loadOpenProposal(context, user, id);
  checkProposalRevision(proposal, input?.expected_updated_at);
  const settings = await getCurationSettings(context);
  return applyAndRecord(context, user, proposal, settings, {
    status: PROPOSAL_STATUS_ACCEPTED,
    rationale: input?.rationale,
    targetId: input?.target_id,
    payload: parseJsonPayload(input?.action_payload),
    expectedUpdatedAt: input?.expected_updated_at,
  });
};

const recordRejection = async (
  context: AuthContext,
  user: AuthUser,
  loadedProposal: BasicStoreEntityCurationProposal,
  rationale?: string | null,
  adjudication?: CurationAdjudication | null,
  expectedUpdatedAt?: string | Date | null,
) => withProposalLock(loadedProposal.internal_id, async () => {
  const proposal = await loadOpenProposal(context, user, loadedProposal.internal_id);
  checkProposalRevision(proposal, expectedUpdatedAt);
  const patch: Record<string, unknown> = {
    proposal_status: PROPOSAL_STATUS_REJECTED,
    decided_at: now(),
    decided_by_id: user.id,
    decision_rationale: rationale ?? null,
  };
  if (adjudication) patch.curation_adjudication = { ...adjudication, applied: true };
  const { element } = await patchAttribute(context, SYSTEM_USER, proposal.internal_id, ENTITY_TYPE_CURATION_PROPOSAL, patch);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'extended',
    message: `rejects curation proposal \`${proposal.name}\` (${proposal.proposal_kind})`,
    context_data: { id: proposal.internal_id, entity_type: ENTITY_TYPE_CURATION_PROPOSAL, input: { subject_ids: proposal.subject_ids, rationale: rationale ?? null } },
  });
  addCurationProposalRejectedCount();
  return element as unknown as BasicStoreEntityCurationProposal;
});

export const rejectProposal = async (context: AuthContext, user: AuthUser, id: string, rationale?: string | null) => {
  const proposal = await loadOpenProposal(context, user, id);
  return recordRejection(context, user, proposal, rationale);
};

/**
 * Decision of an adjudicator (XTM One agent through the decide tool, or any API client). Decisions resolve entities,
 * so only duplicate proposals (merge and alias) take one; the other kinds are accepted or rejected in the inbox.
 * Without apply, the decision is only recorded. With apply: merge and alias decisions apply the proposal, distinct
 * rejects it (and the pair is never proposed again), skip leaves it open. With expected_updated_at, the decision only
 * lands on the proposal as the adjudicator read it (checked again under the transition lock).
 */
export const decideProposal = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
  input: {
    decision: CurationDecision;
    rationale: string;
    apply?: boolean | null;
    agent_slug?: string | null;
    model?: string | null;
    target_id?: string | null;
    expected_updated_at?: string | Date | null;
  },
) => {
  const proposal = await loadOpenProposal(context, user, id);
  checkProposalRevision(proposal, input.expected_updated_at);
  if (!ADJUDICATED_PROPOSAL_KINDS.includes(proposal.proposal_kind)) {
    throw FunctionalError('Only merge and alias proposals take a curation decision: accept or reject this proposal instead', {
      id: proposal.internal_id,
      proposal_kind: proposal.proposal_kind,
    });
  }
  if (!adjudicationDecisionsFor(proposal.subject_ids).includes(input.decision)) {
    throw FunctionalError('A merge needs two subjects: decide a one-subject proposal with alias, distinct or skip', {
      id: proposal.internal_id,
      decision: input.decision,
    });
  }
  const rationale = (input.rationale ?? '').trim();
  if (rationale.length === 0) {
    throw FunctionalError('A rationale is required to decide a curation proposal');
  }
  if (input.target_id && !proposal.subject_ids.includes(input.target_id)) {
    throw FunctionalError('The target must be one of the proposal subjects', { target_id: input.target_id });
  }
  const adjudication: CurationAdjudication = {
    decision: input.decision,
    rationale: rationale.slice(0, 2000),
    agent_slug: input.agent_slug ?? null,
    model: input.model ?? null,
    adjudicated_at: now(),
    applied: false,
    verified: false,
  };
  if (input.apply) {
    if (input.decision === DECISION_DISTINCT) {
      return recordRejection(context, user, proposal, rationale, adjudication, input.expected_updated_at);
    }
    if (input.decision === DECISION_MERGE || input.decision === DECISION_ALIAS) {
      const settings = await getCurationSettings(context);
      return applyAndRecord(context, user, proposal, settings, {
        status: PROPOSAL_STATUS_ACCEPTED,
        rationale,
        targetId: input.target_id ?? null,
        decision: input.decision,
        adjudication,
        expectedUpdatedAt: input.expected_updated_at,
      });
    }
  }
  const patch: Record<string, unknown> = { curation_adjudication: adjudication };
  if (input.target_id) patch.target_id = input.target_id;
  // Recorded under the transition lock on a proposal read again: a decision never lands on a proposal closed meanwhile.
  return withProposalLock(proposal.internal_id, async () => {
    const current = await loadOpenProposal(context, user, proposal.internal_id);
    checkProposalRevision(current, input.expected_updated_at);
    const { element } = await patchAttribute(context, SYSTEM_USER, proposal.internal_id, ENTITY_TYPE_CURATION_PROPOSAL, patch);
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'update',
      event_access: 'extended',
      message: `records decision \`${input.decision}\` on curation proposal \`${proposal.name}\``,
      context_data: { id: proposal.internal_id, entity_type: ENTITY_TYPE_CURATION_PROPOSAL, input: { decision: input.decision, apply: input.apply ?? false } },
    });
    return element as unknown as BasicStoreEntityCurationProposal;
  });
};

const POLICY_APPLIED_COUNT_SCRIPT = 'ctx._source.applied_count = (ctx._source.applied_count == null ? 0 : ctx._source.applied_count) + params.increment';

// Policy tasks run in parallel workers: the counter is incremented in the index itself, never read-modify-written.
const incrementPolicyAppliedCount = async (context: AuthContext, policy: BasicStoreEntityCurationPolicy) => {
  await elUpdate(context, policy._index, policy.internal_id, { script: { source: POLICY_APPLIED_COUNT_SCRIPT, lang: 'painless', params: { increment: 1 } } });
};

/**
 * Apply executed by a background task, as its initiator (the worker sends the task's applicant): a bulk accept (no
 * policy) or a policy auto-apply. A bulk accept applies the proposal as it was when the task was queued
 * (expected_updated_at), and is refused for a proposal refreshed since. A policy apply re-checks the eligibility of the
 * current proposal at apply time (the graph may have changed since the task was created), and for a merge that the
 * detectors still find the pair at the policy threshold, and skips silently otherwise.
 */
export const applyProposalFromTask = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
  policyId?: string | null,
  expectedUpdatedAt?: string | Date | null,
) => {
  const proposal = await findProposalById(context, user, id);
  if (!proposal) {
    throw FunctionalError('Curation proposal not found', { id });
  }
  if (proposal.proposal_status !== PROPOSAL_STATUS_OPEN) {
    return proposal;
  }
  const settings = await getCurationSettings(context);
  if (!policyId) {
    return applyAndRecord(context, user, proposal, settings, { status: PROPOSAL_STATUS_ACCEPTED, rationale: 'Bulk accept', expectedUpdatedAt });
  }
  if (!canUserApplyPolicy(user)) {
    throw ForbiddenAccess('You are not allowed to apply a curation policy');
  }
  await checkEnterpriseEdition(context);
  const policy = await findPolicyById(context, SYSTEM_USER, policyId);
  if (!policy || !policy.policy_enabled) {
    logApp.info('[CURATION] Policy disabled or removed, auto-apply skipped', { proposal_id: id, policy_id: policyId });
    return proposal;
  }
  const { factsFor, hasOpenContradiction } = await loadPolicyFacts(context, [proposal]);
  const exclusion = evaluatePolicyEligibility(policy, proposal, factsFor(proposal), hasOpenContradiction(proposal));
  if (exclusion) {
    logApp.info('[CURATION] Proposal not eligible anymore, auto-apply skipped', { proposal_id: id, policy_id: policyId, reason: exclusion });
    return proposal;
  }
  // The entities may have changed since the finding: a policy only merges a pair the detectors still find at its threshold.
  if (proposal.proposal_kind === PROPOSAL_KIND_MERGE) {
    const confidence = await currentMergeConfidence(context, settings, proposal);
    if (confidence === null || confidence < policy.auto_apply_threshold) {
      logApp.info('[CURATION] Duplicate finding no longer holds, auto-apply skipped', { proposal_id: id, policy_id: policyId, confidence });
      return proposal;
    }
  }
  const adjudication = proposal.curation_adjudication?.verified === true ? proposal.curation_adjudication : null;
  const decision = adjudication?.decision === DECISION_ALIAS ? DECISION_ALIAS : null;
  const applied = await applyAndRecord(context, user, proposal, settings, {
    status: PROPOSAL_STATUS_AUTO_APPLIED,
    rationale: `Applied by curation policy ${policy.name}`,
    policyId: policy.internal_id,
    decision,
  });
  await incrementPolicyAppliedCount(context, policy);
  return applied;
};

export const adjudicateProposalNow = async (context: AuthContext, user: AuthUser, id: string) => {
  const proposal = await loadOpenProposal(context, user, id);
  const settings = await getCurationSettings(context);
  if (!settings.adjudication_enabled) {
    throw FunctionalError('Curation adjudication is disabled in the curation settings');
  }
  const adjudicated = await adjudicateProposal(context, user, proposal, settings);
  if (!adjudicated) {
    throw FunctionalError('The Run as account of the curation settings cannot read this proposal and all its subjects', { id });
  }
  return adjudicated;
};

export const bulkAcceptProposals = async (context: AuthContext, user: AuthUser, ids: string[]) => {
  const uniqueIds = R.uniq(ids);
  if (uniqueIds.length === 0 || uniqueIds.length > MAX_BULK) {
    throw FunctionalError(`Bulk accept handles between 1 and ${MAX_BULK} proposals`, { count: uniqueIds.length });
  }
  const proposals = await internalFindByIds(context, user, uniqueIds, { type: ENTITY_TYPE_CURATION_PROPOSAL }) as unknown as BasicStoreEntityCurationProposal[];
  const resolvedIds = new Set(proposals.flatMap((proposal) => [proposal.internal_id, proposal.standard_id]));
  if (uniqueIds.some((id) => !resolvedIds.has(id))) {
    throw ForbiddenAccess('Some of the selected curation proposals do not exist or are not accessible');
  }
  const choiceRequiredIds = proposals.filter((proposal) => isProposalChoiceRequired(proposal)).map((proposal) => proposal.internal_id);
  if (choiceRequiredIds.length > 0) {
    throw FunctionalError('Some selected proposals need a choice (the attribution to keep): accept them one by one', { proposal_ids: choiceRequiredIds });
  }
  // Refused here as by a single acceptance, rather than queued for a worker that would fail them.
  const forbiddenIds = proposals.filter((proposal) => !canUserApplyProposal(user, proposal)).map((proposal) => proposal.internal_id);
  if (forbiddenIds.length > 0) {
    throw ForbiddenAccess('You are not allowed to apply some of the selected curation proposals', { proposal_ids: forbiddenIds });
  }
  // Each proposal is applied as it is read here: one a detection refreshes before the worker runs is refused.
  const revisions = Object.fromEntries(proposals.map((proposal) => [proposal.internal_id, proposal.updated_at]));
  const task = await createListTask(context, user, {
    ids: uniqueIds,
    scope: 'KNOWLEDGE',
    actions: [{ type: ACTION_TYPE_CURATION_APPLY, context: { values: [], revisions } }],
    description: `Curation: accept ${uniqueIds.length} proposal(s)`,
  });
  return task.id;
};

export const bulkRejectProposals = async (context: AuthContext, user: AuthUser, ids: string[], rationale?: string | null) => {
  const uniqueIds = R.uniq(ids);
  if (uniqueIds.length === 0 || uniqueIds.length > MAX_BULK) {
    throw FunctionalError(`Bulk reject handles between 1 and ${MAX_BULK} proposals`, { count: uniqueIds.length });
  }
  const rejected: string[] = [];
  for (let index = 0; index < uniqueIds.length; index += 1) {
    const proposal = await findProposalById(context, user, uniqueIds[index]);
    if (proposal && proposal.proposal_status === PROPOSAL_STATUS_OPEN) {
      await recordRejection(context, user, proposal, rationale);
      rejected.push(proposal.internal_id);
    }
  }
  return rejected;
};

/**
 * An applied proposal is reverted from its merge record (applied as a merge: its recommended action, or a merge
 * decision) or its applied patch. Two exceptions: a date fix, as reverting it would write back an end date before the
 * start date, which the platform refuses on every update; and a split, whose merge record is the merge it undid, so
 * there is no merge of its own to undo.
 */
const NOT_REVERTIBLE_ACTIONS = [ACTION_FIX_DATES, ACTION_UNMERGE];

export const isProposalRevertible = (proposal: BasicStoreEntityCurationProposal) => {
  const isApplied = proposal.proposal_status === PROPOSAL_STATUS_ACCEPTED || proposal.proposal_status === PROPOSAL_STATUS_AUTO_APPLIED;
  const hasTrace = !!proposal.merge_record_id || !!proposal.applied_patch;
  return isApplied && hasTrace && !NOT_REVERTIBLE_ACTIONS.includes(proposal.recommended_action);
};

export const revertProposal = async (context: AuthContext, user: AuthUser, id: string) => withProposalLock(id, async () => {
  const proposal = await findProposalById(context, user, id);
  if (!proposal) {
    throw FunctionalError('Curation proposal not found', { id });
  }
  if (proposal.proposal_status !== PROPOSAL_STATUS_ACCEPTED && proposal.proposal_status !== PROPOSAL_STATUS_AUTO_APPLIED) {
    throw FunctionalError('Only applied curation proposals can be reverted', { id, status: proposal.proposal_status });
  }
  if (proposal.recommended_action === ACTION_FIX_DATES) {
    throw FunctionalError('A date fix cannot be reverted: the original end date is before the start date, which the platform does not accept', { id });
  }
  if (proposal.recommended_action === ACTION_UNMERGE) {
    throw FunctionalError('A split cannot be reverted: merge the restored entities again instead', { id });
  }
  if (!canUserRevertProposal(user, proposal)) {
    throw ForbiddenAccess('You are not allowed to revert this curation proposal');
  }
  let report: Record<string, unknown>;
  if (proposal.merge_record_id) {
    // A revert retried after its graph change failed to close the proposal: the merge record is already fully undone,
    // so only the proposal is left to close. A partially undone record is completed by the unmerge.
    const record = await findMergeRecordById(context, user, proposal.merge_record_id);
    if (record?.merge_status === MERGE_STATUS_REVERTED) {
      report = { restored_ids: [], skipped_relationship_ids: [], already_reverted: true };
    } else {
      const result = await unmergeFromRecord(context, user, proposal.merge_record_id);
      report = { restored_ids: result.restored_ids, skipped_relationship_ids: result.skipped_relationship_ids };
    }
  } else if (proposal.applied_patch) {
    report = { ...(await revertAppliedPatch(context, user, proposal.applied_patch)) };
  } else {
    throw FunctionalError('This curation proposal has nothing to revert', { id });
  }
  const reverted = await markProposalReverted(context, proposal.internal_id);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'extended',
    message: `reverts curation proposal \`${proposal.name}\``,
    context_data: { id: proposal.internal_id, entity_type: ENTITY_TYPE_CURATION_PROPOSAL, input: report },
  });
  return reverted ?? proposal;
});
// endregion

// region settings
/** Whether an analyst can ask the OpenCTI Curator to adjudicate a proposal: adjudication enabled and XTM One reachable. */
export const isCurationAdjudicationOffered = async (context: AuthContext) => {
  const settings = await getCurationSettings(context);
  return settings.adjudication_enabled && isAdjudicationAvailable(context);
};

export const curationSettingsForApi = async (context: AuthContext) => {
  const settings = await getCurationSettings(context);
  const taxonomy = getTaxonomyMetadata();
  const [adjudicationAvailable, id, graphSimilarityAvailable] = await Promise.all([
    isAdjudicationAvailable(context),
    getCurationSettingsId(context),
    isGraphSimilarityAvailable(),
  ]);
  return {
    id,
    ...settings,
    available_detectors: [...CURATION_DETECTORS],
    adjudication_available: adjudicationAvailable,
    graph_similarity_available: graphSimilarityAvailable,
    taxonomy_version: taxonomy.version,
    taxonomy_clusters_count: taxonomy.clusters,
  };
};

export const editCurationSettings = async (context: AuthContext, user: AuthUser, input: Partial<CurationSettings>) => {
  const patch: Partial<CurationSettings> = R.reject(R.isNil, input as Record<string, unknown>) as Partial<CurationSettings>;
  if (patch.adjudication_enabled === true) {
    await checkEnterpriseEdition(context);
  }
  if (patch.field_authority_rules) {
    validateFieldAuthorityRules(patch.field_authority_rules);
  }
  const changesBand = patch.ambiguous_band_min !== undefined || patch.ambiguous_band_max !== undefined;
  // A partial input is checked against the settings it is merged into, read under the settings write lock.
  const validate = (merged: CurationSettings) => {
    if (changesBand && merged.ambiguous_band_min >= merged.ambiguous_band_max) {
      throw FunctionalError('The ambiguous band minimum must be lower than its maximum', {
        ambiguous_band_min: merged.ambiguous_band_min,
        ambiguous_band_max: merged.ambiguous_band_max,
      });
    }
  };
  await saveCurationSettings(context, user, patch, { validate });
  return curationSettingsForApi(context);
};

export const requestCurationScan = async (context: AuthContext, user: AuthUser) => {
  await saveCurationSettings(context, user, { force_scan: true });
  return curationSettingsForApi(context);
};

export const refreshKnowledgeHealth = async (context: AuthContext, user: AuthUser) => {
  const settings = await getCurationSettings(context);
  const snapshot = await createHealthSnapshot(context, settings);
  await saveCurationSettings(context, user, { last_snapshot_date: snapshot.snapshot_date }, { auditLog: false });
  return snapshot;
};
// endregion
