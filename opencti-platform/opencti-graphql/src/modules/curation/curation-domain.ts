import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase } from '../../types/store';
import { FunctionalError, ForbiddenAccess } from '../../config/errors';
import { logApp } from '../../config/conf';
import { patchAttribute } from '../../database/middleware';
import { internalFindByIds, pageEntitiesConnection, storeLoadById, type EntityOptions } from '../../database/middleware-loader';
import { elAggregationCount, elCount } from '../../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { isUserHasCapability, KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNMERGE, SYSTEM_USER } from '../../utils/access';
import { publishUserAction } from '../../listener/UserActionListener';
import { createListTask, ACTION_TYPE_CURATION_APPLY } from '../../domain/backgroundTask-common';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import {
  addCurationProposalAcceptedCount,
  addCurationProposalAutoAppliedCount,
  addCurationProposalRejectedCount,
  addCurationProposalRevertedCount,
} from '../../manager/telemetryManager';
import { now } from '../../utils/format';
import {
  ACTION_MERGE,
  ACTION_UNMERGE,
  type BasicStoreEntityCurationProposal,
  type CurationAdjudication,
  type CurationDecision,
  type CurationSettings,
  DECISION_ALIAS,
  DECISION_DISTINCT,
  DECISION_MERGE,
  ENTITY_TYPE_CURATION_POLICY,
  ENTITY_TYPE_CURATION_PROPOSAL,
  ENTITY_TYPE_MERGE_RECORD,
  MERGE_STATUS_ACTIVE,
  MERGE_STATUS_PARTIALLY_REVERTED,
  PROPOSAL_STATUS_ACCEPTED,
  PROPOSAL_STATUS_AUTO_APPLIED,
  PROPOSAL_STATUS_OPEN,
  PROPOSAL_STATUS_REJECTED,
  PROPOSAL_STATUS_REVERTED,
  CURATION_DETECTORS,
} from './curation-types';
import { executeProposalAction, isProceduresAttributeAvailable, revertAppliedPatch } from './curation-apply';
import { unmergeFromRecord } from './curation-merge-record';
import { getCurationSettings, getCurationSettingsId, saveCurationSettings, validateFieldAuthorityRules } from './curation-settings';
import { adjudicateProposal, isAdjudicationAvailable } from './curation-adjudication';
import { evaluatePolicyEligibility, findPolicyById, loadPolicyFacts } from './curation-policies';
import { createHealthSnapshot, findLatestHealthSnapshot } from './curation-health';
import { getTaxonomyMetadata } from './curation-taxonomy';

const MAX_BULK = 500;

// region queries
export const findProposalById = async (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityCurationProposal>(context, user, id, ENTITY_TYPE_CURATION_PROPOSAL);
};

export const findProposalsPaginated = async (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityCurationProposal>) => {
  return pageEntitiesConnection<BasicStoreEntityCurationProposal>(context, user, [ENTITY_TYPE_CURATION_PROPOSAL], opts);
};

export const findProposalsForEntity = async (context: AuthContext, user: AuthUser, entityId: string, statuses?: string[] | null) => {
  const filters = [{ key: ['subject_ids'], values: [entityId], operator: FilterOperator.Eq }];
  const wanted = statuses && statuses.length > 0 ? statuses : [PROPOSAL_STATUS_OPEN];
  filters.push({ key: ['proposal_status'], values: wanted, operator: FilterOperator.Eq });
  const page = await pageEntitiesConnection<BasicStoreEntityCurationProposal>(context, user, [ENTITY_TYPE_CURATION_PROPOSAL], {
    filters: { mode: FilterMode.And, filters, filterGroups: [] },
    orderBy: 'confidence_score',
    orderMode: 'desc' as any,
    first: 50,
  });
  return page.edges.map((edge) => edge.node);
};

export const resolveProposalSubjects = async (context: AuthContext, user: AuthUser, proposal: BasicStoreEntityCurationProposal) => {
  const found = await internalFindByIds(context, user, proposal.subject_ids) as BasicStoreBase[];
  const byId = new Map(found.map((element) => [element.internal_id, element]));
  return proposal.subject_ids.map((id) => byId.get(id)).filter((element): element is BasicStoreBase => element !== undefined);
};

export const canUserApplyProposal = (user: AuthUser, proposal: BasicStoreEntityCurationProposal) => {
  if (!isUserHasCapability(user, KNOWLEDGE_KNUPDATE)) return false;
  if (proposal.recommended_action === ACTION_MERGE || proposal.recommended_action === ACTION_UNMERGE) {
    return isUserHasCapability(user, KNOWLEDGE_KNUPDATE_KNMERGE);
  }
  return true;
};

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
  return {
    open_count: openCount,
    ambiguous_count: ambiguousCount,
    open_by_kind: asEntries(openByKind as Array<{ label: string; value: number }>),
    decided_by_status: asEntries((byStatus as Array<{ label: string; value: number }>).filter((entry) => entry.label !== PROPOSAL_STATUS_OPEN)),
    active_merge_records_count: activeMergeRecords,
    latest_health_score: latest?.health_score ?? null,
    last_scan_date: settings.last_scan_date,
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
}

const applyAndRecord = async (
  context: AuthContext,
  user: AuthUser,
  proposal: BasicStoreEntityCurationProposal,
  settings: CurationSettings,
  input: ApplyDecisionInput,
) => {
  if (!canUserApplyProposal(user, proposal)) {
    throw ForbiddenAccess('You are not allowed to apply this curation proposal');
  }
  const result = await executeProposalAction(context, user, proposal, settings, {
    targetId: input.targetId ?? null,
    payload: input.payload ?? null,
    decision: input.decision ?? null,
  });
  const patch: Record<string, unknown> = {
    proposal_status: input.status,
    decided_at: now(),
    decided_by_id: user.id,
    decision_rationale: input.rationale ?? null,
    applied_patch: result.appliedPatch,
    merge_record_id: result.mergeRecordId,
  };
  if (input.targetId) patch.target_id = input.targetId;
  if (input.policyId) patch.policy_id = input.policyId;
  if (input.adjudication) patch.curation_adjudication = { ...input.adjudication, applied: true };
  else if (proposal.curation_adjudication) patch.curation_adjudication = { ...proposal.curation_adjudication, applied: true };
  const { element } = await patchAttribute(context, SYSTEM_USER, proposal.internal_id, ENTITY_TYPE_CURATION_PROPOSAL, patch);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'extended',
    message: `${input.status === PROPOSAL_STATUS_AUTO_APPLIED ? 'auto-applies' : 'accepts'} curation proposal \`${proposal.name}\` (${proposal.proposal_kind}: ${proposal.recommended_action})`,
    context_data: {
      id: proposal.internal_id,
      entity_type: ENTITY_TYPE_CURATION_PROPOSAL,
      input: { subject_ids: proposal.subject_ids, policy_id: input.policyId ?? null, merge_record_id: result.mergeRecordId },
    },
  });
  if (input.status === PROPOSAL_STATUS_AUTO_APPLIED) addCurationProposalAutoAppliedCount();
  else addCurationProposalAcceptedCount();
  return element as unknown as BasicStoreEntityCurationProposal;
};

export const acceptProposal = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
  input?: { target_id?: string | null; rationale?: string | null; action_payload?: string | null } | null,
) => {
  const proposal = await loadOpenProposal(context, user, id);
  const settings = await getCurationSettings(context);
  return applyAndRecord(context, user, proposal, settings, {
    status: PROPOSAL_STATUS_ACCEPTED,
    rationale: input?.rationale,
    targetId: input?.target_id,
    payload: parseJsonPayload(input?.action_payload),
  });
};

const recordRejection = async (
  context: AuthContext,
  user: AuthUser,
  proposal: BasicStoreEntityCurationProposal,
  rationale?: string | null,
  adjudication?: CurationAdjudication | null,
) => {
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
};

export const rejectProposal = async (context: AuthContext, user: AuthUser, id: string, rationale?: string | null) => {
  const proposal = await loadOpenProposal(context, user, id);
  return recordRejection(context, user, proposal, rationale);
};

/**
 * Decision of an adjudicator (XTM One agent through the decide tool, or any API client). Without apply, the decision
 * is only recorded. With apply: merge and alias decisions apply the proposal, distinct rejects it (and the pair is
 * never proposed again), skip leaves it open.
 */
export const decideProposal = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
  input: { decision: CurationDecision; rationale: string; apply?: boolean | null; agent_slug?: string | null; model?: string | null; target_id?: string | null },
) => {
  const proposal = await loadOpenProposal(context, user, id);
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
  };
  if (input.apply) {
    if (input.decision === DECISION_DISTINCT) {
      return recordRejection(context, user, proposal, rationale, adjudication);
    }
    if (input.decision === DECISION_MERGE || input.decision === DECISION_ALIAS) {
      const settings = await getCurationSettings(context);
      return applyAndRecord(context, user, proposal, settings, {
        status: PROPOSAL_STATUS_ACCEPTED,
        rationale,
        targetId: input.target_id ?? null,
        decision: input.decision,
        adjudication,
      });
    }
  }
  const patch: Record<string, unknown> = { curation_adjudication: adjudication };
  if (input.target_id) patch.target_id = input.target_id;
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
};

/**
 * Apply executed by a background task: a bulk accept (no policy) or a policy auto-apply. A policy apply re-checks the
 * eligibility at apply time (the graph may have changed since the task was created) and skips silently otherwise.
 */
export const applyProposalFromTask = async (context: AuthContext, user: AuthUser, id: string, policyId?: string | null) => {
  const proposal = await findProposalById(context, user, id);
  if (!proposal) {
    throw FunctionalError('Curation proposal not found', { id });
  }
  if (proposal.proposal_status !== PROPOSAL_STATUS_OPEN) {
    return proposal;
  }
  const settings = await getCurationSettings(context);
  if (!policyId) {
    return applyAndRecord(context, user, proposal, settings, { status: PROPOSAL_STATUS_ACCEPTED, rationale: 'Bulk accept' });
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
  const decision = proposal.curation_adjudication?.decision === DECISION_ALIAS ? DECISION_ALIAS : null;
  const applied = await applyAndRecord(context, user, proposal, settings, {
    status: PROPOSAL_STATUS_AUTO_APPLIED,
    rationale: `Applied by curation policy ${policy.name}`,
    policyId: policy.internal_id,
    decision,
  });
  await patchAttribute(context, SYSTEM_USER, policy.internal_id, ENTITY_TYPE_CURATION_POLICY, { applied_count: (policy.applied_count ?? 0) + 1 });
  return applied;
};

export const adjudicateProposalNow = async (context: AuthContext, user: AuthUser, id: string) => {
  const proposal = await loadOpenProposal(context, user, id);
  const settings = await getCurationSettings(context);
  return adjudicateProposal(context, user, proposal, settings);
};

export const bulkAcceptProposals = async (context: AuthContext, user: AuthUser, ids: string[]) => {
  const uniqueIds = R.uniq(ids);
  if (uniqueIds.length === 0 || uniqueIds.length > MAX_BULK) {
    throw FunctionalError(`Bulk accept handles between 1 and ${MAX_BULK} proposals`, { count: uniqueIds.length });
  }
  const task = await createListTask(context, user, {
    ids: uniqueIds,
    scope: 'KNOWLEDGE',
    actions: [{ type: ACTION_TYPE_CURATION_APPLY, context: { values: [] } }],
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

export const revertProposal = async (context: AuthContext, user: AuthUser, id: string) => {
  const proposal = await findProposalById(context, user, id);
  if (!proposal) {
    throw FunctionalError('Curation proposal not found', { id });
  }
  if (proposal.proposal_status !== PROPOSAL_STATUS_ACCEPTED && proposal.proposal_status !== PROPOSAL_STATUS_AUTO_APPLIED) {
    throw FunctionalError('Only applied curation proposals can be reverted', { id, status: proposal.proposal_status });
  }
  if (!canUserApplyProposal(user, proposal)) {
    throw ForbiddenAccess('You are not allowed to revert this curation proposal');
  }
  let report: Record<string, unknown>;
  if (proposal.recommended_action === ACTION_MERGE && proposal.merge_record_id) {
    const result = await unmergeFromRecord(context, user, proposal.merge_record_id);
    report = { restored_ids: result.restored_ids, skipped_relationship_ids: result.skipped_relationship_ids };
  } else if (proposal.applied_patch) {
    report = { ...(await revertAppliedPatch(context, user, proposal.applied_patch)) };
  } else {
    throw FunctionalError('This curation proposal has nothing to revert', { id });
  }
  const { element } = await patchAttribute(context, SYSTEM_USER, proposal.internal_id, ENTITY_TYPE_CURATION_PROPOSAL, { proposal_status: PROPOSAL_STATUS_REVERTED });
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'extended',
    message: `reverts curation proposal \`${proposal.name}\``,
    context_data: { id: proposal.internal_id, entity_type: ENTITY_TYPE_CURATION_PROPOSAL, input: report },
  });
  addCurationProposalRevertedCount();
  return element as unknown as BasicStoreEntityCurationProposal;
};
// endregion

// region settings
export const curationSettingsForApi = async (context: AuthContext) => {
  const settings = await getCurationSettings(context);
  const taxonomy = getTaxonomyMetadata();
  const [adjudicationAvailable, id] = await Promise.all([isAdjudicationAvailable(context), getCurationSettingsId(context)]);
  return {
    id,
    ...settings,
    available_detectors: [...CURATION_DETECTORS],
    adjudication_available: adjudicationAvailable,
    graph_similarity_available: true,
    provenance_available: isProceduresAttributeAvailable(),
    procedures_attribute_available: isProceduresAttributeAvailable(),
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
  if (patch.ambiguous_band_min !== undefined && patch.ambiguous_band_max !== undefined && patch.ambiguous_band_min >= patch.ambiguous_band_max) {
    throw FunctionalError('The ambiguous band minimum must be lower than its maximum');
  }
  await saveCurationSettings(context, user, patch);
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
