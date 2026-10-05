import type { Resolvers } from '../../generated/graphql';
import type { AuthContext } from '../../types/user';
import type { BasicStoreBase, BasicStoreEntity } from '../../types/store';
import { loadCreator } from '../../database/members';
import { internalFindByIds } from '../../database/middleware-loader';
import { getEntitiesListFromCache } from '../../database/cache';
import { ENTITY_TYPE_CONNECTOR } from '../../schema/internalObject';
import { isUserHasCapability, SETTINGS_SETCUSTOMIZATION, SYSTEM_USER } from '../../utils/access';
import { AUTHORITY_SOURCE_CONNECTOR, KNOWLEDGE_HEALTH_METRIC_KEYS } from './curation-types';
import {
  acceptProposal,
  adjudicateProposalNow,
  applyProposalFromTask,
  bulkAcceptProposals,
  bulkRejectProposals,
  isProposalRevertible,
  curationSettingsForApi,
  isCurationAdjudicationOffered,
  curationStatistics,
  decideProposal,
  editCurationSettings,
  findProposalById,
  findProposalsForEntity,
  findProposalsPaginated,
  refreshKnowledgeHealth,
  rejectProposal,
  requestCurationScan,
  revertProposal,
} from './curation-domain';
import { findMergeRecordById, findMergeRecordsPaginated, isMergeRecordReversible, unmergeFromRecord } from './curation-merge-record';
import {
  addCurationPolicy,
  applyCurationPolicyById,
  deleteCurationPolicy,
  dryRunCurationPolicy,
  editCurationPolicy,
  findPoliciesPaginated,
  findPolicyById,
} from './curation-policies';
import { findHealthSnapshotsPaginated, findLatestHealthSnapshot } from './curation-health';
import { curationResolve } from './curation-resolve';
import { curationAdjudicationSetup, isProposalAdjudicable } from './curation-adjudication';
import { curationAuthorityAttributes } from './curation-settings';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { canUserApplyProposal, canUserRevertProposal, isProposalChoiceRequired } from './curation-access';
import type {
  BasicStoreEntityCurationPolicy,
  BasicStoreEntityCurationProposal,
  BasicStoreEntityKnowledgeHealthSnapshot,
  BasicStoreEntityMergeRecord,
  CurationPolicyDryRunResult,
} from './curation-types';

const toJsonString = (value: unknown) => {
  if (value === null || value === undefined) return null;
  return typeof value === 'string' ? value : JSON.stringify(value);
};

const resolveSampleProposals = async (context: AuthContext, dryRun: CurationPolicyDryRunResult) => {
  const proposals = await Promise.all((dryRun.sample_proposal_ids ?? []).map((id) => findProposalById(context, context.user!, id)));
  return proposals.filter((proposal) => proposal !== undefined && proposal !== null);
};

const resolveAuthoritySourceName = async (context: AuthContext, sourceType: string, sourceId: string) => {
  if (sourceType === AUTHORITY_SOURCE_CONNECTOR) {
    const connectors = await getEntitiesListFromCache<BasicStoreEntity>(context, SYSTEM_USER, ENTITY_TYPE_CONNECTOR);
    return connectors.find((connector) => connector.internal_id === sourceId)?.name ?? null;
  }
  const [author] = await internalFindByIds<BasicStoreEntity>(context, context.user!, [sourceId]) as BasicStoreEntity[];
  return author?.name ?? null;
};

const loadSubjects = async (context: AuthContext, proposal: BasicStoreEntityCurationProposal) => {
  const loaded = await Promise.all(proposal.subject_ids.map((id, index) => context.batch?.idsBatchLoader.load({ id, type: proposal.subject_types?.[index] })));
  return loaded.filter((element): element is BasicStoreBase => !!element);
};

const knowledgeHealthMetricResolvers = Object.fromEntries(KNOWLEDGE_HEALTH_METRIC_KEYS.map((key) => [
  key,
  (snapshot: unknown) => (snapshot as BasicStoreEntityKnowledgeHealthSnapshot).health_metrics[key],
])) as Resolvers['KnowledgeHealthSnapshot'];

const curationResolvers: Resolvers = {
  Query: {
    curationProposal: (_, { id }, context) => findProposalById(context, context.user, id),
    curationProposals: (_, args, context) => findProposalsPaginated(context, context.user, args as any),
    curationProposalsForEntity: (_, { id, status }, context) => findProposalsForEntity(context, context.user, id, status as string[] | null),
    curationStatistics: (_, __, context) => curationStatistics(context, context.user),
    curationResolve: (_, { name, type }, context) => curationResolve(context, context.user, name, type),
    mergeRecord: (_, { id }, context) => findMergeRecordById(context, context.user, id),
    mergeRecords: (_, args, context) => findMergeRecordsPaginated(context, context.user, args as any),
    curationPolicy: (_, { id }, context) => findPolicyById(context, context.user, id),
    curationPolicies: (_, args, context) => findPoliciesPaginated(context, context.user, args as any),
    curationPolicyDryRun: (_, { id }, context) => dryRunCurationPolicy(context, context.user, id) as any,
    knowledgeHealth: (_, __, context) => findLatestHealthSnapshot(context, context.user),
    knowledgeHealthSnapshots: (_, args, context) => findHealthSnapshotsPaginated(context, context.user, args as any),
    curationSettings: (_, __, context) => curationSettingsForApi(context) as any,
    curationAdjudicationAvailable: (_, __, context) => isCurationAdjudicationOffered(context),
    curationAdjudicationSetup: (_, __, context) => curationAdjudicationSetup(context),
    curationAuthorityAttributes: () => curationAuthorityAttributes(schemaAttributesDefinition.registeredTypes),
  },
  CurationProposal: {
    objectMarking: (proposal, _, context) => context.batch.markingsBatchLoader.load(proposal),
    evidence: (proposal) => (proposal as unknown as BasicStoreEntityCurationProposal).curation_evidence ?? [],
    adjudication: (proposal) => ((proposal as unknown as BasicStoreEntityCurationProposal).curation_adjudication ?? null) as any,
    in_ambiguous_band: (proposal) => (proposal as unknown as BasicStoreEntityCurationProposal).in_ambiguous_band ?? false,
    action_payload: (proposal) => toJsonString((proposal as unknown as BasicStoreEntityCurationProposal).action_payload),
    applied_patch: (proposal) => toJsonString((proposal as unknown as BasicStoreEntityCurationProposal).applied_patch),
    subjects: (proposal, _, context) => loadSubjects(context, proposal as unknown as BasicStoreEntityCurationProposal) as any,
    restricted_subjects_count: async (proposal, _, context) => {
      const typed = proposal as unknown as BasicStoreEntityCurationProposal;
      const subjects = await loadSubjects(context, typed);
      return typed.subject_ids.length - subjects.length;
    },
    // Policies are read under Settings > Customization only, like the curationPolicy query.
    policy: (proposal, _, context) => {
      const { policy_id } = proposal as unknown as BasicStoreEntityCurationProposal;
      if (!policy_id || !isUserHasCapability(context.user!, SETTINGS_SETCUSTOMIZATION)) return null;
      return findPolicyById(context, context.user, policy_id) as any;
    },
    decidedBy: (proposal, _, context) => {
      const { decided_by_id } = proposal as unknown as BasicStoreEntityCurationProposal;
      return decided_by_id ? loadCreator(context, context.user, decided_by_id) : null;
    },
    mergeRecord: (proposal, _, context) => {
      const { merge_record_id } = proposal as unknown as BasicStoreEntityCurationProposal;
      return merge_record_id ? findMergeRecordById(context, context.user, merge_record_id) as any : null;
    },
    can_apply: (proposal, _, context) => canUserApplyProposal(context.user!, proposal as unknown as BasicStoreEntityCurationProposal),
    can_revert: (proposal, _, context) => {
      const typed = proposal as unknown as BasicStoreEntityCurationProposal;
      return isProposalRevertible(typed) && canUserRevertProposal(context.user!, typed);
    },
    adjudicable: (proposal) => isProposalAdjudicable(proposal as unknown as BasicStoreEntityCurationProposal),
    choice_required: (proposal) => isProposalChoiceRequired(proposal as unknown as BasicStoreEntityCurationProposal),
  },
  CurationAdjudication: {
    verified: (adjudication) => (adjudication as { verified?: boolean }).verified === true,
  },
  MergeRecord: {
    objectMarking: (record, _, context) => context.batch.markingsBatchLoader.load(record),
    target: (record, _, context) => {
      const typed = record as unknown as BasicStoreEntityMergeRecord;
      return context.batch.idsBatchLoader.load({ id: typed.merge_target_id, type: typed.merge_target_type });
    },
    sources: (record) => {
      const typed = record as unknown as BasicStoreEntityMergeRecord;
      return (typed.merge_snapshot?.sources ?? []).map((source) => ({
        id: source.internal_id,
        standard_id: source.standard_id,
        name: source.name ?? source.standard_id,
        entity_type: source.entity_type,
        aliases: [...((source.attributes?.aliases as string[]) ?? []), ...((source.attributes?.x_opencti_aliases as string[]) ?? [])],
        redirected_relationships_count: source.redirected?.length ?? 0,
        recreatable_relationships_count: source.recreatable?.length ?? 0,
        contributed_aliases: source.contributed_aliases ?? [],
        reverted_at: source.reverted_at ?? null,
      }));
    },
    alias_provenance: (record) => ((record as unknown as BasicStoreEntityMergeRecord).alias_provenance ?? []).map((provenance) => ({
      alias: provenance.alias ?? '',
      source_id: provenance.source_id,
      source_aliases: provenance.source_aliases ?? [],
      relationships_count: provenance.relationship_ids?.length ?? 0,
    })),
    is_reversible: (record) => isMergeRecordReversible(record as unknown as BasicStoreEntityMergeRecord),
    mergedBy: (record, _, context) => loadCreator(context, context.user, (record as unknown as BasicStoreEntityMergeRecord).merged_by_id),
    unmergedBy: (record, _, context) => {
      const { unmerged_by_id } = record as unknown as BasicStoreEntityMergeRecord;
      return unmerged_by_id ? loadCreator(context, context.user, unmerged_by_id) : null;
    },
  },
  CurationPolicy: {
    last_dry_run: (policy, _, context) => {
      const lastDryRun = (policy as unknown as BasicStoreEntityCurationPolicy).last_dry_run;
      // A dry run counts what its user can read: another user is never shown those counts.
      return (lastDryRun && lastDryRun.computed_by_id === context.user?.id ? lastDryRun : null) as any;
    },
  },
  CurationSettings: {
    adjudication_run_as: async (settings, _, context) => {
      const id = settings.adjudication_run_as_id;
      if (!id || !isUserHasCapability(context.user!, SETTINGS_SETCUSTOMIZATION)) return null;
      const [member] = await internalFindByIds(context, context.user!, [id]) as BasicStoreEntity[];
      return (member ?? null) as any;
    },
    authority_connector_sources: async (_, __, context) => {
      if (!isUserHasCapability(context.user!, SETTINGS_SETCUSTOMIZATION)) return [];
      const connectors = await getEntitiesListFromCache<BasicStoreEntity>(context, SYSTEM_USER, ENTITY_TYPE_CONNECTOR);
      return connectors
        .map((connector) => ({ source_type: AUTHORITY_SOURCE_CONNECTOR, source_id: connector.internal_id, source_name: connector.name }))
        .sort((left, right) => left.source_name.localeCompare(right.source_name)) as any;
    },
    digest_recipients: async (settings, _, context) => {
      if (settings.digest_recipient_ids.length === 0 || !isUserHasCapability(context.user!, SETTINGS_SETCUSTOMIZATION)) return [];
      return internalFindByIds(context, context.user!, settings.digest_recipient_ids) as any;
    },
  },
  CurationAuthoritySource: {
    source_name: (source, _, context) => source.source_name ?? resolveAuthoritySourceName(context, source.source_type, source.source_id),
  },
  CurationPolicyDryRun: {
    sample_proposals: (dryRun, _, context) => resolveSampleProposals(context, dryRun as unknown as CurationPolicyDryRunResult) as any,
  },
  KnowledgeHealthSnapshot: knowledgeHealthMetricResolvers,
  Mutation: {
    curationProposalAccept: (_, { id, input }, context) => acceptProposal(context, context.user, id, input),
    curationProposalReject: (_, { id, rationale }, context) => rejectProposal(context, context.user, id, rationale),
    curationProposalDecide: (_, { id, input }, context) => decideProposal(context, context.user, id, input as any),
    curationProposalApply: (_, { id, policy_id }, context) => applyProposalFromTask(context, context.user, id, policy_id),
    curationProposalAdjudicate: (_, { id }, context) => adjudicateProposalNow(context, context.user, id),
    curationProposalsBulkAccept: (_, { ids }, context) => bulkAcceptProposals(context, context.user, ids),
    curationProposalsBulkReject: (_, { ids, rationale }, context) => bulkRejectProposals(context, context.user, ids, rationale),
    curationProposalRevert: (_, { id }, context) => revertProposal(context, context.user, id),
    unmergeEntity: async (_, { mergeRecordId, sourceIds }, context) => {
      const result = await unmergeFromRecord(context, context.user, mergeRecordId, sourceIds);
      return result.record as any;
    },
    curationPolicyAdd: (_, { input }, context) => addCurationPolicy(context, context.user, input),
    curationPolicyFieldPatch: (_, { id, input }, context) => editCurationPolicy(context, context.user, id, input),
    curationPolicyDelete: (_, { id }, context) => deleteCurationPolicy(context, context.user, id),
    curationPolicyApply: (_, { id }, context) => applyCurationPolicyById(context, context.user, id),
    curationSettingsEdit: (_, { input }, context) => editCurationSettings(context, context.user, input as any) as any,
    curationScanRequest: (_, __, context) => requestCurationScan(context, context.user) as any,
    knowledgeHealthRefresh: (_, __, context) => refreshKnowledgeHealth(context, context.user),
  },
};

export default curationResolvers;
