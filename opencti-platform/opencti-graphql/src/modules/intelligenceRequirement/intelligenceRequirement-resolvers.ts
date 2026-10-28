import type { Resolvers } from '../../generated/graphql';
import { getAuthorizedMembers } from '../../utils/authorizedMembers';
import { getUserAccessRight } from '../../utils/access';
import { loadCreators } from '../../database/members';
import { internalFindByIds } from '../../database/middleware-loader';
import type { BasicStoreEntity } from '../../types/store';
import {
  findById,
  findIntelligenceRequirementPaginated,
  intelligenceRequirementAdd,
  intelligenceRequirementDelete,
  intelligenceRequirementStatusUpdate,
  intelligenceRequirementUpdate,
  countRequirementEntities,
  countRequirementOpenItems,
  countRequirementInbox,
  intelligenceRequirementHealthCheck,
  intelligenceRequirementBriefGenerate,
  countRequirementEntitiesByType,
  countRequirementStoredContent,
  requirementProcessingStatus,
  requirementActivity,
} from './intelligenceRequirement-domain';
import { parseIntelligenceRequirement } from './intelligenceRequirement-config';
import { findMatchesPaginated, loadMatchById, parseMatchExplanations } from './intelligenceRequirementMatch-domain';
import { findItemsPaginated, parseItemData } from './intelligenceRequirementItem-domain';
import { decideItem, decideItems, setMatchesStatus, setMatchStatus } from './intelligenceRequirement-pipeline';
import { buildRequirementAiPrompt, buildRequirementAiReference, generateRequirementAiInsight } from './intelligenceRequirement-ai';
import { previewIntelligenceRequirement } from './intelligenceRequirement-preview';
import { testIntelligenceRequirementEntity } from './intelligenceRequirement-dryrun';
import { parseMatchHistory } from './intelligenceRequirement-scoring';

const parseJson = <T>(value: string | null | undefined, fallback: T): T => {
  try {
    return value ? JSON.parse(value) : fallback;
  } catch {
    return fallback;
  }
};
import type { BasicStoreEntityIntelligenceRequirement } from './intelligenceRequirement-types';

const parsed = (ir: BasicStoreEntityIntelligenceRequirement) => parseIntelligenceRequirement(ir);

const intelligenceRequirementResolvers: Resolvers = {
  Query: {
    intelligenceRequirementPreview: (_, { input }, context) => previewIntelligenceRequirement(context, context.user, input),
    intelligenceRequirementTestEntity: (_, { input, entity_id, ir_id }, context) => testIntelligenceRequirementEntity(context, context.user, input, entity_id, ir_id),
    intelligenceRequirement: (_, { id }, context) => findById(context, context.user, id),
    intelligenceRequirements: (_, args, context) => findIntelligenceRequirementPaginated(context, context.user, args),
    intelligenceRequirementMatches: (_, { id, ...args }, context) => findMatchesPaginated(context, context.user, id, args),
    intelligenceRequirementMatch: (_, { id }, context) => loadMatchById(context, context.user, id),
    intelligenceRequirementItems: (_, { id, ...args }, context) => findItemsPaginated(context, context.user, id, args),
  },
  IntelligenceRequirement: {
    ir_brief_frequency: (ir) => ir.ir_brief_frequency ?? 'off',
    created_at: (ir) => ir.created_at ?? ir.updated_at ?? new Date(0),
    updated_at: (ir) => ir.updated_at ?? ir.created_at ?? new Date(0),
    creators: (ir, _, context) => loadCreators(context, context.user, ir),
    authorizedMembers: (ir, _, context) => getAuthorizedMembers(context, context.user, ir),
    currentUserAccessRight: (ir, _, context) => getUserAccessRight(context.user, ir),
    ir_entities_count: (ir, _, context) => countRequirementEntities(context, context.user, ir.id),
    ir_inbox_open_count: (ir, _, context) => countRequirementOpenItems(context, context.user, ir.id),
    ir_inbox_counts: (ir, _, context) => countRequirementInbox(context, context.user, ir.id),
    ir_stored_counts: (ir, _, context) => countRequirementStoredContent(context, context.user, ir.id),
    ir_processing_status: (ir, _, context) => requirementProcessingStatus(context, context.user, ir),
    ir_entities_by_type: (ir, { statuses, excluded }, context) => countRequirementEntitiesByType(context, context.user, ir.id, statuses, excluded),
    ir_ai_prompt: (ir, { language, reference_only }, context) => (reference_only
      ? buildRequirementAiReference(context, context.user, ir, language || 'English')
      : buildRequirementAiPrompt(context, context.user, ir, language || 'English')),
    ir_activity: (ir, { days }, context) => requirementActivity(context, context.user, ir.id, days ?? 30),
    // Stored as serialized JSON, exposed as typed blocks
    ir_kiqs: (ir) => parsed(ir).ir_kiqs,
    ir_subject_groups: (ir) => parsed(ir).ir_subject_groups,
    ir_scope_criteria: (ir) => parsed(ir).ir_scope_criteria,
    ir_relevance_rules: (ir) => parsed(ir).ir_relevance_rules,
    ir_thresholds: (ir) => ir.ir_thresholds ?? [],
  },
  IrSubjectGroup: {
    entities: async (group, _, context) => {
      if (!group.entity_ids?.length) return [];
      const entities = await internalFindByIds<BasicStoreEntity>(context, context.user, group.entity_ids);
      return entities as BasicStoreEntity[];
    },
  },
  IrPathCondition: {
    target_group_ids: (condition) => condition.target_group_ids ?? [],
    targets: async (condition, _, context) => {
      if (!condition.target_ids?.length) return [];
      const entities = await internalFindByIds<BasicStoreEntity>(context, context.user, condition.target_ids);
      return entities as BasicStoreEntity[];
    },
  },
  IntelligenceRequirementMatch: {
    created_at: (match) => match.created_at ?? match.match_last_fact_at ?? new Date(0),
    updated_at: (match) => match.updated_at ?? match.match_last_fact_at ?? new Date(0),
    entity: (match, _, context) => context.batch.idsBatchLoader.load({ id: match.match_entity_id, type: match.match_entity_type }),
    match_explanations: (match) => parseMatchExplanations(match),
    match_criteria_ids: (match) => match.match_criteria_ids ?? [],
    match_excluded: (match) => match.match_excluded ?? false,
    match_score: (match) => match.match_score ?? 0,
    match_score_breakdown: (match) => parseJson(match.match_score_breakdown, []),
    match_history: (match) => parseMatchHistory(match),
  },
  IntelligenceRequirementItem: {
    created_at: (item) => item.created_at ?? new Date(0),
    updated_at: (item) => item.updated_at ?? item.created_at ?? new Date(0),
    entity: (item, _, context) => (item.item_entity_id ? context.batch.idsBatchLoader.load({ id: item.item_entity_id, type: item.item_entity_type }) : null),
    match: (item, _, context) => (item.item_match_id ? loadMatchById(context, context.user, item.item_match_id) : null),
    item_data: (item) => parseItemData(item),
  },
  IrMatchExplanation: {
    anchor: (explanation, _, context) => {
      if (!explanation.anchor_id) return null;
      return context.batch.idsBatchLoader.load({ id: explanation.anchor_id, type: explanation.anchor_type });
    },
    relationship: (explanation, _, context) => {
      if (!explanation.relationship_id) return null;
      return context.batch.idsBatchLoader.load({ id: explanation.relationship_id, type: explanation.relationship_type });
    },
    container: (explanation, _, context) => {
      if (!explanation.container_id) return null;
      return context.batch.idsBatchLoader.load({ id: explanation.container_id, type: explanation.container_type });
    },
  },
  Mutation: {
    intelligenceRequirementAdd: (_, { input }, context) => intelligenceRequirementAdd(context, context.user, input),
    intelligenceRequirementUpdate: (_, { id, input }, context) => intelligenceRequirementUpdate(context, context.user, id, input),
    intelligenceRequirementStatusUpdate: (_, { id, status }, context) => intelligenceRequirementStatusUpdate(context, context.user, id, status),
    intelligenceRequirementDelete: (_, { id }, context) => intelligenceRequirementDelete(context, context.user, id),
    intelligenceRequirementItemDecide: (_, { id, decision }, context) => decideItem(context, context.user, id, decision),
    intelligenceRequirementAiInsight: (_, { id, language }, context) => generateRequirementAiInsight(context, context.user, id, language || 'English'),
    intelligenceRequirementBriefGenerate: (_, { id }, context) => intelligenceRequirementBriefGenerate(context, context.user, id),
    intelligenceRequirementHealthCheck: (_, { id }, context) => intelligenceRequirementHealthCheck(context, context.user, id),
    intelligenceRequirementItemsDecide: (_, { ids, decision }, context) => decideItems(context, context.user, ids, decision),
    intelligenceRequirementMatchesStatusUpdate: (_, { ids, status }, context) => setMatchesStatus(context, context.user, ids, status),
    intelligenceRequirementMatchStatusUpdate: (_, { id, status }, context) => setMatchStatus(context, context.user, id, status),
  },
};

export default intelligenceRequirementResolvers;
