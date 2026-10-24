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
} from './intelligenceRequirement-domain';
import { parseIntelligenceRequirement } from './intelligenceRequirement-config';
import { findMatchesPaginated, loadMatchById, parseMatchExplanations } from './intelligenceRequirementMatch-domain';
import { findItemsPaginated, parseItemData } from './intelligenceRequirementItem-domain';
import { decideItem, setMatchStatus } from './intelligenceRequirement-pipeline';

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
    intelligenceRequirement: (_, { id }, context) => findById(context, context.user, id),
    intelligenceRequirements: (_, args, context) => findIntelligenceRequirementPaginated(context, context.user, args),
    intelligenceRequirementMatches: (_, { id, ...args }, context) => findMatchesPaginated(context, context.user, id, args),
    intelligenceRequirementItems: (_, { id, ...args }, context) => findItemsPaginated(context, context.user, id, args),
  },
  IntelligenceRequirement: {
    created_at: (ir) => ir.created_at ?? ir.updated_at ?? new Date(0),
    updated_at: (ir) => ir.updated_at ?? ir.created_at ?? new Date(0),
    creators: (ir, _, context) => loadCreators(context, context.user, ir),
    authorizedMembers: (ir, _, context) => getAuthorizedMembers(context, context.user, ir),
    currentUserAccessRight: (ir, _, context) => getUserAccessRight(context.user, ir),
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
    intelligenceRequirementMatchStatusUpdate: (_, { id, status }, context) => setMatchStatus(context, context.user, id, status),
  },
};

export default intelligenceRequirementResolvers;
