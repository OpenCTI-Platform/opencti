import type { AuthContext, AuthUser } from '../../types/user';
import { type EntityOptions, fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { createEntity, internalDeleteElementById, patchAttribute } from '../../database/middleware';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { enforceEnableFeatureFlag } from '../../utils/access';
import { INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG } from '../../config/conf';
import type { FilterGroup } from '../../generated/graphql';
import {
  type BasicStoreEntityIntelligenceRequirementMatch,
  ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH,
  IR_MATCH_IN_STATUSES,
  isInRequirement,
  type StoreIrMatchExplanation,
} from './intelligenceRequirementMatch-types';
import type { StoreIrCriterion } from './intelligenceRequirement-types';
import { entityDisplayName } from './intelligenceRequirementItem-domain';
import { isRequirementDeleted } from './intelligenceRequirement-lifecycle';

const MAX_EXPLANATIONS = 20;

const matchFilters = (irId: string, entityId?: string, statuses?: string[], filters?: FilterGroup | null) => {
  let finalFilters = addFilter(filters, 'ir_id', irId);
  if (entityId) finalFilters = addFilter(finalFilters, 'match_entity_id', entityId);
  if (statuses) finalFilters = addFilter(finalFilters, 'match_status', statuses);
  return finalFilters;
};

export const parseMatchExplanations = (match: BasicStoreEntityIntelligenceRequirementMatch): StoreIrMatchExplanation[] => {
  try {
    const parsed = JSON.parse(match.match_explanations ?? '[]');
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
};

export const findMatchesPaginated = async (
  context: AuthContext,
  user: AuthUser,
  irId: string,
  opts: EntityOptions<BasicStoreEntityIntelligenceRequirementMatch> & { statuses?: string[] | null } = {},
) => {
  enforceEnableFeatureFlag(INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG);
  const { statuses, search, ...listOpts } = opts;
  let filters = matchFilters(irId, undefined, statuses ?? undefined, listOpts.filters);
  // Search by entity name (the match itself has no other text)
  if (search) filters = addFilter(filters, 'match_entity_name', search, 'contains');
  return pageEntitiesConnection<BasicStoreEntityIntelligenceRequirementMatch>(context, user, [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH], { ...listOpts, filters });
};

export const loadMatch = async (context: AuthContext, user: AuthUser, irId: string, entityId: string) => {
  const matches = await fullEntitiesList<BasicStoreEntityIntelligenceRequirementMatch>(context, user, [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH], {
    filters: matchFilters(irId, entityId),
  });
  return matches.length > 0 ? matches[0] : null;
};

export const listMatches = async (context: AuthContext, user: AuthUser, irId: string, statuses?: string[]) => {
  return fullEntitiesList<BasicStoreEntityIntelligenceRequirementMatch>(context, user, [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH], {
    filters: matchFilters(irId, undefined, statuses),
  });
};

// Entities that are part of the requirement (used as starting point of "second hop" criteria)
export const listInRequirementEntityIds = async (context: AuthContext, user: AuthUser, irId: string) => {
  const matches = await listMatches(context, user, irId, IR_MATCH_IN_STATUSES);
  return new Set(matches.filter(isInRequirement).map((m) => m.match_entity_id));
};

const ENTITY_LOOKUP_CHUNK = 500;

// The stored matches of these entities only (whatever their status): what a batch of events touches
export const listMatchesForEntities = async (context: AuthContext, user: AuthUser, irId: string, entityIds: string[]) => {
  const matches: BasicStoreEntityIntelligenceRequirementMatch[] = [];
  for (let i = 0; i < entityIds.length; i += ENTITY_LOOKUP_CHUNK) {
    const chunk = entityIds.slice(i, i + ENTITY_LOOKUP_CHUNK);
    matches.push(...await fullEntitiesList<BasicStoreEntityIntelligenceRequirementMatch>(context, user, [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH], {
      filters: addFilter(addFilter(undefined, 'ir_id', irId), 'match_entity_id', chunk),
    }));
  }
  return matches;
};

/**
 * Starting points of the second hop, kept in memory between batches (this node): loaded once, then kept up to date
 * by the engine as entities enter or leave. Reloaded after an analyst decision or a change of configuration,
 * and after a while in any case (another node may have changed the requirement).
 */
const IN_REQUIREMENT_TTL = 5 * 60 * 1000;
const inRequirementCache = new Map<string, { at: number; ids: Set<string> }>();

export const getInRequirementEntityIds = async (context: AuthContext, user: AuthUser, irId: string) => {
  const cached = inRequirementCache.get(irId);
  if (cached && Date.now() - cached.at < IN_REQUIREMENT_TTL) return cached.ids;
  const ids = await listInRequirementEntityIds(context, user, irId);
  inRequirementCache.set(irId, { at: Date.now(), ids });
  return ids;
};

export const invalidateInRequirementEntityIds = (irId: string) => {
  inRequirementCache.delete(irId);
};

const sameExplanation = (a: StoreIrMatchExplanation, b: StoreIrMatchExplanation) => a.criterion_id === b.criterion_id
  && a.relationship_id === b.relationship_id
  && a.anchor_id === b.anchor_id
  && a.keyword === b.keyword
  && a.container_id === b.container_id;

export interface UpsertMatchResult {
  match: BasicStoreEntityIntelligenceRequirementMatch;
  created: boolean;
  previousStatus: string | null;
}

/**
 * An entity matched an entry criterion: create its match (auto or proposed, depending on the criterion mode)
 * or add the criterion and its proof to the existing match.
 * Rejected and removed matches are not resurrected.
 * admit: checked before creating a match (the conditions of the scope); a candidate it refuses is not stored.
 */
export const upsertMatch = async (
  context: AuthContext,
  user: AuthUser,
  irId: string,
  entity: { id: string; type: string },
  criterion: StoreIrCriterion,
  explanation: StoreIrMatchExplanation,
  admit?: () => Promise<boolean>,
): Promise<UpsertMatchResult | null> => {
  if (isRequirementDeleted(irId)) return null;
  const existing = await loadMatch(context, user, irId, entity.id);
  const now = new Date();
  if (!existing) {
    if (admit && !await admit()) return null;
    const input = {
      ir_id: irId,
      match_entity_id: entity.id,
      match_entity_type: entity.type,
      match_entity_name: await entityDisplayName(context, user, entity.id),
      match_status: criterion.mode === 'auto' ? 'auto' : 'proposed',
      match_criteria_ids: [criterion.id],
      match_explanations: JSON.stringify([explanation]),
      match_score: 0,
      match_score_breakdown: '[]',
      match_excluded: false,
      match_last_fact_at: now,
      created_at: now,
      updated_at: now,
    };
    const created = await createEntity(context, user, input, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH);
    return { match: created as BasicStoreEntityIntelligenceRequirementMatch, created: true, previousStatus: null };
  }
  if (existing.match_status === 'rejected' || existing.match_status === 'removed') {
    return null;
  }
  const explanations = parseMatchExplanations(existing);
  const isNewProof = !explanations.some((e) => sameExplanation(e, explanation));
  const criteriaIds = Array.from(new Set([...(existing.match_criteria_ids ?? []), criterion.id]));
  // A proposed entity becomes automatic if it now also matches an automatic criterion
  const status = existing.match_status === 'proposed' && criterion.mode === 'auto' ? 'auto' : existing.match_status;
  const patch = {
    ...(existing.match_entity_name ? {} : { match_entity_name: await entityDisplayName(context, user, entity.id) }),
    match_criteria_ids: criteriaIds,
    match_explanations: JSON.stringify(isNewProof ? [explanation, ...explanations].slice(0, MAX_EXPLANATIONS) : explanations),
    match_status: status,
    match_last_fact_at: now,
  };
  const { element } = await patchAttribute(context, user, existing.id, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH, patch);
  return { match: element as unknown as BasicStoreEntityIntelligenceRequirementMatch, created: false, previousStatus: existing.match_status };
};

export const loadMatchById = async (context: AuthContext, user: AuthUser, matchId: string) => {
  return storeLoadById<BasicStoreEntityIntelligenceRequirementMatch>(context, user, matchId, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH);
};

// An entity that leaves the requirement (it no longer meets the conditions of the scope): nothing is kept for it
export const deleteMatch = async (context: AuthContext, user: AuthUser, matchId: string) => {
  await internalDeleteElementById(context, user, matchId, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH);
};

export const updateMatchStatus = async (context: AuthContext, user: AuthUser, matchId: string, status: string) => {
  const { element } = await patchAttribute(context, user, matchId, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH, { match_status: status });
  return element as unknown as BasicStoreEntityIntelligenceRequirementMatch;
};

// Entity names of the matches created before the name was stored (search and sort by name)
export const backfillMatchEntityNames = async (context: AuthContext, user: AuthUser, irId: string) => {
  const missing = await fullEntitiesList<BasicStoreEntityIntelligenceRequirementMatch>(context, user, [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH], {
    filters: addFilter(addFilter(undefined, 'ir_id', irId), 'match_entity_name', [], 'nil'),
  });
  for (let i = 0; i < missing.length; i += 1) {
    const match = missing[i];
    await patchAttribute(context, user, match.id, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH, { match_entity_name: await entityDisplayName(context, user, match.match_entity_id) });
  }
  return missing.length;
};
