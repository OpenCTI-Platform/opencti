import type { AuthContext, AuthUser } from '../../types/user';
import type { FilterGroup } from '../../generated/graphql';
import type { BasicStoreEntity, BasicStoreRelation } from '../../types/store';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { fullRelationsList, internalFindByIds, pageEntitiesConnection } from '../../database/middleware-loader';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { IDS_FILTER } from '../../utils/filtering/filtering-constants';
import { getParentTypes } from '../../schema/schemaUtils';
import type { ParsedIntelligenceRequirement, StoreIrCriterion } from './intelligenceRequirement-types';
import type { StoreIrMatchExplanation } from './intelligenceRequirementMatch-types';
import { parseIrFilters } from './intelligenceRequirement-config';
import { listInRequirementEntityIds } from './intelligenceRequirementMatch-domain';
import { resolveSubjectGroup } from './intelligenceRequirement-groups';

// Scope engine: evaluates one stream event against the entry criteria of a requirement
// and returns the entities that should enter it (with the criterion and the proof).

export interface IrCandidate {
  entity: { id: string; type: string };
  criterion: StoreIrCriterion;
  explanation: StoreIrMatchExplanation;
}

export interface IrEngineState {
  ir: ParsedIntelligenceRequirement;
  listIds: Map<string, Set<string>>; // list or filter group id -> internal and standard ids of its anchors
  keywords: Map<string, string[]>; // keywords group id -> lower-cased keywords
  excludedKeywords: Map<string, string[]>; // keywords group id -> lower-cased phrases removed from the texts before the search
  inRequirement: Set<string>; // internal ids of the entities already in the requirement
  filterCache: Map<string, boolean>; // (entity, filters) -> result of the search engine
}

const activeCriteria = (ir: ParsedIntelligenceRequirement, kind: string) => ir.ir_scope_criteria.filter((c) => c.kind === kind && c.mode !== 'off');

/**
 * Resolve what the engine needs once per batch of events: anchors of list groups,
 * filters of filter groups, keywords, and the current content of the requirement.
 */
export const buildEngineState = async (context: AuthContext, user: AuthUser, ir: ParsedIntelligenceRequirement): Promise<IrEngineState> => {
  const listIds = new Map<string, Set<string>>();
  const keywords = new Map<string, string[]>();
  const excludedKeywords = new Map<string, string[]>();
  for (let i = 0; i < ir.ir_subject_groups.length; i += 1) {
    const group = ir.ir_subject_groups[i];
    if (group.kind === 'list' || group.kind === 'filter') {
      // A dynamic group is resolved by the search engine: any OpenCTI filter key can be used (malware types, labels...)
      listIds.set(group.id, (await resolveSubjectGroup(context, user, group)).allIds);
    } else if (group.kind === 'keywords') {
      keywords.set(group.id, group.keywords.map((k) => k.toLowerCase()));
      excludedKeywords.set(group.id, (group.exclude_keywords ?? []).map((k) => k.toLowerCase()));
    }
  }
  const needsContent = ir.ir_scope_criteria.some((c) => c.from_in_requirement);
  const inRequirement = needsContent ? await listInRequirementEntityIds(context, user, ir.id) : new Set<string>();
  return { ir, listIds, keywords, excludedKeywords, inRequirement, filterCache: new Map() };
};

/**
 * Filters are evaluated by the search engine on the stored entity, so every OpenCTI filter key is supported.
 */
export const isEntityMatchingFilters = async (context: AuthContext, user: AuthUser, entityId: string, filters: FilterGroup | null) => {
  if (!filters) return true;
  const result = await pageEntitiesConnection(context, user, [ABSTRACT_STIX_CORE_OBJECT], { first: 1, filters: addFilter(filters, IDS_FILTER, entityId) });
  return result.edges.length > 0;
};

export const isTypeMatching = (type: string, targetTypes: string[]) => {
  if (targetTypes.length === 0) return true;
  if (targetTypes.includes(type)) return true;
  return getParentTypes(type).some((parent: string) => targetTypes.includes(parent));
};

const matchesFilters = async (context: AuthContext, user: AuthUser, state: IrEngineState, id: string, filters: FilterGroup | null) => {
  if (!filters) return true;
  const key = `${id}|${JSON.stringify(filters)}`;
  if (!state.filterCache.has(key)) {
    state.filterCache.set(key, await isEntityMatchingFilters(context, user, id, filters));
  }
  return state.filterCache.get(key) as boolean;
};

const isAnchor = async (context: AuthContext, user: AuthUser, state: IrEngineState, criterion: StoreIrCriterion, anchorId: string, anchorType: string) => {
  if ((criterion.from_types ?? []).length > 0 && !isTypeMatching(anchorType, criterion.from_types ?? [])) return false;
  if (criterion.from_in_requirement && state.inRequirement.has(anchorId)) return true;
  for (let i = 0; i < criterion.from_group_ids.length; i += 1) {
    const groupId = criterion.from_group_ids[i];
    if (state.listIds.get(groupId)?.has(anchorId)) return true;
  }
  return false;
};

const isTarget = async (context: AuthContext, user: AuthUser, state: IrEngineState, criterion: StoreIrCriterion, id: string, type: string) => {
  if (!isTypeMatching(type, criterion.target_types)) return false;
  return matchesFilters(context, user, state, id, parseIrFilters(criterion.target_filters));
};

/**
 * A relationship was created or updated: graph criteria.
 * (anchor) —relationship→ (target) for outgoing, (target) —relationship→ (anchor) for incoming.
 */
export const evaluateRelationship = async (context: AuthContext, user: AuthUser, state: IrEngineState, stix: any): Promise<IrCandidate[]> => {
  const ext = stix.extensions?.[STIX_EXT_OCTI];
  if (!ext?.source_ref || !ext?.target_ref) return [];
  const relationshipType = stix.relationship_type;
  const candidates: IrCandidate[] = [];
  const criteria = activeCriteria(state.ir, 'graph').filter((c) => c.relationship_types.includes(relationshipType));
  for (let i = 0; i < criteria.length; i += 1) {
    const criterion = criteria[i];
    const sides = [];
    if (criterion.direction === 'outgoing' || criterion.direction === 'both') {
      sides.push({ anchorId: ext.source_ref, anchorType: ext.source_type, targetId: ext.target_ref, targetType: ext.target_type, direction: 'outgoing' });
    }
    if (criterion.direction === 'incoming' || criterion.direction === 'both') {
      sides.push({ anchorId: ext.target_ref, anchorType: ext.target_type, targetId: ext.source_ref, targetType: ext.source_type, direction: 'incoming' });
    }
    for (let j = 0; j < sides.length; j += 1) {
      const side = sides[j];
      if (await isAnchor(context, user, state, criterion, side.anchorId, side.anchorType) && await isTarget(context, user, state, criterion, side.targetId, side.targetType)) {
        candidates.push({
          entity: { id: side.targetId, type: side.targetType },
          criterion,
          explanation: {
            criterion_id: criterion.id,
            kind: 'graph',
            at: new Date().toISOString(),
            anchor_id: side.anchorId,
            anchor_type: side.anchorType,
            relationship_id: ext.id,
            relationship_type: relationshipType,
            direction: side.direction,
          },
        });
      }
    }
  }
  return candidates;
};

export const IR_CONTAINS_RELATIONSHIP = 'object';
const BACKFILL_MAX_RELATIONS_PER_CRITERION = 1000;

/**
 * Backfill: an entity just entered the requirement. Its relationships that already exist are evaluated
 * against the second hop criteria (from the entities already in the requirement), as if they had just been created.
 * The "object" relationship (container content) is a meta relationship and is read the same way.
 */
export const evaluateExistingRelationships = async (context: AuthContext, user: AuthUser, state: IrEngineState, anchor: { id: string; type: string }) => {
  const criteria = activeCriteria(state.ir, 'graph')
    .filter((c) => c.from_in_requirement && ((c.from_types ?? []).length === 0 || isTypeMatching(anchor.type, c.from_types ?? [])));
  const candidates: IrCandidate[] = [];
  const at = new Date().toISOString();
  for (let i = 0; i < criteria.length; i += 1) {
    const criterion = criteria[i];
    const sides: { direction: string; args: { fromId?: string; toId?: string } }[] = [];
    if (criterion.direction === 'outgoing' || criterion.direction === 'both') sides.push({ direction: 'outgoing', args: { fromId: anchor.id } });
    if (criterion.direction === 'incoming' || criterion.direction === 'both') sides.push({ direction: 'incoming', args: { toId: anchor.id } });
    for (let j = 0; j < sides.length; j += 1) {
      const side = sides[j];
      const relations = await fullRelationsList<BasicStoreRelation>(context, user, criterion.relationship_types, side.args);
      const limited = relations.slice(0, BACKFILL_MAX_RELATIONS_PER_CRITERION);
      for (let k = 0; k < limited.length; k += 1) {
        const relation = limited[k];
        const target = side.direction === 'outgoing' ? { id: relation.toId, type: relation.toType } : { id: relation.fromId, type: relation.fromType };
        if (await isTarget(context, user, state, criterion, target.id, target.type)) {
          candidates.push({
            entity: target,
            criterion,
            explanation: {
              criterion_id: criterion.id,
              kind: 'graph',
              at,
              anchor_id: anchor.id,
              anchor_type: anchor.type,
              relationship_id: relation.relationship_type === IR_CONTAINS_RELATIONSHIP ? undefined : relation.internal_id,
              relationship_type: relation.relationship_type ?? relation.entity_type,
              direction: side.direction,
            },
          });
        }
      }
    }
  }
  return candidates;
};

/**
 * A container (report, grouping, note, case...) was created or updated: graph criteria with the "object" relationship.
 * incoming: a contained entity is a subject, the container enters. outgoing: the container is a subject, its contained entities enter.
 */
const evaluateContainer = async (context: AuthContext, user: AuthUser, state: IrEngineState, stix: any, container: { id: string; type: string }, at: string) => {
  const objectRefs: string[] = stix.object_refs ?? [];
  const criteria = activeCriteria(state.ir, 'graph').filter((c) => c.relationship_types.includes(IR_CONTAINS_RELATIONSHIP));
  if (objectRefs.length === 0 || criteria.length === 0) return [];
  const objects = await internalFindByIds<BasicStoreEntity>(context, user, objectRefs) as BasicStoreEntity[];
  const candidates: IrCandidate[] = [];
  for (let i = 0; i < criteria.length; i += 1) {
    const criterion = criteria[i];
    const explanation = (anchor: { id: string; type: string }, direction: string) => ({
      criterion_id: criterion.id,
      kind: 'graph',
      at,
      anchor_id: anchor.id,
      anchor_type: anchor.type,
      relationship_type: IR_CONTAINS_RELATIONSHIP,
      direction,
    });
    if (criterion.direction === 'incoming' || criterion.direction === 'both') {
      for (let j = 0; j < objects.length; j += 1) {
        const object = { id: objects[j].internal_id, type: objects[j].entity_type };
        if (await isAnchor(context, user, state, criterion, object.id, object.type) && await isTarget(context, user, state, criterion, container.id, container.type)) {
          candidates.push({ entity: container, criterion, explanation: explanation(object, 'incoming') });
          break; // one proof per container is enough
        }
      }
    }
    if ((criterion.direction === 'outgoing' || criterion.direction === 'both') && await isAnchor(context, user, state, criterion, container.id, container.type)) {
      for (let j = 0; j < objects.length; j += 1) {
        const object = { id: objects[j].internal_id, type: objects[j].entity_type };
        if (await isTarget(context, user, state, criterion, object.id, object.type)) {
          candidates.push({ entity: object, criterion, explanation: explanation(container, 'outgoing') });
        }
      }
    }
  }
  return candidates;
};

const KEYWORD_FIELD_EXTRACTORS: Record<string, (stix: any) => string[]> = {
  name: (stix) => [stix.name, stix.value, ...(stix.aliases ?? []), ...(stix.x_opencti_aliases ?? [])],
  description: (stix) => [stix.description, stix.x_opencti_description],
  content: (stix) => [stix.content, stix.extensions?.[STIX_EXT_OCTI]?.content],
};

/**
 * Simple keyword search: case-insensitive substring in name (and aliases), description and content.
 * Returns the first matching keyword and field.
 */
export const findKeyword = (stix: any, keywords: string[], fields: string[], excluded: string[] = []) => {
  // An excluded phrase (e.g. "targets russia") is removed from the text first: the keyword must appear elsewhere
  const strip = (text: string) => excluded.reduce((t, phrase) => (phrase ? t.split(phrase).join(' ') : t), text);
  for (let i = 0; i < fields.length; i += 1) {
    const field = fields[i];
    const texts = (KEYWORD_FIELD_EXTRACTORS[field]?.(stix) ?? []).filter((t) => typeof t === 'string' && t.length > 0).map((t: string) => strip(t.toLowerCase()));
    for (let j = 0; j < keywords.length; j += 1) {
      if (texts.some((t) => t.includes(keywords[j]))) return { keyword: keywords[j], field };
    }
  }
  return null;
};

/**
 * An entity was created or updated: attribute criteria (zero hop) and keyword criteria.
 * When the keyword is found in a container, the contained objects are the candidates.
 */
/**
 * Member of one of the subject groups: listed in a list group, or selected by the dynamic filter of a filter group.
 * The filter is evaluated on the entity now, so an entity that has just been labelled enters at once.
 */
const isGroupMember = async (context: AuthContext, user: AuthUser, state: IrEngineState, groupIds: string[], id: string) => {
  for (let i = 0; i < groupIds.length; i += 1) {
    const group = state.ir.ir_subject_groups.find((g) => g.id === groupIds[i]);
    if (group?.kind === 'list' && state.listIds.get(group.id)?.has(id)) return true;
    if (group?.kind === 'filter' && await matchesFilters(context, user, state, id, parseIrFilters(group.filters))) return true;
  }
  return false;
};

export const evaluateEntity = async (context: AuthContext, user: AuthUser, state: IrEngineState, stix: any): Promise<IrCandidate[]> => {
  const ext = stix.extensions?.[STIX_EXT_OCTI];
  if (!ext?.id || !ext?.type) return [];
  const entity = { id: ext.id, type: ext.type };
  const candidates: IrCandidate[] = [];
  const at = new Date().toISOString();
  // Attribute criteria (zero hop), possibly "the members of these subject groups"
  const attributeCriteria = activeCriteria(state.ir, 'attribute');
  for (let i = 0; i < attributeCriteria.length; i += 1) {
    const criterion = attributeCriteria[i];
    // The type first: it costs nothing, while the membership of a dynamic group is a query
    if (!isTypeMatching(entity.type, criterion.target_types)) continue;
    if (criterion.from_group_ids.length > 0 && !await isGroupMember(context, user, state, criterion.from_group_ids, entity.id)) continue;
    if (await isTarget(context, user, state, criterion, entity.id, entity.type)) {
      candidates.push({ entity, criterion, explanation: { criterion_id: criterion.id, kind: 'attribute', at } });
    }
  }
  // Graph criteria on the content of a container: (container) —object→ (contained entity)
  candidates.push(...await evaluateContainer(context, user, state, stix, entity, at));
  // Keyword criteria
  const keywordCriteria = activeCriteria(state.ir, 'keywords');
  for (let i = 0; i < keywordCriteria.length; i += 1) {
    const criterion = keywordCriteria[i];
    const keywords = criterion.from_group_ids.flatMap((gid) => state.keywords.get(gid) ?? []);
    const excluded = criterion.from_group_ids.flatMap((gid) => state.excludedKeywords.get(gid) ?? []);
    const hit = keywords.length > 0 ? findKeyword(stix, keywords, criterion.keyword_fields, excluded) : null;
    if (hit) {
      const objectRefs: string[] = stix.object_refs ?? [];
      if (objectRefs.length > 0) {
        const objects = await internalFindByIds<BasicStoreEntity>(context, user, objectRefs) as BasicStoreEntity[];
        for (let j = 0; j < objects.length; j += 1) {
          const object = objects[j];
          if (await isTarget(context, user, state, criterion, object.internal_id, object.entity_type)) {
            candidates.push({
              entity: { id: object.internal_id, type: object.entity_type },
              criterion,
              explanation: { criterion_id: criterion.id, kind: 'keywords', at, keyword: hit.keyword, field: hit.field, container_id: entity.id, container_type: entity.type },
            });
          }
        }
      }
      if (await isTarget(context, user, state, criterion, entity.id, entity.type)) {
        candidates.push({ entity, criterion, explanation: { criterion_id: criterion.id, kind: 'keywords', at, keyword: hit.keyword, field: hit.field } });
      }
    }
  }
  return candidates;
};
