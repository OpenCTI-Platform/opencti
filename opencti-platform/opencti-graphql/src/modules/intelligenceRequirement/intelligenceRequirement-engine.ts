import type { AuthContext, AuthUser } from '../../types/user';
import type { FilterGroup } from '../../generated/graphql';
import type { BasicStoreEntity } from '../../types/store';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { isStixMatchFilterGroup } from '../../utils/filtering/filtering-stix/stix-filtering';
import { internalFindByIds } from '../../database/middleware-loader';
import { stixLoadById } from '../../database/middleware';
import { getParentTypes } from '../../schema/schemaUtils';
import type { ParsedIntelligenceRequirement, StoreIrCriterion } from './intelligenceRequirement-types';
import type { StoreIrMatchExplanation } from './intelligenceRequirementMatch-types';
import { parseIrFilters } from './intelligenceRequirement-config';
import { listInRequirementEntityIds } from './intelligenceRequirementMatch-domain';

// Scope engine: evaluates one stream event against the entry criteria of a requirement
// and returns the entities that should enter it (with the criterion and the proof).

export interface IrCandidate {
  entity: { id: string; type: string };
  criterion: StoreIrCriterion;
  explanation: StoreIrMatchExplanation;
}

export interface IrEngineState {
  ir: ParsedIntelligenceRequirement;
  listIds: Map<string, Set<string>>; // list group id -> internal and standard ids of its anchors
  groupFilters: Map<string, FilterGroup>; // filter group id -> filters
  keywords: Map<string, string[]>; // keywords group id -> lower-cased keywords
  inRequirement: Set<string>; // internal ids of the entities already in the requirement
  stixCache: Map<string, any>;
}

const activeCriteria = (ir: ParsedIntelligenceRequirement, kind: string) => ir.ir_scope_criteria.filter((c) => c.kind === kind && c.mode !== 'off');

/**
 * Resolve what the engine needs once per batch of events: anchors of list groups,
 * filters of filter groups, keywords, and the current content of the requirement.
 */
export const buildEngineState = async (context: AuthContext, user: AuthUser, ir: ParsedIntelligenceRequirement): Promise<IrEngineState> => {
  const listIds = new Map<string, Set<string>>();
  const groupFilters = new Map<string, FilterGroup>();
  const keywords = new Map<string, string[]>();
  for (let i = 0; i < ir.ir_subject_groups.length; i += 1) {
    const group = ir.ir_subject_groups[i];
    if (group.kind === 'list') {
      const ids = new Set<string>(group.entity_ids);
      const entities = await internalFindByIds<BasicStoreEntity>(context, user, group.entity_ids) as BasicStoreEntity[];
      entities.forEach((e) => {
        ids.add(e.internal_id);
        ids.add(e.standard_id);
      });
      listIds.set(group.id, ids);
    } else if (group.kind === 'filter') {
      const filters = parseIrFilters(group.filters);
      if (filters) groupFilters.set(group.id, filters);
    } else if (group.kind === 'keywords') {
      keywords.set(group.id, group.keywords.map((k) => k.toLowerCase()));
    }
  }
  const needsContent = ir.ir_scope_criteria.some((c) => c.from_in_requirement);
  const inRequirement = needsContent ? await listInRequirementEntityIds(context, user, ir.id) : new Set<string>();
  return { ir, listIds, groupFilters, keywords, inRequirement, stixCache: new Map() };
};

const loadStix = async (context: AuthContext, user: AuthUser, state: IrEngineState, id: string) => {
  if (!state.stixCache.has(id)) {
    state.stixCache.set(id, await stixLoadById(context, user, id));
  }
  return state.stixCache.get(id);
};

export const isTypeMatching = (type: string, targetTypes: string[]) => {
  if (targetTypes.length === 0) return true;
  if (targetTypes.includes(type)) return true;
  return getParentTypes(type).some((parent: string) => targetTypes.includes(parent));
};

const matchesFilters = async (context: AuthContext, user: AuthUser, state: IrEngineState, id: string, filters: FilterGroup | null) => {
  if (!filters) return true;
  const stix = await loadStix(context, user, state, id);
  return stix ? isStixMatchFilterGroup(context, user, stix, filters) : false;
};

const isAnchor = async (context: AuthContext, user: AuthUser, state: IrEngineState, criterion: StoreIrCriterion, anchorId: string) => {
  if (criterion.from_in_requirement && state.inRequirement.has(anchorId)) return true;
  for (let i = 0; i < criterion.from_group_ids.length; i += 1) {
    const groupId = criterion.from_group_ids[i];
    if (state.listIds.get(groupId)?.has(anchorId)) return true;
    const filters = state.groupFilters.get(groupId);
    if (filters && await matchesFilters(context, user, state, anchorId, filters)) return true;
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
      if (await isAnchor(context, user, state, criterion, side.anchorId) && await isTarget(context, user, state, criterion, side.targetId, side.targetType)) {
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

const KEYWORD_FIELD_EXTRACTORS: Record<string, (stix: any) => string[]> = {
  name: (stix) => [stix.name, stix.value, ...(stix.aliases ?? []), ...(stix.x_opencti_aliases ?? [])],
  description: (stix) => [stix.description, stix.x_opencti_description],
  content: (stix) => [stix.content, stix.extensions?.[STIX_EXT_OCTI]?.content],
};

/**
 * Simple keyword search: case-insensitive substring in name (and aliases), description and content.
 * Returns the first matching keyword and field.
 */
export const findKeyword = (stix: any, keywords: string[], fields: string[]) => {
  for (let i = 0; i < fields.length; i += 1) {
    const field = fields[i];
    const texts = (KEYWORD_FIELD_EXTRACTORS[field]?.(stix) ?? []).filter((t) => typeof t === 'string' && t.length > 0).map((t: string) => t.toLowerCase());
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
export const evaluateEntity = async (context: AuthContext, user: AuthUser, state: IrEngineState, stix: any): Promise<IrCandidate[]> => {
  const ext = stix.extensions?.[STIX_EXT_OCTI];
  if (!ext?.id || !ext?.type) return [];
  const entity = { id: ext.id, type: ext.type };
  state.stixCache.set(entity.id, stix);
  const candidates: IrCandidate[] = [];
  const at = new Date().toISOString();
  // Attribute criteria
  const attributeCriteria = activeCriteria(state.ir, 'attribute');
  for (let i = 0; i < attributeCriteria.length; i += 1) {
    const criterion = attributeCriteria[i];
    if (await isTarget(context, user, state, criterion, entity.id, entity.type)) {
      candidates.push({ entity, criterion, explanation: { criterion_id: criterion.id, kind: 'attribute', at } });
    }
  }
  // Keyword criteria
  const keywordCriteria = activeCriteria(state.ir, 'keywords');
  for (let i = 0; i < keywordCriteria.length; i += 1) {
    const criterion = keywordCriteria[i];
    const keywords = criterion.from_group_ids.flatMap((gid) => state.keywords.get(gid) ?? []);
    const hit = keywords.length > 0 ? findKeyword(stix, keywords, criterion.keyword_fields) : null;
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
