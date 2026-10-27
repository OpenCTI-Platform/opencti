import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity, BasicStoreRelation } from '../../types/store';
import type { FilterGroup, IntelligenceRequirementInput } from '../../generated/graphql';
import { internalFindByIds, pageEntitiesConnection, pageRelationsConnection } from '../../database/middleware-loader';
import { extractEntityRepresentativeName } from '../../database/entity-representative';
import { checkStixCoreRelationshipMapping } from '../../database/stix';
import { enforceEnableFeatureFlag } from '../../utils/access';
import { INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG } from '../../config/conf';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import { normalizeIntelligenceRequirementInput, parseIrFilters, typesOverlap, validateIntelligenceRequirementConfig } from './intelligenceRequirement-config';
import type { StoreIrCriterion, StoreIrSubjectGroup } from './intelligenceRequirement-types';

// Preview of a requirement configuration before saving it (AI assisted creation, review screen):
// blocking errors, resolution of the subjects, what each scope criterion would bring today, warnings.

const MAX_ANCHORS = 500;
const SHORT_KEYWORD = 4;
const IR_CONTAINS_RELATIONSHIP = 'object';

interface PreviewEntity { id: string; name: string; entity_type: string }
interface PreviewGroup { id: string; name: string; kind: string; entities: PreviewEntity[]; unresolved_ids: string[]; matching_count: number | null }
interface PreviewCriterion { id: string; name: string; kind: string; today_count: number | null; note: string | null; warnings: string[] }

const errorMessage = (e: unknown) => {
  const error = e as { message?: string; data?: Record<string, unknown> };
  const details = error.data ? Object.entries(error.data).filter(([k]) => !['http_status', 'genre'].includes(k)).map(([k, v]) => `${k}: ${String(v)}`).join(', ') : '';
  return `${error.message ?? String(e)}${details ? ` (${details})` : ''}`;
};

const entityTypesOfFilter = (filters: FilterGroup | null): string[] => {
  const types = (filters?.filters ?? []).filter((f) => (Array.isArray(f.key) ? f.key : [f.key]).includes('entity_type')).flatMap((f) => (f.values ?? []) as string[]);
  return Array.from(new Set(types));
};

// Is the relationship allowed by the schema between one of the anchor types and one of the target types, in this direction?
const relationAllowed = (relationshipType: string, fromTypes: string[], toTypes: string[]) => fromTypes.some((from) => toTypes.some((to) => {
  try {
    return checkStixCoreRelationshipMapping(from, to, relationshipType);
  } catch {
    return true; // unknown pair: do not warn
  }
}));

export const previewIntelligenceRequirement = async (context: AuthContext, user: AuthUser, input: IntelligenceRequirementInput) => {
  enforceEnableFeatureFlag(INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG);
  const errors: string[] = [];
  const warnings: string[] = [];
  const config = normalizeIntelligenceRequirementInput(input);
  try {
    validateIntelligenceRequirementConfig(config);
  } catch (e) {
    errors.push(errorMessage(e));
  }
  // Subjects: resolution of the listed entities, size of the dynamic groups
  const anchorsByGroup = new Map<string, PreviewEntity[]>();
  const groups: PreviewGroup[] = [];
  for (let i = 0; i < config.groups.length; i += 1) {
    const group: StoreIrSubjectGroup = config.groups[i];
    const preview: PreviewGroup = { id: group.id, name: group.name, kind: group.kind, entities: [], unresolved_ids: [], matching_count: null };
    if (group.kind === 'list') {
      const found = await internalFindByIds<BasicStoreEntity>(context, user, group.entity_ids) as BasicStoreEntity[];
      preview.entities = found.map((e) => ({ id: e.internal_id, name: extractEntityRepresentativeName(e), entity_type: e.entity_type }));
      const known = new Set(found.flatMap((e) => [e.internal_id, e.standard_id, ...(e.x_opencti_stix_ids ?? [])]));
      preview.unresolved_ids = group.entity_ids.filter((id) => !known.has(id));
      preview.matching_count = preview.entities.length;
      if (preview.unresolved_ids.length > 0) warnings.push(`Subject group "${group.name}": ${preview.unresolved_ids.length} entity id(s) not found in the platform.`);
    }
    if (group.kind === 'filter') {
      const filters = parseIrFilters(group.filters);
      const types = entityTypesOfFilter(filters);
      const page = await pageEntitiesConnection<BasicStoreEntity>(context, user, types.length > 0 ? types : [ABSTRACT_STIX_CORE_OBJECT], { filters, first: MAX_ANCHORS });
      preview.entities = page.edges.map(({ node }) => ({ id: node.internal_id, name: extractEntityRepresentativeName(node), entity_type: node.entity_type }));
      preview.matching_count = page.pageInfo.globalCount ?? preview.entities.length;
      if (preview.matching_count === 0) warnings.push(`Subject group "${group.name}": its filter matches no entity today.`);
    }
    if (group.kind === 'keywords') {
      const short = group.keywords.filter((k) => k.length < SHORT_KEYWORD);
      if (short.length > 0) warnings.push(`Subject group "${group.name}": short keywords (${short.join(', ')}) match inside many words and may bring noise.`);
    }
    anchorsByGroup.set(group.id, preview.entities);
    groups.push(preview);
  }
  // Scope criteria: what each one would bring today
  const criteria: PreviewCriterion[] = [];
  const linkedCriteria = new Set(config.kiqs.flatMap((k) => k.criteria_ids));
  for (let i = 0; i < config.criteria.length; i += 1) {
    const criterion: StoreIrCriterion = config.criteria[i];
    const preview: PreviewCriterion = { id: criterion.id, name: criterion.name, kind: criterion.kind, today_count: null, note: null, warnings: [] };
    const targetTypes = criterion.target_types.length > 0 ? criterion.target_types : [ABSTRACT_STIX_CORE_OBJECT];
    try {
      if (criterion.kind === 'graph') {
        const anchors = criterion.from_group_ids.flatMap((gid) => anchorsByGroup.get(gid) ?? []).slice(0, MAX_ANCHORS);
        const anchorTypes = Array.from(new Set([...anchors.map((a) => a.entity_type), ...(criterion.from_types ?? [])]));
        // Schema consistency of each relationship type with the direction
        const relationshipTypes = criterion.relationship_types.filter((r) => r !== IR_CONTAINS_RELATIONSHIP);
        if (anchorTypes.length > 0 && criterion.target_types.length > 0) {
          relationshipTypes.forEach((relationshipType) => {
            const outgoing = relationAllowed(relationshipType, anchorTypes, criterion.target_types);
            const incoming = relationAllowed(relationshipType, criterion.target_types, anchorTypes);
            if (criterion.direction === 'outgoing' && !outgoing) {
              preview.warnings.push(incoming
                ? `"${relationshipType}" never goes from ${anchorTypes.join('/')} to ${criterion.target_types.join('/')}: the direction should be incoming.`
                : `"${relationshipType}" is not allowed between ${anchorTypes.join('/')} and ${criterion.target_types.join('/')}.`);
            }
            if (criterion.direction === 'incoming' && !incoming) {
              preview.warnings.push(outgoing
                ? `"${relationshipType}" never goes from ${criterion.target_types.join('/')} to ${anchorTypes.join('/')}: the direction should be outgoing.`
                : `"${relationshipType}" is not allowed between ${criterion.target_types.join('/')} and ${anchorTypes.join('/')}.`);
            }
            if (criterion.direction === 'both' && !incoming && !outgoing) {
              preview.warnings.push(`"${relationshipType}" is not allowed between ${anchorTypes.join('/')} and ${criterion.target_types.join('/')}.`);
            }
          });
        }
        if (criterion.from_in_requirement && criterion.from_group_ids.length === 0) {
          preview.note = 'Second hop: counted once entities enter the requirement (their existing relationships are then backfilled).';
        } else if (anchors.length === 0) {
          preview.today_count = 0;
          preview.note = 'No subject entity to start from today.';
        } else {
          const ids = anchors.map((a) => a.id);
          let total = 0;
          const sides: { fromId?: string[]; toId?: string[]; fromTypes?: string[]; toTypes?: string[] }[] = [];
          if (criterion.direction !== 'incoming') sides.push({ fromId: ids, toTypes: criterion.target_types.length > 0 ? criterion.target_types : undefined });
          if (criterion.direction !== 'outgoing') sides.push({ toId: ids, fromTypes: criterion.target_types.length > 0 ? criterion.target_types : undefined });
          for (let s = 0; s < sides.length; s += 1) {
            const page = await pageRelationsConnection<BasicStoreRelation>(context, user, criterion.relationship_types, { ...sides[s], first: 1 });
            total += page.pageInfo.globalCount ?? 0;
          }
          preview.today_count = total;
          preview.note = `${total} matching relationship(s) today${criterion.from_in_requirement ? ', plus the second hop once entities enter' : ''}.`;
        }
      }
      if (criterion.kind === 'attribute' && criterion.from_group_ids.length > 0) {
        const members = groups.filter((g) => criterion.from_group_ids.includes(g.id)).reduce((sum, g) => sum + (g.matching_count ?? 0), 0);
        preview.today_count = members;
        preview.note = `${members} member(s) of its subject group(s) today (they enter when they are created or updated, and as soon as they become members).`;
      } else if (criterion.kind === 'attribute') {
        const page = await pageEntitiesConnection<BasicStoreEntity>(context, user, targetTypes, { filters: parseIrFilters(criterion.target_filters), first: 1 });
        preview.today_count = page.pageInfo.globalCount ?? 0;
        preview.note = `${preview.today_count} matching entities today (they enter when they are created or updated).`;
      }
      if (criterion.kind === 'keywords') {
        const keywords = criterion.from_group_ids.flatMap((gid) => config.groups.find((g) => g.id === gid)?.keywords ?? []);
        let total = 0;
        for (let k = 0; k < keywords.length; k += 1) {
          const page = await pageEntitiesConnection<BasicStoreEntity>(context, user, targetTypes, { search: keywords[k], first: 1 });
          total += page.pageInfo.globalCount ?? 0;
        }
        preview.today_count = total;
        preview.note = `About ${total} entities mention these keywords today (full-text search, approximate).`;
      }
    } catch (e) {
      preview.warnings.push(`Could not count today's matches: ${errorMessage(e)}`);
    }
    const conditions = criterion.conditions ?? [];
    if (conditions.length > 0) {
      preview.note = `${preview.note ?? ''}${preview.note ? ' ' : ''}Counted before its ${conditions.length} condition(s): ${conditions.map((cond) => cond.name).join(' AND ')}.`;
      conditions.filter((cond) => !typesOverlap(criterion.target_types, cond.applies_to_types)).forEach((cond) => {
        preview.warnings.push(`Condition "${cond.name}" applies to ${cond.applies_to_types.join(', ')}, a type this criterion never brings: it has no effect.`);
      });
    }
    if (!linkedCriteria.has(criterion.id) && config.kiqs.length > 0) preview.warnings.push('Not linked to any key intelligence question.');
    criteria.push(preview);
  }
  config.kiqs.filter((k) => k.criteria_ids.length === 0).forEach((k) => warnings.push(`KIQ "${k.text}" is linked to no scope criterion: it will always show as unanswered.`));
  if (config.criteria.length === 0) warnings.push('No scope criterion: nothing will enter the requirement.');
  return { valid: errors.length === 0, errors, warnings, groups, criteria };
};
