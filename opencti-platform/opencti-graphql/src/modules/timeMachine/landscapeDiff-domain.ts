import { createHash } from 'node:crypto';
import { v4 as uuidv4 } from 'uuid';
import conf, { logApp } from '../../config/conf';
import { FunctionalError, ValidationError } from '../../config/errors';
import { getClientBase } from '../../database/redis';
import { fullRelationsList, internalFindByIdsMapped, internalLoadById, topEntitiesList } from '../../database/middleware-loader';
import { extractEntityRepresentativeName } from '../../database/entity-representative';
import { READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED } from '../../database/utils';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { RELATION_INDICATES, RELATION_TARGETS, RELATION_USES } from '../../schema/stixCoreRelationship';
import { RELATION_KILL_CHAIN_PHASE } from '../../schema/stixRefRelationship';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_TOOL,
} from '../../schema/stixDomainObject';
import { ENTITY_DOMAIN_NAME, ENTITY_HOSTNAME, ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR, ENTITY_URL } from '../../schema/stixCyberObservable';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import { ENTITY_TYPE_SAVED_FILTER, type BasicStoreEntitySavedFilter } from '../savedFilter/savedFilter-types';
import { ENTITY_TYPE_CUSTOM_VIEW, type BasicStoreEntityCustomView } from '../customView/customView-types';
import { isStixCoreObject } from '../../schema/stixCoreObject';
import { isFilterGroupNotEmpty } from '../../utils/filtering/filtering-utils';
import { executionContext, SYSTEM_USER } from '../../utils/access';
import { getDraftContext } from '../../utils/draftContext';
import { now, utcDate } from '../../utils/format';
import { doYield } from '../../utils/eventloop-utils';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity, BasicStoreObject, BasicStoreRelation } from '../../types/store';
import type { FilterGroup } from '../../generated/graphql';
import { OrderingMode } from '../../generated/graphql';
import { addLandscapeDiffCount } from '../../manager/telemetryManager';
import { changeFieldKey, firstNumber } from './timeMachine-replay';
import { fetchElementsHistoryEvents, fetchRelationshipsHistoryEvents, inclusiveEndDate } from './timeMachine-history';
import { buildRelationshipStates, type RelationshipStateAction, relationshipStateActions, TIME_MACHINE_RELATIONSHIP_TYPES } from './timeMachine-relationships';
import type {
  LandscapeDiffAggregates,
  LandscapeDiffBucket,
  LandscapeDiffEntitySummary,
  LandscapeDiffInputData,
  LandscapeDiffNamedItem,
  LandscapeDiffState,
} from './timeMachine-types';

const LANDSCAPE_MAX_ENTITIES: number = conf.get('time_machine:landscape_max_entities') || 1000;
const LANDSCAPE_BATCH_SIZE: number = conf.get('time_machine:landscape_batch_size') || 100;
const LANDSCAPE_MAX_RELATIONSHIPS: number = conf.get('time_machine:landscape_max_relationships') || 20000;
const LANDSCAPE_CACHE_TTL: number = conf.get('time_machine:landscape_cache_ttl') || 3600;
const LANDSCAPE_MAX_RUNNING_PER_USER: number = conf.get('time_machine:landscape_max_running_per_user') || 1;
const LANDSCAPE_MAX_RUNNING: number = conf.get('time_machine:landscape_max_running') || 4;
// Maximum number of history events read per batch of entities
export const LANDSCAPE_MAX_EVENTS_PER_BATCH = 20000;
// Maximum number of entities and items kept in a landscape diff result
const LANDSCAPE_MAX_ENTITY_SUMMARIES = 200;
const LANDSCAPE_MAX_ITEMS = 50;
// A running computation that did not report progress for this duration is considered interrupted
const LANDSCAPE_STALE_SECONDS = 120;

const LANDSCAPE_WIDGET_MAX_ENTITIES: number = conf.get('time_machine:widget_max_entities') || 200;

const LANDSCAPE_STATE_PREFIX = 'landscape_diff:';
const LANDSCAPE_CONTRIBUTORS_PREFIX = 'landscape_diff_contributors:';
const LANDSCAPE_KEY_PREFIX = 'landscape_diff_key:';
const LANDSCAPE_SUMMARY_PREFIX = 'landscape_diff_summary:';
const LANDSCAPE_CLUSTER_SLOTS_KEY = 'landscape_diff_slots';

export const LANDSCAPE_GROUP_BY_VALUES = ['entity_type', 'relationship_type', 'tactic'];

const INFRASTRUCTURE_TYPES = [ENTITY_TYPE_INFRASTRUCTURE, ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR, ENTITY_DOMAIN_NAME, ENTITY_URL, ENTITY_HOSTNAME];

// Saved filters are scoped to the list they were created in (the storage key of the list), this maps the list scope
// to its entity types
export const SAVED_FILTER_SCOPES: Record<string, string[]> = {
  intrusionSets: ['Intrusion-Set'],
  threatActorsGroups: ['Threat-Actor-Group'],
  threatActorsIndividuals: ['Threat-Actor-Individual'],
  campaigns: ['Campaign'],
  incidents: ['Incident'],
  malwares: ['Malware'],
  tools: ['Tool'],
  vulnerabilities: ['Vulnerability'],
  channels: ['Channel'],
  attackPattern: ['Attack-Pattern'],
  narratives: ['Narrative'],
  coursesOfAction: ['Course-Of-Action'],
  dataComponents: ['Data-Component'],
  dataSources: ['Data-Source'],
  reports: ['Report'],
  groupings: ['Grouping'],
  notes: ['Note'],
  observedDatas: ['Observed-Data'],
  malwareAnalyses: ['Malware-Analysis'],
  caseIncidents: ['Case-Incident'],
  caseRfis: ['Case-Rfi'],
  caseRfts: ['Case-Rft'],
  'cases-casesTasks': ['Task'],
  feedbacks: ['Feedback'],
  sectors: ['Sector'],
  organizations: ['Organization'],
  individuals: ['Individual'],
  systems: ['System'],
  events: ['Event'],
  countries: ['Country'],
  regions: ['Region'],
  cities: ['City'],
  positions: ['Position'],
  'administrative-areas': ['Administrative-Area'],
  infrastructures: ['Infrastructure'],
  'indicators-list': ['Indicator'],
  stixCyberObservables: ['Stix-Cyber-Observable'],
  artifacts: ['Artifact'],
  securityPlatform: ['SecurityPlatform'],
  securityCoverages: ['Security-Coverage'],
};

export const savedFilterScopeEntityTypes = (scope: string | undefined | null): string[] | null => {
  if (!scope) return null;
  return SAVED_FILTER_SCOPES[scope] ?? null;
};

// region Scope
export interface LandscapeScope {
  filters: FilterGroup | null;
  entityTypes: string[];
}

const parseFilters = (filters: string | null | undefined): FilterGroup | null => {
  if (!filters) return null;
  try {
    const parsed = JSON.parse(filters) as FilterGroup;
    return isFilterGroupNotEmpty(parsed) ? parsed : null;
  } catch {
    throw ValidationError('Invalid filters', 'filters');
  }
};

const validateEntityTypes = (types: string[]) => {
  types.forEach((type) => {
    if (!isStixCoreObject(type)) {
      throw ValidationError('Landscape diff only supports STIX core object types', 'entity_types', { type });
    }
  });
};

export const resolveLandscapeScope = async (context: AuthContext, user: AuthUser, input: LandscapeDiffInputData): Promise<LandscapeScope> => {
  if (input.saved_filter_id && input.custom_view_id) {
    throw ValidationError('A landscape scope is either a saved filter or a custom view, not both', 'saved_filter_id');
  }
  const customFilters = parseFilters(input.filters);
  // The filters of a saved filter or a custom view are read from it at each computation, never sent along
  if (customFilters && (input.saved_filter_id || input.custom_view_id)) {
    throw ValidationError('A landscape scope is either filters, a saved filter or a custom view, not a combination', 'filters');
  }
  const filterGroups: FilterGroup[] = [];
  let entityTypes = input.entity_types && input.entity_types.length > 0 ? input.entity_types : null;
  if (input.saved_filter_id) {
    const savedFilter = await internalLoadById<BasicStoreEntitySavedFilter>(context, user, input.saved_filter_id, { type: ENTITY_TYPE_SAVED_FILTER });
    if (!savedFilter) throw FunctionalError('Saved filter not found', { id: input.saved_filter_id });
    const savedFilters = parseFilters(savedFilter.filters);
    if (savedFilters) filterGroups.push(savedFilters);
    if (!entityTypes) {
      // Without explicit entity types, the list of the saved filter gives them: a list that does not map
      // to entity types must not silently widen the scope to every domain object
      entityTypes = savedFilterScopeEntityTypes(savedFilter.scope);
      if (!entityTypes) {
        throw ValidationError('The list of this saved filter has no entity type to compare, choose the entity types', 'entity_types', { scope: savedFilter.scope });
      }
    }
  }
  if (input.custom_view_id) {
    const customView = await internalLoadById<BasicStoreEntityCustomView>(context, user, input.custom_view_id, { type: ENTITY_TYPE_CUSTOM_VIEW });
    if (!customView) throw FunctionalError('Custom view not found', { id: input.custom_view_id });
    // A custom view applies to every entity of its target type, other entity types are not part of it
    if (entityTypes && entityTypes.some((type) => type !== customView.target_entity_type)) {
      throw ValidationError('The entity types of a custom view scope are the target type of the custom view', 'entity_types', {
        entity_types: entityTypes,
        target_entity_type: customView.target_entity_type,
      });
    }
    entityTypes = [customView.target_entity_type];
  }
  if (customFilters) filterGroups.push(customFilters);
  const finalTypes = entityTypes ?? [ABSTRACT_STIX_DOMAIN_OBJECT];
  validateEntityTypes(finalTypes);
  let filters: FilterGroup | null = null;
  if (filterGroups.length === 1) {
    [filters] = filterGroups;
  } else if (filterGroups.length > 1) {
    filters = { mode: 'and', filters: [], filterGroups } as unknown as FilterGroup;
  }
  return { filters, entityTypes: finalTypes };
};
// endregion

// region Computation
interface EntityAccumulator {
  entity: BasicStoreEntity;
  created_in_period: boolean;
  revoked_in_period: boolean;
  changed_keys: Set<string>;
  relationships_added: number;
  relationships_removed: number;
  relationships_revoked: number;
  relationships_confidence_changed: number;
  confidence_before?: number | null;
  confidence_after?: number | null;
  score_before?: number | null;
  score_after?: number | null;
}

interface TargetAccumulator {
  type: string;
  relationshipTypes: Set<string>;
  entityIds: Set<string>;
}

interface GlobalAccumulator {
  entities: Map<string, EntityAccumulator>;
  newRelationshipsByType: Map<string, number>;
  newRelationships: number;
  removedRelationships: number;
  revocations: number;
  relationshipConfidenceChanges: number;
  targets: Map<string, TargetAccumulator>;
  // A relationship between entities of two batches is read by both: global counters count it once
  countedRelationships: Set<string>;
  countedRelationshipStates: Set<string>;
  // Accessible elements behind the counts of removed, revoked and updated relationships, revalidated with a stored
  // result: the endpoints out of the scope of a removed relationship, the other relationships themselves
  countedElements: Set<string>;
  resolvedTargets: Set<string>;
  relationshipsFetched: number;
  truncated: boolean;
}

export interface LandscapeDiffComputation {
  aggregates: LandscapeDiffAggregates;
  entities: LandscapeDiffEntitySummary[];
  total: number;
  truncated: boolean;
  // Every element whose access shaped the result, counted or named
  contributors: string[];
}

const increment = (map: Map<string, number>, key: string, by = 1) => map.set(key, (map.get(key) ?? 0) + by);

const toBuckets = (map: Map<string, number>, labels?: Map<string, string>): LandscapeDiffBucket[] => {
  return [...map.entries()]
    .map(([key, count]) => ({ key, label: labels?.get(key) ?? key, count }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
};

const registerTarget = (acc: GlobalAccumulator, targetId: string, targetType: string, relationshipType: string, entityId: string) => {
  const target = acc.targets.get(targetId) ?? { type: targetType, relationshipTypes: new Set<string>(), entityIds: new Set<string>() };
  target.relationshipTypes.add(relationshipType);
  target.entityIds.add(entityId);
  acc.targets.set(targetId, target);
};

// Changes of existing relationships that the landscape counts (a relationship unrevoked in the period is not)
const COUNTED_RELATIONSHIP_ACTIONS: RelationshipStateAction[] = ['removed', 'revoked', 'confidence_changed'];

/**
 * Access of the elements behind a relationship count, with the rights of the user: the accessible ones are counted
 * and revalidated with a stored result, the ones that no longer exist are counted (nothing is left to reclassify),
 * the ones that exist but that the user cannot access are not counted.
 */
export const resolveCountedElements = async (context: AuthContext, user: AuthUser, ids: string[]) => {
  const uniqueIds = [...new Set(ids)];
  const accessible = new Set<string>();
  const restricted = new Set<string>();
  if (uniqueIds.length === 0) return { accessible, restricted };
  const found = await internalFindByIdsMapped<BasicStoreObject>(context, user, uniqueIds, { baseData: true });
  const missing = uniqueIds.filter((id) => !found[id]);
  const existing = missing.length > 0 ? await internalFindByIdsMapped<BasicStoreObject>(context, SYSTEM_USER, missing, { baseData: true }) : {};
  uniqueIds.forEach((id) => {
    if (found[id]) accessible.add(id);
    else if (existing[id]) restricted.add(id);
  });
  return { accessible, restricted };
};

const processBatch = async (
  context: AuthContext,
  user: AuthUser,
  batch: BasicStoreEntity[],
  from: string,
  to: string,
  acc: GlobalAccumulator,
) => {
  const ids = batch.map((entity) => entity.internal_id);
  const idSet = new Set(ids);
  // 1. Relationships created in the period. Both scoped sides of a relationship are counted the first time it is read,
  // whatever their batch: a later batch only looks for new relationships once the budget is spent. The relationships
  // counted from earlier batches that it reads again are the ones its entities already count, so the read lets them through.
  const budget = Math.max(0, LANDSCAPE_MAX_RELATIONSHIPS - acc.relationshipsFetched);
  const alreadyCounted = batch.reduce((total, entity) => total + (acc.entities.get(entity.internal_id)?.relationships_added ?? 0), 0);
  const maxSize = budget + alreadyCounted;
  // One extra relationship is read to know whether some were left out
  const fetched = await fullRelationsList<BasicStoreRelation>(context, user, [ABSTRACT_STIX_CORE_RELATIONSHIP, STIX_SIGHTING_RELATIONSHIP], {
    fromOrToId: ids,
    indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
    startDate: from,
    endDate: inclusiveEndDate(to),
    dateAttribute: 'created_at',
    maxSize: maxSize + 1,
    baseData: true,
    baseFields: ['created_at'],
  } as any);
  if (fetched.length > maxSize) acc.truncated = true;
  let newRelationships = 0;
  fetched.slice(0, maxSize).forEach((relation) => {
    if (acc.countedRelationships.has(relation.internal_id)) return;
    if (newRelationships >= budget) {
      acc.truncated = true;
      return;
    }
    newRelationships += 1;
    acc.countedRelationships.add(relation.internal_id);
    acc.newRelationships += 1;
    increment(acc.newRelationshipsByType, relation.entity_type);
    const fromEntity = acc.entities.get(relation.fromId);
    if (fromEntity) {
      fromEntity.relationships_added += 1;
      registerTarget(acc, relation.toId, relation.toType, relation.entity_type, relation.fromId);
    }
    const toEntity = acc.entities.get(relation.toId);
    if (toEntity) {
      toEntity.relationships_added += 1;
      registerTarget(acc, relation.fromId, relation.fromType, relation.entity_type, relation.toId);
    }
  });
  acc.relationshipsFetched += newRelationships;
  // 2. Relationships removed, revoked or whose confidence changed in the period
  const fetchedEvents = await fetchRelationshipsHistoryEvents(context, user, ids, {
    from,
    to,
    scopes: ['create', 'delete', 'update'],
    entityTypes: TIME_MACHINE_RELATIONSHIP_TYPES,
    max: LANDSCAPE_MAX_EVENTS_PER_BATCH + 1,
  });
  if (fetchedEvents.length > LANDSCAPE_MAX_EVENTS_PER_BATCH) acc.truncated = true;
  const relationshipEvents = fetchedEvents.slice(0, LANDSCAPE_MAX_EVENTS_PER_BATCH);
  const changedRelationships = [...buildRelationshipStates(relationshipEvents).entries()].map(([relationshipId, state]) => {
    // A relationship created in the period is counted with the new relationships; when it is one of them,
    // its revocation and confidence changes after its creation count as well
    const actions = relationshipStateActions(state, acc.countedRelationships.has(relationshipId));
    // A removed relationship is only known through its endpoints, the other ones still exist
    const shapingIds = actions.includes('removed')
      ? [state.from_id, state.to_id].filter((id): id is string => !!id && !acc.entities.has(id))
      : [relationshipId];
    return { relationshipId, state, actions, shapingIds };
  }).filter(({ actions }) => actions.some((action) => COUNTED_RELATIONSHIP_ACTIONS.includes(action)));
  const access = await resolveCountedElements(context, user, changedRelationships.flatMap(({ shapingIds }) => shapingIds));
  changedRelationships.forEach(({ relationshipId, state, actions, shapingIds }) => {
    if (shapingIds.some((id) => access.restricted.has(id))) return;
    shapingIds.filter((id) => access.accessible.has(id)).forEach((id) => acc.countedElements.add(id));
    const sides = [state.from_id, state.to_id].filter((id): id is string => !!id && idSet.has(id));
    const countGlobally = !acc.countedRelationshipStates.has(relationshipId);
    acc.countedRelationshipStates.add(relationshipId);
    if (actions.includes('removed')) {
      if (countGlobally) acc.removedRelationships += 1;
      sides.forEach((id) => {
        acc.entities.get(id)!.relationships_removed += 1;
      });
      return;
    }
    if (actions.includes('revoked')) {
      if (countGlobally) acc.revocations += 1;
      sides.forEach((id) => {
        acc.entities.get(id)!.relationships_revoked += 1;
      });
    }
    if (actions.includes('confidence_changed')) {
      if (countGlobally) acc.relationshipConfidenceChanges += 1;
      sides.forEach((id) => {
        acc.entities.get(id)!.relationships_confidence_changed += 1;
      });
    }
  });
  // 3. Updates of the entities themselves in the period
  const fetchedEntityEvents = await fetchElementsHistoryEvents(context, user, ids, {
    from,
    to,
    scopes: ['update', 'merge'],
    max: LANDSCAPE_MAX_EVENTS_PER_BATCH + 1,
    order: 'asc',
  });
  if (fetchedEntityEvents.length > LANDSCAPE_MAX_EVENTS_PER_BATCH) acc.truncated = true;
  const entityEvents = fetchedEntityEvents.slice(0, LANDSCAPE_MAX_EVENTS_PER_BATCH);
  entityEvents.forEach((event) => {
    const entityAcc = acc.entities.get(event.context_id);
    if (!entityAcc) return;
    (event.changes ?? []).forEach((change) => {
      const key = changeFieldKey(change.field);
      entityAcc.changed_keys.add(key);
      const added = (change.changes_added ?? []).map((v) => v.raw);
      const removed = (change.changes_removed ?? []).map((v) => v.raw);
      if (key === 'confidence') {
        if (entityAcc.confidence_before === undefined) entityAcc.confidence_before = firstNumber(removed);
        entityAcc.confidence_after = firstNumber(added);
      }
      if (key === 'x_opencti_score') {
        if (entityAcc.score_before === undefined) entityAcc.score_before = firstNumber(removed);
        entityAcc.score_after = firstNumber(added);
      }
      if (key === 'revoked' && added[0] === 'true') {
        entityAcc.revoked_in_period = true;
      }
    });
  });
};

const changeScore = (entity: EntityAccumulator) => {
  const confidenceDelta = Math.abs((entity.confidence_after ?? 0) - (entity.confidence_before ?? entity.confidence_after ?? 0));
  const scoreDelta = Math.abs((entity.score_after ?? 0) - (entity.score_before ?? entity.score_after ?? 0));
  return entity.changed_keys.size
    + 2 * (entity.relationships_added + entity.relationships_removed + entity.relationships_revoked)
    + entity.relationships_confidence_changed
    + (entity.created_in_period ? 5 : 0)
    + (entity.revoked_in_period ? 5 : 0)
    + Math.round((confidenceDelta + scoreDelta) / 10);
};

export const buildNamedItems = (
  acc: Pick<GlobalAccumulator, 'targets'>,
  resolved: Record<string, BasicStoreObject>,
  predicate: (target: TargetAccumulator) => boolean,
): LandscapeDiffNamedItem[] => {
  const items: LandscapeDiffNamedItem[] = [];
  acc.targets.forEach((target, id) => {
    const element = resolved[id];
    if (element && predicate(target)) {
      items.push({
        id,
        standard_id: element.standard_id ?? null,
        entity_type: element.entity_type,
        name: extractEntityRepresentativeName(element),
        x_mitre_id: element.entity_type === ENTITY_TYPE_ATTACK_PATTERN ? ((element as any).x_mitre_id ?? null) : null,
        count: target.entityIds.size,
      });
    }
  });
  return items.sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
};

const buildAggregates = async (
  context: AuthContext,
  user: AuthUser,
  acc: GlobalAccumulator,
  entitiesInScope: number,
  groupBy: string,
): Promise<LandscapeDiffAggregates> => {
  const interestingTypes = new Set([
    ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_MALWARE, ENTITY_TYPE_TOOL, ENTITY_TYPE_IDENTITY_SECTOR,
    ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_REGION, ...INFRASTRUCTURE_TYPES,
  ]);
  const targetIds = [...acc.targets.entries()].filter(([, target]) => interestingTypes.has(target.type)).map(([id]) => id);
  // Targets are resolved with the rights of the user, inaccessible ones are ignored
  const resolved = targetIds.length > 0 ? await internalFindByIdsMapped<BasicStoreObject>(context, user, targetIds) : {};
  const uses = (type: string) => (target: TargetAccumulator) => target.type === type && target.relationshipTypes.has(RELATION_USES);
  const techniques = buildNamedItems(acc, resolved, uses(ENTITY_TYPE_ATTACK_PATTERN));
  // Techniques by tactic (kill chain phase)
  const phaseIds = new Set<string>();
  techniques.forEach((technique) => ((resolved[technique.id] as any)?.[RELATION_KILL_CHAIN_PHASE] ?? []).forEach((id: string) => phaseIds.add(id)));
  const phases = phaseIds.size > 0 ? await internalFindByIdsMapped<BasicStoreObject>(context, user, [...phaseIds]) : {};
  const techniquesByTactic = new Map<string, number>();
  techniques.forEach((technique) => {
    const techniquePhases: string[] = (resolved[technique.id] as any)?.[RELATION_KILL_CHAIN_PHASE] ?? [];
    const tactics = new Set(techniquePhases.map((id) => (phases[id] as any)?.phase_name).filter((name): name is string => !!name));
    if (tactics.size === 0) increment(techniquesByTactic, 'unknown');
    tactics.forEach((tactic) => increment(techniquesByTactic, tactic));
  });
  const victimsBy = (type: string) => {
    const buckets = new Map<string, number>();
    const labels = new Map<string, string>();
    acc.targets.forEach((target, id) => {
      const element = resolved[id];
      if (element && target.type === type && target.relationshipTypes.has(RELATION_TARGETS)) {
        buckets.set(id, target.entityIds.size);
        labels.set(id, extractEntityRepresentativeName(element));
      }
    });
    return toBuckets(buckets, labels);
  };
  const infrastructure = buildNamedItems(acc, resolved, (target) => INFRASTRUCTURE_TYPES.includes(target.type));
  const malware = buildNamedItems(acc, resolved, uses(ENTITY_TYPE_MALWARE));
  const tools = buildNamedItems(acc, resolved, uses(ENTITY_TYPE_TOOL));
  // Indicators are only counted, but a visible relationship can point to an indicator the user cannot access
  const indicatorIds = [...acc.targets.entries()]
    .filter(([, target]) => target.type === ENTITY_TYPE_INDICATOR && target.relationshipTypes.has(RELATION_INDICATES))
    .map(([id]) => id);
  const accessibleIndicators = indicatorIds.length > 0 ? await internalFindByIdsMapped<BasicStoreObject>(context, user, indicatorIds, { baseData: true }) : {};
  const indicatorsCount = indicatorIds.filter((id) => !!accessibleIndicators[id]).length;
  [resolved, phases, accessibleIndicators].forEach((found) => Object.keys(found).forEach((id) => acc.resolvedTargets.add(id)));
  const entities = [...acc.entities.values()];
  const newEntitiesByType = new Map<string, number>();
  entities.filter((e) => e.created_in_period).forEach((e) => increment(newEntitiesByType, e.entity.entity_type));
  const changedEntities = entities.filter((e) => changeScore(e) > 0);
  let groups: LandscapeDiffBucket[];
  if (groupBy === 'relationship_type') {
    groups = toBuckets(acc.newRelationshipsByType);
  } else if (groupBy === 'tactic') {
    groups = toBuckets(techniquesByTactic);
  } else {
    const byType = new Map<string, number>();
    changedEntities.forEach((e) => increment(byType, e.entity.entity_type));
    groups = toBuckets(byType);
  }
  const hasChanged = (before: number | null | undefined, after: number | null | undefined) => after !== undefined && before !== undefined && before !== after;
  return {
    entities_in_scope: entitiesInScope,
    entities_changed: changedEntities.length,
    new_entities: entities.filter((e) => e.created_in_period).length,
    new_entities_by_type: toBuckets(newEntitiesByType),
    new_relationships: acc.newRelationships,
    new_relationships_by_type: toBuckets(acc.newRelationshipsByType),
    removed_relationships: acc.removedRelationships,
    revocations: acc.revocations + entities.filter((e) => e.revoked_in_period).length,
    confidence_changes: acc.relationshipConfidenceChanges + entities.filter((e) => hasChanged(e.confidence_before, e.confidence_after)).length,
    score_changes: entities.filter((e) => hasChanged(e.score_before, e.score_after)).length,
    new_techniques_by_tactic: toBuckets(techniquesByTactic),
    new_techniques: techniques.slice(0, LANDSCAPE_MAX_ITEMS),
    new_techniques_count: techniques.length,
    new_malware: malware.slice(0, LANDSCAPE_MAX_ITEMS),
    new_malware_count: malware.length,
    new_tools: tools.slice(0, LANDSCAPE_MAX_ITEMS),
    new_tools_count: tools.length,
    new_victims_by_sector: victimsBy(ENTITY_TYPE_IDENTITY_SECTOR),
    new_victims_by_country: victimsBy(ENTITY_TYPE_LOCATION_COUNTRY),
    new_victims_by_region: victimsBy(ENTITY_TYPE_LOCATION_REGION),
    new_infrastructure: infrastructure.slice(0, LANDSCAPE_MAX_ITEMS),
    new_infrastructure_count: infrastructure.length,
    new_indicators_count: indicatorsCount,
    groups,
  };
};

const buildEntitySummaries = (acc: GlobalAccumulator): LandscapeDiffEntitySummary[] => {
  return [...acc.entities.values()]
    .map((e) => ({
      entity_id: e.entity.internal_id,
      standard_id: e.entity.standard_id ?? null,
      entity_type: e.entity.entity_type,
      name: extractEntityRepresentativeName(e.entity),
      created_in_period: e.created_in_period,
      revoked_in_period: e.revoked_in_period,
      attributes_changed: e.changed_keys.size,
      relationships_added: e.relationships_added,
      relationships_removed: e.relationships_removed,
      relationships_revoked: e.relationships_revoked,
      relationships_confidence_changed: e.relationships_confidence_changed,
      confidence_before: e.confidence_before ?? null,
      confidence_after: e.confidence_after ?? null,
      score_before: e.score_before ?? null,
      score_after: e.score_after ?? null,
      change_score: changeScore(e),
    }))
    .filter((summary) => summary.change_score > 0)
    .sort((a, b) => b.change_score - a.change_score || a.name.localeCompare(b.name))
    .slice(0, LANDSCAPE_MAX_ENTITY_SUMMARIES);
};

/**
 * Compute the landscape diff between two dates of the entities that match the scope today and
 * were created before `to`: the set an analyst tracks now. Filters are evaluated on the current
 * knowledge and entities deleted since are not part of the scope.
 * Every read uses the rights of the user. Entities are processed in bounded batches.
 */
export const computeLandscapeDiff = async (
  context: AuthContext,
  user: AuthUser,
  scope: LandscapeScope,
  from: string,
  to: string,
  groupBy: string,
  opts: { maxEntities?: number; onProgress?: (progress: number, total: number) => Promise<void>; signal?: AbortSignal } = {},
): Promise<LandscapeDiffComputation> => {
  const maxEntities = opts.maxEntities ?? LANDSCAPE_MAX_ENTITIES;
  const scopeEntities = await topEntitiesList<BasicStoreEntity>(context, user, scope.entityTypes, {
    filters: scope.filters,
    first: maxEntities + 1,
    orderBy: 'created_at',
    orderMode: OrderingMode.Desc,
    endDate: inclusiveEndDate(to),
    dateAttribute: 'created_at',
  } as any);
  const truncatedScope = scopeEntities.length > maxEntities;
  const entities = scopeEntities.slice(0, maxEntities);
  const acc: GlobalAccumulator = {
    entities: new Map(entities.map((entity) => [entity.internal_id, {
      entity,
      created_in_period: utcDate(entity.created_at).isAfter(utcDate(from)) && !utcDate(entity.created_at).isAfter(utcDate(to)),
      revoked_in_period: false,
      changed_keys: new Set<string>(),
      relationships_added: 0,
      relationships_removed: 0,
      relationships_revoked: 0,
      relationships_confidence_changed: 0,
    }])),
    newRelationshipsByType: new Map(),
    newRelationships: 0,
    removedRelationships: 0,
    revocations: 0,
    relationshipConfidenceChanges: 0,
    targets: new Map(),
    countedRelationships: new Set(),
    countedRelationshipStates: new Set(),
    countedElements: new Set(),
    resolvedTargets: new Set(),
    relationshipsFetched: 0,
    truncated: truncatedScope,
  };
  await opts.onProgress?.(0, entities.length);
  for (let index = 0; index < entities.length; index += LANDSCAPE_BATCH_SIZE) {
    await doYield();
    opts.signal?.throwIfAborted();
    const batch = entities.slice(index, index + LANDSCAPE_BATCH_SIZE);
    await processBatch(context, user, batch, from, to, acc);
    await opts.onProgress?.(Math.min(index + batch.length, entities.length), entities.length);
  }
  opts.signal?.throwIfAborted();
  const aggregates = await buildAggregates(context, user, acc, entities.length, groupBy);
  const contributors = new Set([...acc.entities.keys(), ...acc.countedRelationships, ...acc.countedElements, ...acc.resolvedTargets]);
  return { aggregates, entities: buildEntitySummaries(acc), total: entities.length, truncated: acc.truncated, contributors: [...contributors] };
};
// endregion

// region Background execution with progress and cache
const LANDSCAPE_INTERRUPTED_MESSAGE = 'Landscape diff computation was interrupted';
const LANDSCAPE_ACCESS_CHANGED_MESSAGE = 'Access to the knowledge of this landscape diff changed, it must be computed again';

export interface LandscapeRunSlot {
  userId: string;
  controller: AbortController;
  // Last progress of the computation (epoch milliseconds)
  lastActivity: number;
}

/**
 * Concurrency slots of the landscape diffs computed on this node, reserved per run id. A computation that did not
 * report progress for `staleSeconds` is aborted and its slot released when the next run is reserved or when its
 * state is read, so a hung computation never keeps a slot until the node restarts. Releasing is idempotent.
 */
export const createLandscapeRunSlots = (limits: { maxPerUser: number; maxTotal: number; staleSeconds: number }, clock: () => number = Date.now) => {
  const slots = new Map<string, LandscapeRunSlot>();
  const release = (id: string, reason?: string) => {
    const slot = slots.get(id);
    if (!slot) return;
    slots.delete(id);
    if (reason) slot.controller.abort(new Error(reason));
  };
  const releaseStale = () => {
    const staleBefore = clock() - limits.staleSeconds * 1000;
    [...slots.entries()].filter(([, slot]) => slot.lastActivity < staleBefore).forEach(([id]) => release(id, LANDSCAPE_INTERRUPTED_MESSAGE));
  };
  // Synchronous, so concurrent requests cannot exceed the limits
  const reserve = (id: string, userId: string): LandscapeRunSlot | null => {
    releaseStale();
    const userRunning = [...slots.values()].filter((slot) => slot.userId === userId).length;
    if (userRunning >= limits.maxPerUser || slots.size >= limits.maxTotal) return null;
    const slot: LandscapeRunSlot = { userId, controller: new AbortController(), lastActivity: clock() };
    slots.set(id, slot);
    return slot;
  };
  const touch = (id: string) => {
    const slot = slots.get(id);
    if (slot) slot.lastActivity = clock();
  };
  return { reserve, touch, release, size: () => slots.size };
};

// Removes the expired leases, then adds the lease only within the per-user and total limits
const RESERVE_CLUSTER_SLOT_SCRIPT = `
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[1])
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[6]) then return 0 end
local userRunning = 0
for _, member in ipairs(redis.call('ZRANGE', KEYS[1], 0, -1)) do
  if string.sub(member, 1, string.len(ARGV[4])) == ARGV[4] then userRunning = userRunning + 1 end
end
if userRunning >= tonumber(ARGV[5]) then return 0 end
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[3])
return 1`;

// Extends a lease that has not expired yet
const EXTEND_CLUSTER_SLOT_SCRIPT = `
local leaseEnd = redis.call('ZSCORE', KEYS[1], ARGV[2])
if not leaseEnd or tonumber(leaseEnd) < tonumber(ARGV[3]) then return 0 end
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[2])
return 1`;

/**
 * The same limits for the whole platform: every node reserves its runs in one Redis sorted set of leases (one member
 * per user and run, scored by the end of its lease). A lease is extended at each progress of its computation and
 * expires `staleSeconds` after the last one, so the slot of a node that stopped is freed without any cleanup job.
 */
export const createLandscapeClusterSlots = (key: string, limits: { maxPerUser: number; maxTotal: number; staleSeconds: number }, clock: () => number = Date.now) => {
  const member = (id: string, userId: string) => `${userId}|${id}`;
  const reserve = async (id: string, userId: string): Promise<boolean> => {
    const now = clock();
    const leaseEnd = now + limits.staleSeconds * 1000;
    const reserved = await getClientBase().eval(RESERVE_CLUSTER_SLOT_SCRIPT, 1, key, now, leaseEnd, member(id, userId), `${userId}|`, limits.maxPerUser, limits.maxTotal);
    return reserved === 1;
  };
  // False when the lease expired meanwhile: the slot may be taken by another run
  const extend = async (id: string, userId: string): Promise<boolean> => {
    const now = clock();
    const extended = await getClientBase().eval(EXTEND_CLUSTER_SLOT_SCRIPT, 1, key, now + limits.staleSeconds * 1000, member(id, userId), now);
    return extended === 1;
  };
  const release = async (id: string, userId: string) => {
    await getClientBase().zrem(key, member(id, userId));
  };
  return { reserve, extend, release };
};

const LANDSCAPE_LIMITS = {
  maxPerUser: LANDSCAPE_MAX_RUNNING_PER_USER,
  maxTotal: LANDSCAPE_MAX_RUNNING,
  staleSeconds: LANDSCAPE_STALE_SECONDS,
};
// The node keeps the controller of each of its runs, the cluster keeps the limits of the platform
const landscapeRunSlots = createLandscapeRunSlots(LANDSCAPE_LIMITS);
const landscapeClusterSlots = createLandscapeClusterSlots(LANDSCAPE_CLUSTER_SLOTS_KEY, LANDSCAPE_LIMITS);

const releaseClusterSlot = async (id: string, userId: string) => {
  try {
    await landscapeClusterSlots.release(id, userId);
  } catch (err) {
    // The lease expires by itself
    logApp.warn('[TIME MACHINE] Landscape diff slot could not be released', { cause: err, id });
  }
};

const stateKey = (id: string) => `${LANDSCAPE_STATE_PREFIX}${id}`;

const readState = async (id: string): Promise<LandscapeDiffState | null> => {
  const raw = await getClientBase().get(stateKey(id));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as LandscapeDiffState;
  } catch {
    logApp.warn('[TIME MACHINE] Landscape diff state could not be parsed', { id });
    return null;
  }
};

const stateTtl = (state: LandscapeDiffState) => Math.max(1, utcDate(state.expires_at).diff(utcDate(), 'seconds'));

const writeState = async (state: LandscapeDiffState) => {
  await getClientBase().set(stateKey(state.id), JSON.stringify(state), 'EX', stateTtl(state));
};

// Runs are polled through any node but executed by the node that started them: an execution never overwrites a
// terminal state, so a run finalized elsewhere (found stale by a poll) stops instead of being revived
const SET_IF_ACTIVE_SCRIPT = `
local current = redis.call('GET', KEYS[1])
if current then
  local status = cjson.decode(current).status
  if status == 'complete' or status == 'failed' then return 0 end
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
return 1`;

// A stale run is only finalized when it did not progress since it was read
const SET_IF_UNCHANGED_SCRIPT = `
local current = redis.call('GET', KEYS[1])
if not current or cjson.decode(current).updated_at ~= ARGV[3] then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
return 1`;

export const writeActiveLandscapeState = async (state: LandscapeDiffState): Promise<boolean> => {
  const written = await getClientBase().eval(SET_IF_ACTIVE_SCRIPT, 1, stateKey(state.id), JSON.stringify(state), stateTtl(state));
  return written === 1;
};

export const finalizeStaleLandscapeState = async (stale: LandscapeDiffState, finalized: LandscapeDiffState): Promise<boolean> => {
  const written = await getClientBase().eval(SET_IF_UNCHANGED_SCRIPT, 1, stateKey(stale.id), JSON.stringify(finalized), stateTtl(finalized), stale.updated_at);
  return written === 1;
};

// Kept apart from the state, which is read at every progress poll
const writeContributors = async (state: LandscapeDiffState, contributors: string[]) => {
  await getClientBase().set(`${LANDSCAPE_CONTRIBUTORS_PREFIX}${state.id}`, JSON.stringify(contributors), 'EX', stateTtl(state));
};

const readContributors = async (id: string): Promise<string[] | null> => {
  const raw = await getClientBase().get(`${LANDSCAPE_CONTRIBUTORS_PREFIX}${id}`);
  if (!raw) return null;
  try {
    const contributors = JSON.parse(raw);
    return Array.isArray(contributors) ? contributors : null;
  } catch {
    logApp.warn('[TIME MACHINE] Landscape diff contributors could not be parsed', { id });
    return null;
  }
};

/**
 * Fingerprint of everything the results depend on in the rights of the user: a cached result
 * computed before a change of capabilities (draft capabilities included), markings, organizations
 * or groups is never reused.
 */
export const userAccessFingerprint = (context: AuthContext, user: AuthUser) => {
  const ids = (items: Array<{ internal_id?: string; id?: string }> | undefined) => (items ?? []).map((item) => item.internal_id ?? item.id ?? '').sort();
  const payload = JSON.stringify({
    capabilities: (user.capabilities ?? []).map((capability) => capability.name).sort(),
    capabilities_in_draft: (user.capabilitiesInDraft ?? []).map((capability) => capability.name).sort(),
    markings: ids(user.allowed_marking),
    organizations: ids(user.organizations),
    groups: ids(user.groups),
    inside_platform_organization: context.user_inside_platform_organization ?? null,
    draft: getDraftContext(context, user) ?? null,
  });
  return createHash('sha256').update(payload).digest('hex');
};

export const landscapeDiffCacheKey = (userId: string, accessFingerprint: string, input: LandscapeDiffInputData, scope: LandscapeScope) => {
  const payload = JSON.stringify({
    user: userId,
    access: accessFingerprint,
    filters: scope.filters,
    types: [...scope.entityTypes].sort(),
    from: input.from,
    to: input.to,
    group_by: input.group_by ?? 'entity_type',
  });
  return createHash('sha256').update(payload).digest('hex');
};

const normalizeLandscapeDates = (input: LandscapeDiffInputData) => {
  const from = utcDate(input.from);
  const to = utcDate(input.to);
  if (!from.isValid() || !to.isValid()) throw ValidationError('Invalid dates', 'from');
  const currentDate = utcDate();
  const finalTo = to.isAfter(currentDate) ? currentDate : to;
  if (!from.isBefore(finalTo)) throw ValidationError('The start date must be before the end date', 'from');
  return { from: from.toISOString(), to: finalTo.toISOString() };
};

const executeLandscapeDiff = async (requestContext: AuthContext, user: AuthUser, state: LandscapeDiffState, scope: LandscapeScope, signal: AbortSignal) => {
  // The computation outlives the request: it gets its own context, with the same organization evaluation
  // and the same draft as the request so it reads the same knowledge
  const context: AuthContext = {
    ...executionContext('landscape_diff', user),
    user_inside_platform_organization: requestContext.user_inside_platform_organization,
    draft_context: getDraftContext(requestContext, user),
  };
  let current: LandscapeDiffState = { ...state, status: 'running', updated_at: now() };
  const writeOrStop = async (next: LandscapeDiffState) => {
    if (!await writeActiveLandscapeState(next)) landscapeRunSlots.release(state.id, LANDSCAPE_INTERRUPTED_MESSAGE);
  };
  // The slot of the platform is free once the final state can be read: a new run requested right after is accepted
  const writeFinalState = async (final: LandscapeDiffState) => {
    await releaseClusterSlot(state.id, user.id);
    return writeActiveLandscapeState(final);
  };
  try {
    await writeOrStop(current);
    const computation = await computeLandscapeDiff(context, user, scope, state.input.from, state.input.to, state.input.group_by ?? 'entity_type', {
      signal,
      onProgress: async (progress, total) => {
        signal.throwIfAborted();
        landscapeRunSlots.touch(state.id);
        if (!await landscapeClusterSlots.extend(state.id, user.id)) {
          // The lease expired, its slot may be taken by another run: this one stops
          landscapeRunSlots.release(state.id, LANDSCAPE_INTERRUPTED_MESSAGE);
          signal.throwIfAborted();
        }
        current = { ...current, progress, total, updated_at: now() };
        await writeOrStop(current);
      },
    });
    // An interrupted run keeps its failed state, even if its last read completes afterwards
    signal.throwIfAborted();
    // Written before the complete state so a complete result can always be revalidated
    await writeContributors(current, computation.contributors);
    current = {
      ...current,
      status: 'complete',
      progress: computation.total,
      total: computation.total,
      truncated: computation.truncated,
      aggregates: computation.aggregates,
      entities: computation.entities,
      updated_at: now(),
    };
    if (await writeFinalState(current)) {
      addLandscapeDiffCount();
    } else {
      logApp.warn('[TIME MACHINE] Landscape diff finalized by another node before its completion', { id: state.id });
    }
  } catch (err) {
    if (signal.aborted) {
      logApp.warn('[TIME MACHINE] Landscape diff computation interrupted', { id: state.id });
      await writeFinalState({ ...current, status: 'failed', error: LANDSCAPE_INTERRUPTED_MESSAGE, updated_at: now() });
      return;
    }
    logApp.error('[TIME MACHINE] Landscape diff computation failed', { cause: err, id: state.id });
    await writeFinalState({ ...current, status: 'failed', error: (err as Error)?.message ?? 'Landscape diff computation failed', updated_at: now() });
  }
};

export const runLandscapeDiff = async (context: AuthContext, user: AuthUser, rawInput: LandscapeDiffInputData): Promise<LandscapeDiffState> => {
  const groupBy = rawInput.group_by ?? 'entity_type';
  if (!LANDSCAPE_GROUP_BY_VALUES.includes(groupBy)) {
    throw ValidationError('Invalid group by', 'group_by', { group_by: groupBy });
  }
  const dates = normalizeLandscapeDates(rawInput);
  const input: LandscapeDiffInputData = { ...rawInput, ...dates, group_by: groupBy };
  const scope = await resolveLandscapeScope(context, user, input);
  // Results are cached per user and rights (they are computed with the rights of the user)
  const accessFingerprint = userAccessFingerprint(context, user);
  const cacheKey = `${LANDSCAPE_KEY_PREFIX}${landscapeDiffCacheKey(user.id, accessFingerprint, input, scope)}`;
  const cachedId = await getClientBase().get(cacheKey);
  if (cachedId) {
    const cached = await findLandscapeDiff(context, user, cachedId);
    if (cached && cached.status !== 'failed') return cached;
  }
  // The node slot is reserved before any await so concurrent requests of this node cannot exceed the limits, then the
  // cluster slot applies them to the whole platform
  const id = uuidv4();
  const slot = landscapeRunSlots.reserve(id, user.id);
  if (!slot) {
    throw FunctionalError('Too many landscape diffs are being computed, please retry later');
  }
  let clusterReserved: boolean;
  try {
    clusterReserved = await landscapeClusterSlots.reserve(id, user.id);
  } catch (err) {
    landscapeRunSlots.release(id);
    throw err;
  }
  if (!clusterReserved) {
    landscapeRunSlots.release(id);
    throw FunctionalError('Too many landscape diffs are being computed, please retry later');
  }
  const releaseSlot = () => {
    landscapeRunSlots.release(id);
    void releaseClusterSlot(id, user.id);
  };
  const createdAt = now();
  const state: LandscapeDiffState = {
    id,
    user_id: user.id,
    access_fingerprint: accessFingerprint,
    status: 'pending',
    progress: 0,
    total: 0,
    input,
    scope_entity_types: scope.entityTypes,
    created_at: createdAt,
    updated_at: createdAt,
    expires_at: utcDate(createdAt).add(LANDSCAPE_CACHE_TTL, 'seconds').toISOString(),
    error: null,
    truncated: false,
    aggregates: null,
    entities: [],
  };
  try {
    await writeState(state);
    await getClientBase().set(cacheKey, state.id, 'EX', LANDSCAPE_CACHE_TTL);
  } catch (err) {
    releaseSlot();
    throw err;
  }
  // The computation runs in the background, its progress is polled through the landscapeDiff query
  void executeLandscapeDiff(context, user, state, scope, slot.controller.signal).catch((err) => {
    logApp.error('[TIME MACHINE] Landscape diff execution error', { cause: err, id: state.id });
  }).finally(releaseSlot);
  return state;
};

export interface LandscapeDiffSummaryResult {
  from: string;
  to: string;
  scope_entity_types: string[];
  computed_at: string;
  truncated: boolean;
  aggregates: LandscapeDiffAggregates;
  entities: LandscapeDiffEntitySummary[];
}

interface CachedLandscapeSummary {
  result: LandscapeDiffSummaryResult;
  contributors: string[];
  // Instant the computation started reading the history: the changes made after it are not in the result
  computed_until: string;
}

/**
 * A cached summary is reused only when it was computed after the end of the requested period: the end of a period
 * reaching the current minute is in the future when it is computed, a later request must see the changes made since.
 */
export const isCachedSummaryCovering = (computedUntil: string | undefined, requestedTo: string) => {
  return !!computedUntil && !utcDate(computedUntil).isBefore(utcDate(requestedTo));
};

export const landscapeResultReferencedIds = (aggregates: LandscapeDiffAggregates | null, entities: LandscapeDiffEntitySummary[]): string[] => {
  const ids = new Set(entities.map((entity) => entity.entity_id));
  if (aggregates) {
    [...aggregates.new_techniques, ...aggregates.new_malware, ...aggregates.new_tools, ...aggregates.new_infrastructure].forEach((item) => ids.add(item.id));
    // Victim buckets are keyed by the victim entity
    [...aggregates.new_victims_by_sector, ...aggregates.new_victims_by_country, ...aggregates.new_victims_by_region].forEach((bucket) => ids.add(bucket.key));
  }
  return [...ids];
};

/**
 * Stored results are only served while the user can still access every element that shaped them, counted or named:
 * a reclassification after the computation (new marking, restricted sharing) is never leaked, not even as a count.
 * A result whose contributors are unknown is never served.
 */
export const isLandscapeResultAccessible = async (
  context: AuthContext,
  user: AuthUser,
  contributors: string[] | null,
  aggregates: LandscapeDiffAggregates | null,
  entities: LandscapeDiffEntitySummary[],
) => {
  if (!contributors) return false;
  const ids = [...new Set([...contributors, ...landscapeResultReferencedIds(aggregates, entities)])];
  if (ids.length === 0) return true;
  const accessible = await internalFindByIdsMapped<BasicStoreObject>(context, user, ids, { baseData: true });
  return ids.every((id) => !!accessible[id]);
};

/**
 * Widgets use relative dates: the end of the period is aligned on the next minute so the requests of a minute share
 * one cache key without excluding the changes made during the requested period.
 */
export const alignSummaryEnd = (to: string): string => {
  const requestedTo = utcDate(to);
  const flooredTo = requestedTo.clone().startOf('minute');
  return (flooredTo.isSame(requestedTo) ? flooredTo : flooredTo.add(1, 'minute')).toISOString();
};

/**
 * Synchronous landscape diff bounded to a small number of entities, used by dashboard widgets.
 * Results are cached per user for the cache duration.
 */
export const landscapeDiffSummary = async (context: AuthContext, user: AuthUser, rawInput: LandscapeDiffInputData): Promise<LandscapeDiffSummaryResult> => {
  const groupBy = rawInput.group_by ?? 'entity_type';
  if (!LANDSCAPE_GROUP_BY_VALUES.includes(groupBy)) {
    throw ValidationError('Invalid group by', 'group_by', { group_by: groupBy });
  }
  const dates = normalizeLandscapeDates(rawInput);
  const to = alignSummaryEnd(dates.to);
  const input: LandscapeDiffInputData = { ...rawInput, from: dates.from, to, group_by: groupBy };
  const scope = await resolveLandscapeScope(context, user, input);
  const cacheKey = `${LANDSCAPE_SUMMARY_PREFIX}${landscapeDiffCacheKey(user.id, userAccessFingerprint(context, user), input, scope)}`;
  const cached = await getClientBase().get(cacheKey);
  if (cached) {
    let cachedEntry: Partial<CachedLandscapeSummary> | null = null;
    try {
      cachedEntry = JSON.parse(cached) as Partial<CachedLandscapeSummary>;
    } catch {
      logApp.warn('[TIME MACHINE] Landscape diff summary cache could not be parsed');
    }
    const cachedResult = isCachedSummaryCovering(cachedEntry?.computed_until, dates.to) ? cachedEntry?.result : undefined;
    if (cachedResult && await isLandscapeResultAccessible(context, user, cachedEntry?.contributors ?? null, cachedResult.aggregates, cachedResult.entities)) {
      return cachedResult;
    }
  }
  // A fresh result is checked like a stored one: an element reclassified during the computation is never leaked.
  // It is computed again once, then refused when access keeps changing.
  const computeAccessible = async () => {
    const computed = await computeLandscapeDiff(context, user, scope, input.from, input.to, groupBy, { maxEntities: LANDSCAPE_WIDGET_MAX_ENTITIES });
    const accessible = await isLandscapeResultAccessible(context, user, computed.contributors, computed.aggregates, computed.entities);
    return accessible ? computed : null;
  };
  const computedUntil = now();
  const computation = (await computeAccessible()) ?? (await computeAccessible());
  if (!computation) throw FunctionalError(LANDSCAPE_ACCESS_CHANGED_MESSAGE);
  const result: LandscapeDiffSummaryResult = {
    from: input.from,
    to: input.to,
    scope_entity_types: scope.entityTypes,
    computed_at: now(),
    truncated: computation.truncated,
    aggregates: computation.aggregates,
    entities: computation.entities,
  };
  const entry: CachedLandscapeSummary = { result, contributors: computation.contributors, computed_until: computedUntil };
  await getClientBase().set(cacheKey, JSON.stringify(entry), 'EX', LANDSCAPE_CACHE_TTL);
  addLandscapeDiffCount();
  return result;
};

// Every complete result is checked against its contributors before it is returned, the first time included
const revalidateCompleteState = async (context: AuthContext, user: AuthUser, state: LandscapeDiffState): Promise<LandscapeDiffState> => {
  if (state.status !== 'complete') return state;
  if (await isLandscapeResultAccessible(context, user, await readContributors(state.id), state.aggregates, state.entities)) return state;
  const outdated: LandscapeDiffState = {
    ...state,
    status: 'failed',
    error: LANDSCAPE_ACCESS_CHANGED_MESSAGE,
    aggregates: null,
    entities: [],
    updated_at: now(),
  };
  await writeState(outdated);
  return outdated;
};

export const findLandscapeDiff = async (context: AuthContext, user: AuthUser, id: string): Promise<LandscapeDiffState | null> => {
  const state = await readState(id);
  // A landscape diff is only visible to the user who requested it, with the rights it was computed with
  if (!state || state.user_id !== user.id || state.access_fingerprint !== userAccessFingerprint(context, user)) return null;
  const isRunning = state.status === 'running' || state.status === 'pending';
  if (isRunning && utcDate().diff(utcDate(state.updated_at), 'seconds') > LANDSCAPE_STALE_SECONDS) {
    const interrupted: LandscapeDiffState = { ...state, status: 'failed', error: LANDSCAPE_INTERRUPTED_MESSAGE, updated_at: now() };
    if (await finalizeStaleLandscapeState(state, interrupted)) {
      // Aborts the computation and frees its slot when it runs on this node; on another node its next write stops it.
      // Its slot of the platform is freed now, whatever node runs it
      landscapeRunSlots.release(state.id, LANDSCAPE_INTERRUPTED_MESSAGE);
      await releaseClusterSlot(state.id, state.user_id);
      return interrupted;
    }
    // The run progressed since it was read: its owner is alive, and it may have completed in the meantime
    const progressed = await readState(id);
    return progressed ? revalidateCompleteState(context, user, progressed) : null;
  }
  return revalidateCompleteState(context, user, state);
};
// endregion
