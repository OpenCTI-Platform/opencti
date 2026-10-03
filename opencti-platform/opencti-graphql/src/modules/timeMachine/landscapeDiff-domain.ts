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
import { executionContext } from '../../utils/access';
import { getDraftContext } from '../../utils/draftContext';
import { now, utcDate } from '../../utils/format';
import { doYield } from '../../utils/eventloop-utils';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity, BasicStoreObject, BasicStoreRelation } from '../../types/store';
import type { FilterGroup } from '../../generated/graphql';
import { OrderingMode } from '../../generated/graphql';
import { addLandscapeDiffCount } from '../../manager/telemetryManager';
import { changeFieldKey, firstNumber } from './timeMachine-replay';
import { fetchElementsHistoryEvents, fetchRelationshipsHistoryEvents } from './timeMachine-history';
import { buildRelationshipStates, TIME_MACHINE_RELATIONSHIP_TYPES } from './timeMachine-relationships';
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
const LANDSCAPE_MAX_EVENTS_PER_BATCH = 20000;
// Maximum number of entities and items kept in a landscape diff result
const LANDSCAPE_MAX_ENTITY_SUMMARIES = 200;
const LANDSCAPE_MAX_ITEMS = 50;
// A running computation that did not report progress for this duration is considered interrupted
const LANDSCAPE_STALE_SECONDS = 120;

const LANDSCAPE_WIDGET_MAX_ENTITIES: number = conf.get('time_machine:widget_max_entities') || 200;

const LANDSCAPE_STATE_PREFIX = 'landscape_diff:';
const LANDSCAPE_KEY_PREFIX = 'landscape_diff_key:';
const LANDSCAPE_SUMMARY_PREFIX = 'landscape_diff_summary:';

export const LANDSCAPE_GROUP_BY_VALUES = ['entity_type', 'relationship_type', 'tactic'];

const INFRASTRUCTURE_TYPES = [ENTITY_TYPE_INFRASTRUCTURE, ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR, ENTITY_DOMAIN_NAME, ENTITY_URL, ENTITY_HOSTNAME];

// Saved filters are scoped to the list they were created in, this maps the list scope to its entity types
const SAVED_FILTER_SCOPES: Record<string, string[]> = {
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
  malwareAnalyses: ['Malware-Analysis'],
  sectors: ['Sector'],
  organizations: ['Organization'],
  individuals: ['Individual'],
  systems: ['System'],
  events: ['Event'],
  countries: ['Country'],
  regions: ['Region'],
  cities: ['City'],
  positions: ['Position'],
  administrativeAreas: ['Administrative-Area'],
  infrastructures: ['Infrastructure'],
  indicators: ['Indicator'],
  stixCyberObservables: ['Stix-Cyber-Observable'],
  securityPlatforms: ['SecurityPlatform'],
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
  const filterGroups: FilterGroup[] = [];
  let entityTypes = input.entity_types && input.entity_types.length > 0 ? input.entity_types : null;
  if (input.saved_filter_id) {
    const savedFilter = await internalLoadById<BasicStoreEntitySavedFilter>(context, user, input.saved_filter_id, { type: ENTITY_TYPE_SAVED_FILTER });
    if (!savedFilter) throw FunctionalError('Saved filter not found', { id: input.saved_filter_id });
    const savedFilters = parseFilters(savedFilter.filters);
    if (savedFilters) filterGroups.push(savedFilters);
    entityTypes = entityTypes ?? savedFilterScopeEntityTypes(savedFilter.scope);
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
  const customFilters = parseFilters(input.filters);
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
  targets: Map<string, TargetAccumulator>;
  // A relationship between entities of two batches is read by both: global counters count it once
  countedRelationships: Set<string>;
  countedRelationshipStates: Set<string>;
  relationshipsFetched: number;
  truncated: boolean;
}

export interface LandscapeDiffComputation {
  aggregates: LandscapeDiffAggregates;
  entities: LandscapeDiffEntitySummary[];
  total: number;
  truncated: boolean;
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
  // 1. Relationships created in the period. The budget applies to distinct relationships: a relationship
  // already counted from another batch can be read once more, so the read is sized to let it through.
  const budget = LANDSCAPE_MAX_RELATIONSHIPS - acc.relationshipsFetched;
  const maxSize = budget > 0 ? budget + acc.countedRelationships.size : 0;
  const relations = maxSize > 0 ? await fullRelationsList<BasicStoreRelation>(context, user, [ABSTRACT_STIX_CORE_RELATIONSHIP, STIX_SIGHTING_RELATIONSHIP], {
    fromOrToId: ids,
    indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
    startDate: from,
    endDate: to,
    dateAttribute: 'created_at',
    maxSize,
    baseData: true,
    baseFields: ['created_at'],
  } as any) : [];
  if (maxSize <= 0 || relations.length >= maxSize) acc.truncated = true;
  let newRelationships = 0;
  relations.forEach((relation) => {
    if (!acc.countedRelationships.has(relation.internal_id)) {
      if (newRelationships >= budget) {
        acc.truncated = true;
        return;
      }
      newRelationships += 1;
      acc.countedRelationships.add(relation.internal_id);
      acc.newRelationships += 1;
      increment(acc.newRelationshipsByType, relation.entity_type);
    }
    // Each scoped side is in exactly one batch, so per-entity counters are updated once
    if (idSet.has(relation.fromId)) {
      acc.entities.get(relation.fromId)!.relationships_added += 1;
      registerTarget(acc, relation.toId, relation.toType, relation.entity_type, relation.fromId);
    }
    if (idSet.has(relation.toId)) {
      acc.entities.get(relation.toId)!.relationships_added += 1;
      registerTarget(acc, relation.fromId, relation.fromType, relation.entity_type, relation.toId);
    }
  });
  acc.relationshipsFetched += newRelationships;
  // 2. Relationships removed or revoked in the period
  const relationshipEvents = await fetchRelationshipsHistoryEvents(context, user, ids, {
    from,
    to,
    scopes: ['create', 'delete', 'update'],
    entityTypes: TIME_MACHINE_RELATIONSHIP_TYPES,
    max: LANDSCAPE_MAX_EVENTS_PER_BATCH,
  });
  if (relationshipEvents.length >= LANDSCAPE_MAX_EVENTS_PER_BATCH) acc.truncated = true;
  buildRelationshipStates(relationshipEvents).forEach((state, relationshipId) => {
    if (state.created) return; // Created in the period: counted with the new relationships (or no net change)
    const sides = [state.from_id, state.to_id].filter((id): id is string => !!id && idSet.has(id));
    const countGlobally = !acc.countedRelationshipStates.has(relationshipId);
    if (state.deleted) {
      acc.countedRelationshipStates.add(relationshipId);
      if (countGlobally) acc.removedRelationships += 1;
      sides.forEach((id) => {
        acc.entities.get(id)!.relationships_removed += 1;
      });
    } else if (state.revoked_after === 'true' && state.revoked_before !== 'true') {
      acc.countedRelationshipStates.add(relationshipId);
      if (countGlobally) acc.revocations += 1;
      sides.forEach((id) => {
        acc.entities.get(id)!.relationships_revoked += 1;
      });
    }
  });
  // 3. Updates of the entities themselves in the period
  const entityEvents = await fetchElementsHistoryEvents(context, user, ids, {
    from,
    to,
    scopes: ['update', 'merge'],
    max: LANDSCAPE_MAX_EVENTS_PER_BATCH,
    order: 'asc',
  });
  if (entityEvents.length >= LANDSCAPE_MAX_EVENTS_PER_BATCH) acc.truncated = true;
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
    + (entity.created_in_period ? 5 : 0)
    + (entity.revoked_in_period ? 5 : 0)
    + Math.round((confidenceDelta + scoreDelta) / 10);
};

const buildNamedItems = (
  acc: GlobalAccumulator,
  resolved: Record<string, BasicStoreObject>,
  predicate: (target: TargetAccumulator) => boolean,
): LandscapeDiffNamedItem[] => {
  const items: LandscapeDiffNamedItem[] = [];
  acc.targets.forEach((target, id) => {
    const element = resolved[id];
    if (element && predicate(target)) {
      items.push({ id, entity_type: element.entity_type, name: extractEntityRepresentativeName(element), count: target.entityIds.size });
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
  // Indicators are only counted, but a visible relationship can point to an indicator the user cannot access
  const indicatorIds = [...acc.targets.entries()]
    .filter(([, target]) => target.type === ENTITY_TYPE_INDICATOR && target.relationshipTypes.has(RELATION_INDICATES))
    .map(([id]) => id);
  const accessibleIndicators = indicatorIds.length > 0 ? await internalFindByIdsMapped<BasicStoreObject>(context, user, indicatorIds, { baseData: true }) : {};
  const indicatorsCount = indicatorIds.filter((id) => !!accessibleIndicators[id]).length;
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
    confidence_changes: entities.filter((e) => hasChanged(e.confidence_before, e.confidence_after)).length,
    score_changes: entities.filter((e) => hasChanged(e.score_before, e.score_after)).length,
    new_techniques_by_tactic: toBuckets(techniquesByTactic),
    new_techniques: techniques.slice(0, LANDSCAPE_MAX_ITEMS),
    new_malware: buildNamedItems(acc, resolved, uses(ENTITY_TYPE_MALWARE)).slice(0, LANDSCAPE_MAX_ITEMS),
    new_tools: buildNamedItems(acc, resolved, uses(ENTITY_TYPE_TOOL)).slice(0, LANDSCAPE_MAX_ITEMS),
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
      entity_type: e.entity.entity_type,
      name: extractEntityRepresentativeName(e.entity),
      created_in_period: e.created_in_period,
      revoked_in_period: e.revoked_in_period,
      attributes_changed: e.changed_keys.size,
      relationships_added: e.relationships_added,
      relationships_removed: e.relationships_removed,
      relationships_revoked: e.relationships_revoked,
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
  opts: { maxEntities?: number; onProgress?: (progress: number, total: number) => Promise<void> } = {},
): Promise<LandscapeDiffComputation> => {
  const maxEntities = opts.maxEntities ?? LANDSCAPE_MAX_ENTITIES;
  const scopeEntities = await topEntitiesList<BasicStoreEntity>(context, user, scope.entityTypes, {
    filters: scope.filters,
    first: maxEntities + 1,
    orderBy: 'created_at',
    orderMode: OrderingMode.Desc,
    endDate: to,
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
    }])),
    newRelationshipsByType: new Map(),
    newRelationships: 0,
    removedRelationships: 0,
    revocations: 0,
    targets: new Map(),
    countedRelationships: new Set(),
    countedRelationshipStates: new Set(),
    relationshipsFetched: 0,
    truncated: truncatedScope,
  };
  await opts.onProgress?.(0, entities.length);
  for (let index = 0; index < entities.length; index += LANDSCAPE_BATCH_SIZE) {
    await doYield();
    const batch = entities.slice(index, index + LANDSCAPE_BATCH_SIZE);
    await processBatch(context, user, batch, from, to, acc);
    await opts.onProgress?.(Math.min(index + batch.length, entities.length), entities.length);
  }
  const aggregates = await buildAggregates(context, user, acc, entities.length, groupBy);
  return { aggregates, entities: buildEntitySummaries(acc), total: entities.length, truncated: acc.truncated };
};
// endregion

// region Background execution with progress and cache
const runningByUser = new Map<string, number>();
let runningTotal = 0;

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

const writeState = async (state: LandscapeDiffState) => {
  const ttl = Math.max(1, utcDate(state.expires_at).diff(utcDate(), 'seconds'));
  await getClientBase().set(stateKey(state.id), JSON.stringify(state), 'EX', ttl);
};

/**
 * Fingerprint of everything the results depend on in the rights of the user: a cached result
 * computed before a change of capabilities, markings, organizations or groups is never reused.
 */
export const userAccessFingerprint = (context: AuthContext, user: AuthUser) => {
  const ids = (items: Array<{ internal_id?: string; id?: string }> | undefined) => (items ?? []).map((item) => item.internal_id ?? item.id ?? '').sort();
  const payload = JSON.stringify({
    capabilities: (user.capabilities ?? []).map((capability) => capability.name).sort(),
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

const executeLandscapeDiff = async (requestContext: AuthContext, user: AuthUser, state: LandscapeDiffState, scope: LandscapeScope) => {
  // The computation outlives the request: it gets its own context, with the same organization evaluation
  // and the same draft as the request so it reads the same knowledge
  const context: AuthContext = {
    ...executionContext('landscape_diff', user),
    user_inside_platform_organization: requestContext.user_inside_platform_organization,
    draft_context: getDraftContext(requestContext, user),
  };
  let current: LandscapeDiffState = { ...state, status: 'running', updated_at: now() };
  await writeState(current);
  try {
    const computation = await computeLandscapeDiff(context, user, scope, state.input.from, state.input.to, state.input.group_by ?? 'entity_type', {
      onProgress: async (progress, total) => {
        current = { ...current, progress, total, updated_at: now() };
        await writeState(current);
      },
    });
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
    await writeState(current);
    addLandscapeDiffCount();
  } catch (err) {
    logApp.error('[TIME MACHINE] Landscape diff computation failed', { cause: err, id: state.id });
    await writeState({ ...current, status: 'failed', error: (err as Error)?.message ?? 'Landscape diff computation failed', updated_at: now() });
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
  // Slots are reserved before any await so concurrent requests cannot exceed the limits
  const userRunning = runningByUser.get(user.id) ?? 0;
  if (userRunning >= LANDSCAPE_MAX_RUNNING_PER_USER || runningTotal >= LANDSCAPE_MAX_RUNNING) {
    throw FunctionalError('Too many landscape diffs are being computed, please retry later');
  }
  runningByUser.set(user.id, userRunning + 1);
  runningTotal += 1;
  const releaseSlot = () => {
    const remaining = (runningByUser.get(user.id) ?? 1) - 1;
    if (remaining > 0) {
      runningByUser.set(user.id, remaining);
    } else {
      runningByUser.delete(user.id);
    }
    runningTotal = Math.max(0, runningTotal - 1);
  };
  const createdAt = now();
  const state: LandscapeDiffState = {
    id: uuidv4(),
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
  void executeLandscapeDiff(context, user, state, scope).catch((err) => {
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
 * Stored results embed the names of the entities they reference: they are only served while the user can still
 * access every one of them, so a reclassification after the computation (new marking, restricted sharing) is never leaked.
 */
const isLandscapeResultAccessible = async (
  context: AuthContext,
  user: AuthUser,
  aggregates: LandscapeDiffAggregates | null,
  entities: LandscapeDiffEntitySummary[],
) => {
  const ids = landscapeResultReferencedIds(aggregates, entities);
  if (ids.length === 0) return true;
  const accessible = await internalFindByIdsMapped<BasicStoreObject>(context, user, ids, { baseData: true });
  return ids.every((id) => !!accessible[id]);
};

/**
 * Widgets use relative dates: the end of the period is aligned on the next minute so the cache is effective
 * without excluding the changes made during the requested period.
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
    let cachedResult: LandscapeDiffSummaryResult | null = null;
    try {
      cachedResult = JSON.parse(cached) as LandscapeDiffSummaryResult;
    } catch {
      logApp.warn('[TIME MACHINE] Landscape diff summary cache could not be parsed');
    }
    if (cachedResult && await isLandscapeResultAccessible(context, user, cachedResult.aggregates, cachedResult.entities)) {
      return cachedResult;
    }
  }
  const computation = await computeLandscapeDiff(context, user, scope, input.from, input.to, groupBy, { maxEntities: LANDSCAPE_WIDGET_MAX_ENTITIES });
  const result: LandscapeDiffSummaryResult = {
    from: input.from,
    to: input.to,
    scope_entity_types: scope.entityTypes,
    computed_at: now(),
    truncated: computation.truncated,
    aggregates: computation.aggregates,
    entities: computation.entities,
  };
  await getClientBase().set(cacheKey, JSON.stringify(result), 'EX', LANDSCAPE_CACHE_TTL);
  addLandscapeDiffCount();
  return result;
};

export const findLandscapeDiff = async (context: AuthContext, user: AuthUser, id: string): Promise<LandscapeDiffState | null> => {
  const state = await readState(id);
  // A landscape diff is only visible to the user who requested it, with the rights it was computed with
  if (!state || state.user_id !== user.id || state.access_fingerprint !== userAccessFingerprint(context, user)) return null;
  const isRunning = state.status === 'running' || state.status === 'pending';
  if (isRunning && utcDate().diff(utcDate(state.updated_at), 'seconds') > LANDSCAPE_STALE_SECONDS) {
    const interrupted: LandscapeDiffState = { ...state, status: 'failed', error: 'Landscape diff computation was interrupted', updated_at: now() };
    await writeState(interrupted);
    return interrupted;
  }
  if (state.status === 'complete' && !await isLandscapeResultAccessible(context, user, state.aggregates, state.entities)) {
    const outdated: LandscapeDiffState = {
      ...state,
      status: 'failed',
      error: 'Access to the knowledge of this landscape diff changed, it must be computed again',
      aggregates: null,
      entities: [],
      updated_at: now(),
    };
    await writeState(outdated);
    return outdated;
  }
  return state;
};
// endregion
