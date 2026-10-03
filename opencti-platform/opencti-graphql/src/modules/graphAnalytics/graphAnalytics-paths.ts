import conf from '../../config/conf';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase, BasicStoreEntity, BasicStoreRelation } from '../../types/store';
import { computeQueryIndices, elFindByIds, elList } from '../../database/engine';
import { buildRelationsFilter, storeLoadById } from '../../database/middleware-loader';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../schema/general';
import { isStixCoreObject } from '../../schema/stixCoreObject';
import { isStixCoreRelationship } from '../../schema/stixCoreRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { RELATION_OBJECT } from '../../schema/stixRefRelationship';
import { getParentTypes } from '../../schema/schemaUtils';
import { FunctionalError } from '../../config/errors';
import { READ_ENTITIES_INDICES } from '../../database/utils';
import { addGraphPathQueryCount } from '../../manager/telemetryManager';
import { type PathEdge, type PathExpansion, searchPaths } from './graphAnalytics-pathfinder';
import { PATH_DEFAULT_RELATIONSHIP_TYPES } from './graphAnalytics-features';
import { resolveConcreteEntityType } from './graphAnalytics-store';
import type { StixPathsSearchResult } from './graphAnalytics-types';

const PATH_DEFAULT_DEPTH: number = conf.get('graph_analytics:path_default_depth') ?? 4;
const PATH_MAX_DEPTH: number = conf.get('graph_analytics:path_max_depth') ?? 6;
const PATH_DEFAULT_PATHS: number = conf.get('graph_analytics:path_default_paths') ?? 5;
const PATH_MAX_PATHS: number = conf.get('graph_analytics:path_max_paths') ?? 20;
const PATH_TIMEOUT_MS: number = conf.get('graph_analytics:path_timeout_ms') ?? 15000;
const PATH_MAX_EXPANDED_NODES: number = conf.get('graph_analytics:path_max_expanded_nodes') ?? 20000;
const PATH_MAX_RELATIONSHIPS_PER_LEVEL: number = conf.get('graph_analytics:path_max_relationships_per_level') ?? 20000;
const PATH_MAX_PARENTS_PER_NODE: number = conf.get('graph_analytics:path_max_parents_per_node') ?? 8;

const clamp = (value: number | null | undefined, fallback: number, min: number, max: number) => {
  const number = value ?? fallback;
  if (!Number.isFinite(number)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(number)));
};

export interface StixPathsArgs {
  fromId: string;
  toId: string;
  maxDepth?: number | null;
  maxPaths?: number | null;
  relationshipTypes?: string[] | null;
  entityTypes?: string[] | null;
  includeInferred?: boolean | null;
  includeContainers?: boolean | null;
}

export const resolvePathRelationshipTypes = (relationshipTypes: string[] | null | undefined, includeContainers: boolean): string[] => {
  const requested = relationshipTypes && relationshipTypes.length > 0 ? relationshipTypes : PATH_DEFAULT_RELATIONSHIP_TYPES;
  requested.forEach((type) => {
    const allowed = type === ABSTRACT_STIX_CORE_RELATIONSHIP || type === STIX_SIGHTING_RELATIONSHIP || isStixCoreRelationship(type);
    if (!allowed) {
      throw FunctionalError('Path finder only traverses stix core relationships and sightings', { type });
    }
  });
  const types = Array.from(new Set(requested));
  if (includeContainers && !types.includes(RELATION_OBJECT)) {
    types.push(RELATION_OBJECT);
  }
  return types;
};

export const isAcceptedPathEntityType = (entityType: string, entityTypes: string[] | null | undefined): boolean => {
  if (!isStixCoreObject(entityType)) return false;
  if (!entityTypes || entityTypes.length === 0) return true;
  if (entityTypes.includes(entityType)) return true;
  return getParentTypes(entityType).some((parent: string) => entityTypes.includes(parent));
};

const relationsToExpansion = (relations: BasicStoreRelation[], nodeIds: string[], limit: number): PathExpansion => {
  const nodes = new Set(nodeIds);
  const edges = new Map<string, PathEdge[]>();
  const push = (nodeId: string, edge: PathEdge) => {
    const list = edges.get(nodeId) ?? [];
    list.push(edge);
    edges.set(nodeId, list);
  };
  const kept = relations.slice(0, limit);
  kept.forEach((relation) => {
    if (nodes.has(relation.fromId)) {
      push(relation.fromId, { relationship_id: relation.internal_id, relationship_type: relation.relationship_type, neighbor_id: relation.toId, neighbor_type: relation.toType });
    }
    if (nodes.has(relation.toId)) {
      push(relation.toId, { relationship_id: relation.internal_id, relationship_type: relation.relationship_type, neighbor_id: relation.fromId, neighbor_type: relation.fromType });
    }
  });
  return { edges, relationshipsCount: kept.length, truncated: relations.length > limit };
};

export interface StixPathsResolvedResult extends Omit<StixPathsSearchResult, 'paths'> {
  from: BasicStoreBase;
  to: BasicStoreBase;
  paths: Array<{
    length: number;
    node_ids: string[];
    relationship_ids: string[];
    relationship_types: string[];
    nodes: BasicStoreBase[];
    relationships: BasicStoreBase[];
  }>;
}

/**
 * Paths between two entities, computed as the caller: relationships are listed with the caller's access,
 * and every intermediate node is checked against the caller's markings and organizations before it is traversed.
 */
export const findStixPaths = async (context: AuthContext, user: AuthUser, args: StixPathsArgs): Promise<StixPathsResolvedResult> => {
  const from = await storeLoadById<BasicStoreEntity>(context, user, args.fromId, ABSTRACT_STIX_CORE_OBJECT);
  const to = await storeLoadById<BasicStoreEntity>(context, user, args.toId, ABSTRACT_STIX_CORE_OBJECT);
  if (!from || !to) {
    throw FunctionalError('Path finder endpoints must be existing entities you can access', { fromId: args.fromId, toId: args.toId });
  }
  if (from.internal_id === to.internal_id) {
    throw FunctionalError('Path finder endpoints must be two different entities', { id: from.internal_id });
  }
  const maxDepth = clamp(args.maxDepth, PATH_DEFAULT_DEPTH, 1, PATH_MAX_DEPTH);
  const maxPaths = clamp(args.maxPaths, PATH_DEFAULT_PATHS, 1, PATH_MAX_PATHS);
  const relationshipTypes = resolvePathRelationshipTypes(args.relationshipTypes, !!args.includeContainers);
  const indices = computeQueryIndices(undefined, relationshipTypes, !!args.includeInferred) as string[];
  const expand = async (nodeIds: string[], limit: number): Promise<PathExpansion> => {
    const relations = await elList<BasicStoreRelation>(context, user, indices, {
      ...buildRelationsFilter(relationshipTypes, { fromOrToId: nodeIds }),
      baseData: true,
      first: Math.min(limit + 1, 5000),
      maxSize: limit + 1,
    });
    return relationsToExpansion(relations, nodeIds, limit);
  };
  // the endpoints were loaded with the caller's access above; the entity types only restrict the intermediate nodes
  const endpointIds = new Set([from.internal_id, to.internal_id]);
  const acceptNodes = async (nodes: Array<{ id: string; type: string }>): Promise<Set<string>> => {
    const accepted = new Set(nodes.filter((node) => endpointIds.has(node.id)).map((node) => node.id));
    const candidates = nodes.filter((node) => !endpointIds.has(node.id) && isAcceptedPathEntityType(node.type, args.entityTypes));
    if (candidates.length === 0) return accepted;
    const accessible = await elFindByIds<BasicStoreBase>(context, user, candidates.map((c) => c.id), {
      indices: READ_ENTITIES_INDICES,
      baseData: true,
    }) as BasicStoreBase[];
    accessible.forEach((a) => accepted.add(a.internal_id));
    return accepted;
  };
  const result = await searchPaths({
    fromId: from.internal_id,
    toId: to.internal_id,
    maxDepth,
    maxPaths,
    maxExpandedNodes: PATH_MAX_EXPANDED_NODES,
    maxRelationshipsPerLevel: PATH_MAX_RELATIONSHIPS_PER_LEVEL,
    maxParentsPerNode: PATH_MAX_PARENTS_PER_NODE,
    deadline: Date.now() + PATH_TIMEOUT_MS,
    expand,
    acceptNodes,
  });
  addGraphPathQueryCount();
  // Resolve the elements of the paths with the caller's access, a path with a missing element is dropped
  const nodeIds = Array.from(new Set(result.paths.flatMap((p) => p.node_ids)));
  const relationshipIds = Array.from(new Set(result.paths.flatMap((p) => p.relationship_ids)));
  const nodes = nodeIds.length > 0
    ? await elFindByIds<BasicStoreBase>(context, user, nodeIds, { toMap: true, indices: READ_ENTITIES_INDICES }) as Record<string, BasicStoreBase>
    : {};
  const relationships = relationshipIds.length > 0
    ? await elFindByIds<BasicStoreBase>(context, user, relationshipIds, { toMap: true, indices }) as Record<string, BasicStoreBase>
    : {};
  const paths = result.paths
    .filter((path) => path.node_ids.every((id) => nodes[id]) && path.relationship_ids.every((id) => relationships[id]))
    .map((path) => ({
      ...path,
      length: path.relationship_ids.length,
      nodes: path.node_ids.map((id) => nodes[id]),
      relationships: path.relationship_ids.map((id) => relationships[id]),
    }));
  return { ...result, from, to, paths };
};

export interface NeighborhoodSummary {
  id: string;
  total: number;
  by_relationship_type: Array<{ label: string; value: number }>;
  by_entity_type: Array<{ label: string; value: number }>;
  pairs: Array<{ relationship_type: string; entity_type: string; value: number }>;
  truncated: boolean;
}

const countEntries = (counts: Map<string, number>) => Array.from(counts.entries())
  .map(([label, value]) => ({ label, value }))
  .sort((a, b) => b.value - a.value);

/**
 * Counts per relationship type and per neighbor entity type, as visible by the caller:
 * a relationship is counted only when the caller can read both the relationship and the neighbor at its other end.
 */
export const stixNeighborhoodSummary = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
  includeInferred: boolean,
): Promise<NeighborhoodSummary> => {
  const entity = await storeLoadById<BasicStoreEntity>(context, user, id, ABSTRACT_STIX_CORE_OBJECT);
  if (!entity) {
    throw FunctionalError('Entity not found or not accessible', { id });
  }
  const types = PATH_DEFAULT_RELATIONSHIP_TYPES;
  const indices = computeQueryIndices(undefined, types, includeInferred) as string[];
  const limit = PATH_MAX_RELATIONSHIPS_PER_LEVEL;
  const relations = await elList<BasicStoreRelation>(context, user, indices, {
    ...buildRelationsFilter(types, { fromOrToId: [entity.internal_id] }),
    baseData: true,
    first: Math.min(limit + 1, 5000),
    maxSize: limit + 1,
  });
  const kept = relations.slice(0, limit);
  const neighborOf = (relation: BasicStoreRelation) => (relation.fromId === entity.internal_id
    ? { id: relation.toId, type: relation.toType }
    : { id: relation.fromId, type: relation.fromType });
  const neighborIds = Array.from(new Set(kept.map((relation) => neighborOf(relation).id)));
  const accessible = neighborIds.length > 0
    ? await elFindByIds<BasicStoreBase>(context, user, neighborIds, { indices: READ_ENTITIES_INDICES, baseData: true }) as BasicStoreBase[]
    : [];
  const accessibleIds = new Set(accessible.map((neighbor) => neighbor.internal_id));
  const byRelationship = new Map<string, number>();
  const byEntity = new Map<string, number>();
  const pairs = new Map<string, NeighborhoodSummary['pairs'][number]>();
  let total = 0;
  kept.forEach((relation) => {
    const neighbor = neighborOf(relation);
    if (!accessibleIds.has(neighbor.id)) return;
    total += 1;
    const relationshipType = relation.relationship_type;
    byRelationship.set(relationshipType, (byRelationship.get(relationshipType) ?? 0) + 1);
    const entityType = resolveConcreteEntityType(neighbor.type);
    if (!entityType) return;
    byEntity.set(entityType, (byEntity.get(entityType) ?? 0) + 1);
    const pairKey = `${relationshipType}|${entityType}`;
    const pair = pairs.get(pairKey) ?? { relationship_type: relationshipType, entity_type: entityType, value: 0 };
    pair.value += 1;
    pairs.set(pairKey, pair);
  });
  return {
    id: entity.internal_id,
    total,
    by_relationship_type: countEntries(byRelationship),
    by_entity_type: countEntries(byEntity),
    pairs: Array.from(pairs.values()).sort((a, b) => b.value - a.value),
    truncated: relations.length > limit,
  };
};
