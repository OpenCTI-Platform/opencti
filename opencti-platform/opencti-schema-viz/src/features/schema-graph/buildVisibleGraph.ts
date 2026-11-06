import { descendantsAndSelf } from '../../data/normalizeSchema';
import type { NormalizedSchema, RelationKind, SchemaPath, SchemaRelation, ToggleableCategory } from '../../data/schemaTypes';
import {
  groupNodeId,
  inheritanceEdgeId,
  parseRevealKey,
  pathStepEndpoints,
  relationEdgeId,
  type RelationDirection,
  typeNodeId,
} from './graphIds';

/** Above this many hidden counterparts, an expanded relation collapses them into a target group. */
export const GROUP_THRESHOLD = 3;

/** Allowed between almost any pair of types: drawn on expansion, but not when connecting visible types (nor are self-loops). */
export const GENERIC_RELATIONS: ReadonlySet<string> = new Set(['related-to', 'derived-from', 'duplicate-of']);

export type TypeRole = 'pinned' | 'neighbor';

export interface TypeGraphNode {
  kind: 'type';
  id: string;
  typeId: string;
  role: TypeRole;
}

export interface GroupGraphNode {
  kind: 'group';
  id: string;
  anchorTypeId: string;
  direction: RelationDirection;
  relationName: string;
  relationKind: RelationKind;
  typeIds: string[];
}

export type GraphNode = TypeGraphNode | GroupGraphNode;

export interface EdgeRelation {
  relationId: string;
  name: string;
  kind: RelationKind;
  /** Abstract type declared by the relation when the drawn endpoint is one of its descendants. */
  viaTypeId: string | null;
}

export interface InheritanceGraphEdge {
  kind: 'inheritance';
  id: string;
  source: string;
  target: string;
  /** The drawn parent is a farther ancestor because the direct parent is not on the canvas. */
  indirect: boolean;
}

export interface RelationGraphEdge {
  kind: 'relation';
  id: string;
  source: string;
  target: string;
  relations: EdgeRelation[];
  /** Comes from an expansion, a reveal or a path, rather than only from connecting visible types. */
  structural: boolean;
}

export type GraphEdge = InheritanceGraphEdge | RelationGraphEdge;

export interface VisibleGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface GraphScope {
  pinnedTypeIds: readonly string[];
  expandedTypeIds: readonly string[];
  /** Keys built with revealKey(). */
  revealedRelations: readonly string[];
  enabledCategories: Readonly<Record<ToggleableCategory, boolean>>;
  showInheritance: boolean;
  /** Draw every relation whose both ends are already on the canvas. */
  showRelations: boolean;
  includeRefs: boolean;
  path: SchemaPath | null;
}

interface Link {
  relation: SchemaRelation;
  counterpartTypeId: string;
}

interface Bucket {
  anchorTypeId: string;
  direction: RelationDirection;
  name: string;
  kind: RelationKind;
  links: Link[];
}

class EdgeCollector {
  private readonly relationEdges = new Map<string, RelationGraphEdge>();

  addRelation(source: string, target: string, relation: SchemaRelation, structural: boolean, viaTypeId: string | null = null) {
    const id = relationEdgeId(source, target);
    const edge = this.relationEdges.get(id) ?? { kind: 'relation', id, source, target, relations: [], structural };
    edge.structural ||= structural;
    if (!edge.relations.some((existing) => existing.relationId === relation.id && existing.viaTypeId === viaTypeId)) {
      edge.relations.push({ relationId: relation.id, name: relation.name, kind: relation.kind, viaTypeId });
    }
    this.relationEdges.set(id, edge);
  }

  values(): RelationGraphEdge[] {
    return [...this.relationEdges.values()].map((edge) => ({
      ...edge,
      relations: edge.relations.sort((a, b) => a.name.localeCompare(b.name) || a.relationId.localeCompare(b.relationId)),
    }));
  }
}

const pathGraph = (schema: NormalizedSchema, path: SchemaPath): VisibleGraph => {
  const edges = new EdgeCollector();
  for (const step of path.steps) {
    const relation = schema.relations.get(step.relationId);
    if (!relation) continue;
    const { sourceTypeId, targetTypeId } = pathStepEndpoints(relation, step);
    edges.addRelation(typeNodeId(sourceTypeId), typeNodeId(targetTypeId), relation, true, step.viaTypeId);
  }
  return {
    nodes: path.typeIds.map((typeId) => ({ kind: 'type', id: typeNodeId(typeId), typeId, role: 'pinned' })),
    edges: edges.values(),
  };
};

/**
 * Derives what the canvas shows from the user's scope: pinned types, the relations of expanded
 * types (hidden counterparts are added as neighbors, or folded into a target group when there are
 * too many), relations between visible types, and the inheritance tree between them.
 * Pure and deterministic, so the canvas only re-layouts when this result changes.
 */
export const buildVisibleGraph = (schema: NormalizedSchema, scope: GraphScope): VisibleGraph => {
  if (scope.path) return pathGraph(schema, scope.path);

  const isAllowed = (typeId: string) => {
    const type = schema.types.get(typeId);
    if (!type) return false;
    return type.category === 'Abstract' || scope.enabledCategories[type.category];
  };
  const isDrawnKind = (relation: SchemaRelation) => scope.includeRefs || relation.kind === 'relationship';
  const relationsOf = (ids: readonly string[] | undefined) => (ids ?? [])
    .map((id) => schema.relations.get(id))
    .filter((relation): relation is SchemaRelation => relation !== undefined && isDrawnKind(relation));

  const base = new Set(scope.pinnedTypeIds.filter(isAllowed));

  // Buckets: one per (anchor, direction, relation name)
  const buckets = new Map<string, Bucket>();
  const addLink = (anchorTypeId: string, direction: RelationDirection, relation: SchemaRelation, counterpartTypeId: string) => {
    if (!isAllowed(counterpartTypeId)) return;
    const key = groupNodeId(anchorTypeId, direction, relation.name);
    const bucket = buckets.get(key) ?? { anchorTypeId, direction, name: relation.name, kind: relation.kind, links: [] };
    if (!bucket.links.some((link) => link.relation.id === relation.id && link.counterpartTypeId === counterpartTypeId)) {
      bucket.links.push({ relation, counterpartTypeId });
    }
    buckets.set(key, bucket);
  };
  const addOutgoing = (anchorTypeId: string, relation: SchemaRelation) => {
    for (const target of relation.targetTypeIds) addLink(anchorTypeId, 'out', relation, target);
  };
  const addIncoming = (anchorTypeId: string, relation: SchemaRelation) => addLink(anchorTypeId, 'in', relation, relation.sourceTypeId);

  for (const typeId of scope.expandedTypeIds) {
    if (!base.has(typeId)) continue;
    for (const relation of relationsOf(schema.outgoing.get(typeId))) addOutgoing(typeId, relation);
    for (const relation of relationsOf(schema.incoming.get(typeId))) addIncoming(typeId, relation);
  }
  for (const key of scope.revealedRelations) {
    const { direction, anchorTypeId, relationId } = parseRevealKey(key);
    const relation = schema.relations.get(relationId);
    if (!relation || !base.has(anchorTypeId)) continue;
    if (direction === 'out') addOutgoing(anchorTypeId, relation);
    else addIncoming(anchorTypeId, relation);
  }

  // Pass 1: small buckets bring their counterparts onto the canvas.
  const visible = new Set(base);
  const grouped: Bucket[] = [];
  for (const bucket of buckets.values()) {
    const hidden = bucket.links.filter((link) => !base.has(link.counterpartTypeId));
    if (new Set(hidden.map((link) => link.counterpartTypeId)).size > GROUP_THRESHOLD) {
      grouped.push(bucket);
    } else {
      for (const link of hidden) visible.add(link.counterpartTypeId);
    }
  }

  const edges = new EdgeCollector();
  const nodes: GraphNode[] = [];
  const drawLink = (bucket: Bucket, link: Link) => {
    const anchor = typeNodeId(bucket.anchorTypeId);
    const counterpart = typeNodeId(link.counterpartTypeId);
    if (bucket.direction === 'out') edges.addRelation(anchor, counterpart, link.relation, true);
    else edges.addRelation(counterpart, anchor, link.relation, true);
  };

  // Pass 2: draw links, folding what is still hidden into target groups.
  for (const bucket of buckets.values()) {
    if (!grouped.includes(bucket)) {
      for (const link of bucket.links) drawLink(bucket, link);
      continue;
    }
    const hiddenLinks: Link[] = [];
    for (const link of bucket.links) {
      if (visible.has(link.counterpartTypeId)) drawLink(bucket, link);
      else hiddenLinks.push(link);
    }
    if (hiddenLinks.length === 0) continue;
    const id = groupNodeId(bucket.anchorTypeId, bucket.direction, bucket.name);
    const typeIds = [...new Set(hiddenLinks.map((link) => link.counterpartTypeId))]
      .sort((a, b) => (schema.types.get(a)?.label ?? a).localeCompare(schema.types.get(b)?.label ?? b));
    nodes.push({ kind: 'group', id, anchorTypeId: bucket.anchorTypeId, direction: bucket.direction, relationName: bucket.name, relationKind: bucket.kind, typeIds });
    const anchor = typeNodeId(bucket.anchorTypeId);
    for (const link of hiddenLinks) {
      if (bucket.direction === 'out') edges.addRelation(anchor, id, link.relation, true);
      else edges.addRelation(id, anchor, link.relation, true);
    }
  }

  if (scope.showRelations) {
    const descendantsCache = new Map<string, string[]>();
    const visibleDescendants = (typeId: string) => {
      if (!descendantsCache.has(typeId)) {
        descendantsCache.set(typeId, descendantsAndSelf(schema, typeId).filter((id) => id !== typeId && visible.has(id)));
      }
      return descendantsCache.get(typeId) as string[];
    };
    for (const relation of schema.relations.values()) {
      if (!isDrawnKind(relation) || GENERIC_RELATIONS.has(relation.name) || !visible.has(relation.sourceTypeId)) continue;
      const source = typeNodeId(relation.sourceTypeId);
      for (const target of relation.targetTypeIds) {
        if (target === relation.sourceTypeId) continue;
        if (visible.has(target)) {
          edges.addRelation(source, typeNodeId(target), relation, false);
        } else if (schema.types.get(target)?.isAbstract) {
          for (const descendant of visibleDescendants(target)) {
            if (descendant !== relation.sourceTypeId) edges.addRelation(source, typeNodeId(descendant), relation, false, target);
          }
        }
      }
    }
  }

  const inheritanceEdges: InheritanceGraphEdge[] = [];
  if (scope.showInheritance) {
    for (const typeId of visible) {
      const ancestors = schema.types.get(typeId)?.ancestorIds ?? [];
      const nearest = [...ancestors].reverse().find((ancestor) => visible.has(ancestor));
      if (!nearest) continue;
      const parent = typeNodeId(nearest);
      const child = typeNodeId(typeId);
      inheritanceEdges.push({ kind: 'inheritance', id: inheritanceEdgeId(parent, child), source: parent, target: child, indirect: nearest !== ancestors.at(-1) });
    }
  }

  const typeNodes: TypeGraphNode[] = [...visible]
    .sort((a, b) => a.localeCompare(b))
    .map((typeId) => ({ kind: 'type', id: typeNodeId(typeId), typeId, role: base.has(typeId) ? 'pinned' : 'neighbor' }));

  return {
    nodes: [...typeNodes, ...nodes],
    edges: [...inheritanceEdges.sort((a, b) => a.id.localeCompare(b.id)), ...edges.values()],
  };
};
