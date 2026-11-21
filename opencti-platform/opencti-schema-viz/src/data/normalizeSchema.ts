import type {
  AttributeDef,
  NormalizedSchema,
  RawSchema,
  RawTargetGroupNode,
  RawTypeNode,
  RelationKind,
  SchemaCategory,
  SchemaRelation,
  SchemaType,
  StixStatus,
} from './schemaTypes';

const INHERITANCE_LABEL = 'is-a';
const STIX_STATUSES: ReadonlySet<string> = new Set<StixStatus>(['builtin', 'extended', 'new']);

// Roots of each STIX family in the OpenCTI hierarchy.
const CATEGORY_ROOTS: ReadonlyArray<[string, SchemaCategory]> = [
  ['Stix-Domain-Object', 'SDO'],
  ['Stix-Cyber-Observable', 'SCO'],
  ['Stix-Meta-Object', 'Meta'],
  ['stix-relationship', 'SRO'],
];
const ABSTRACT_ROOTS: ReadonlySet<string> = new Set(['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'basic-relationship']);

const byLabel = (a: { label: string }, b: { label: string }) => a.label.localeCompare(b.label, 'en', { sensitivity: 'base' });

const isSlot = (node: RawTypeNode) => node.data.stixType !== undefined;

const categoryOf = (id: string, ancestorIds: string[]): SchemaCategory => {
  if (ABSTRACT_ROOTS.has(id)) return 'Abstract';
  const lineage = new Set([...ancestorIds, id]);
  const match = CATEGORY_ROOTS.find(([root]) => lineage.has(root));
  return match ? match[1] : 'Internal';
};

/**
 * Turns schema.json into lookup maps and adjacency lists, once at load time,
 * so that search, filters, layout and path finding never scan the raw arrays.
 */
export const normalizeSchema = (raw: RawSchema): NormalizedSchema => {
  const rawNodes = new Map(raw.nodes.map((node) => [node.id, node]));
  const typeNodes = raw.nodes.filter((node): node is RawTypeNode => node.type !== 'target-group' && !isSlot(node));
  const typeIdSet = new Set(typeNodes.map((node) => node.id));

  // Hierarchy
  const parentOf = new Map<string, string>();
  const outgoingEdges = new Map<string, string[]>();
  for (const edge of raw.edges) {
    if (edge.label === INHERITANCE_LABEL) {
      if (typeIdSet.has(edge.source) && typeIdSet.has(edge.target)) parentOf.set(edge.source, edge.target);
    } else {
      const targets = outgoingEdges.get(edge.source) ?? [];
      targets.push(edge.target);
      outgoingEdges.set(edge.source, targets);
    }
  }
  const ancestorsOf = (id: string): string[] => {
    const chain: string[] = [];
    const seen = new Set([id]);
    for (let parent = parentOf.get(id); parent && !seen.has(parent); parent = parentOf.get(parent)) {
      chain.unshift(parent);
      seen.add(parent);
    }
    return chain;
  };
  const childrenOf = new Map<string, string[]>();
  for (const [child, parent] of parentOf) {
    childrenOf.set(parent, [...(childrenOf.get(parent) ?? []), child]);
  }

  // Types
  const attributeNames = new Map(typeNodes.map((node) => [node.id, new Set(node.data.attributes.map((attribute) => attribute.name))]));
  const types = new Map<string, SchemaType>();
  for (const node of typeNodes) {
    const ancestorIds = ancestorsOf(node.id);
    const attributes: AttributeDef[] = node.data.attributes.map((attribute) => ({
      ...attribute,
      declaredBy: ancestorIds.find((ancestor) => attributeNames.get(ancestor)?.has(attribute.name)) ?? node.id,
    }));
    const childIds = (childrenOf.get(node.id) ?? []).sort((a, b) => a.localeCompare(b, 'en', { sensitivity: 'base' }));
    types.set(node.id, {
      id: node.id,
      label: node.data.label,
      kind: node.data.isRelationship ? 'relationship' : 'entity',
      category: categoryOf(node.id, ancestorIds),
      isAbstract: childIds.length > 0,
      parentId: parentOf.get(node.id) ?? null,
      childIds,
      ancestorIds,
      attributes,
    });
  }

  // Relations: source type → slot → target group
  const sourceOfSlot = new Map<string, string>();
  for (const [source, targets] of outgoingEdges) {
    if (!typeIdSet.has(source)) continue;
    for (const target of targets) sourceOfSlot.set(target, source);
  }
  const relations = new Map<string, SchemaRelation>();
  for (const node of raw.nodes) {
    if (node.type === 'target-group' || !isSlot(node)) continue;
    const sourceTypeId = sourceOfSlot.get(node.id);
    if (!sourceTypeId) continue;
    const kind: RelationKind = node.data.isRefAttribute ? 'ref' : 'relationship';
    const groups = (outgoingEdges.get(node.id) ?? [])
      .map((id) => rawNodes.get(id))
      .filter((target): target is RawTargetGroupNode => target?.type === 'target-group');
    const targetTypeIds = [...new Set(groups.flatMap((group) => group.data.items.map((item) => item.label)))]
      .filter((id) => typeIdSet.has(id))
      .sort((a, b) => a.localeCompare(b, 'en', { sensitivity: 'base' }));
    const stixType = node.data.stixType ?? '';
    const name = node.data.label;
    relations.set(node.id, {
      id: node.id,
      name,
      kind,
      stixStatus: kind === 'relationship' && STIX_STATUSES.has(stixType) ? (stixType as StixStatus) : null,
      sourceTypeId,
      targetTypeIds,
      relationshipTypeId: kind === 'ref' ? null : [name, 'stix-core-relationship'].find((id) => typeIdSet.has(id)) ?? null,
    });
  }

  // Adjacency
  const outgoing = new Map<string, string[]>();
  const incoming = new Map<string, string[]>();
  const sortedRelations = [...relations.values()].sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
  for (const relation of sortedRelations) {
    outgoing.set(relation.sourceTypeId, [...(outgoing.get(relation.sourceTypeId) ?? []), relation.id]);
    for (const target of relation.targetTypeIds) {
      incoming.set(target, [...(incoming.get(target) ?? []), relation.id]);
    }
  }

  const categoryCounts: Record<SchemaCategory, number> = { SDO: 0, SCO: 0, SRO: 0, Meta: 0, Internal: 0, Abstract: 0 };
  for (const type of types.values()) categoryCounts[type.category] += 1;

  return {
    types,
    relations,
    typeIds: [...types.values()].sort(byLabel).map((type) => type.id),
    outgoing,
    incoming,
    categoryCounts,
  };
};

/** The type itself and all of its subtypes, depth first. */
export const descendantsAndSelf = (schema: NormalizedSchema, typeId: string): string[] => {
  const result: string[] = [];
  const stack = [typeId];
  const seen = new Set<string>();
  while (stack.length > 0) {
    const current = stack.pop() as string;
    if (seen.has(current)) continue;
    seen.add(current);
    result.push(current);
    stack.push(...(schema.types.get(current)?.childIds ?? []));
  }
  return result;
};

export const outgoingRelations = (schema: NormalizedSchema, typeId: string, includeRefs: boolean): SchemaRelation[] => (schema.outgoing.get(typeId) ?? [])
  .map((id) => schema.relations.get(id) as SchemaRelation)
  .filter((relation) => includeRefs || relation.kind === 'relationship');

export const incomingRelations = (schema: NormalizedSchema, typeId: string, includeRefs: boolean): SchemaRelation[] => (schema.incoming.get(typeId) ?? [])
  .map((id) => schema.relations.get(id) as SchemaRelation)
  .filter((relation) => includeRefs || relation.kind === 'relationship');
