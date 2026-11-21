import { descendantsAndSelf } from '../../data/normalizeSchema';
import type { NormalizedSchema, PathStep, SchemaPath } from '../../data/schemaTypes';

export interface FindPathOptions {
  /** Only follow relations from source to target. */
  directed: boolean;
  /** Also follow ref attributes. Off by default: createdBy, objectMarking… connect almost every type to a few hubs. */
  includeRefs: boolean;
}

export const DEFAULT_FIND_PATH_OPTIONS: FindPathOptions = { directed: false, includeRefs: false };

const stepRank = (step: PathStep) => (step.direction === 'out' ? 0 : 2) + (step.viaTypeId ? 1 : 0);

const buildAdjacency = (schema: NormalizedSchema, options: FindPathOptions): Map<string, PathStep[]> => {
  const adjacency = new Map<string, Map<string, PathStep>>();
  const add = (step: PathStep) => {
    const steps = adjacency.get(step.fromTypeId) ?? new Map<string, PathStep>();
    const key = `${step.relationId}|${step.toTypeId}|${step.direction}`;
    const existing = steps.get(key);
    if (!existing || stepRank(step) < stepRank(existing)) steps.set(key, step);
    adjacency.set(step.fromTypeId, steps);
  };
  for (const relation of schema.relations.values()) {
    if (relation.kind === 'ref' && !options.includeRefs) continue;
    for (const declaredTarget of relation.targetTypeIds) {
      // A relation targeting an abstract type accepts every subtype.
      for (const target of descendantsAndSelf(schema, declaredTarget)) {
        const viaTypeId = target === declaredTarget ? null : declaredTarget;
        add({ relationId: relation.id, fromTypeId: relation.sourceTypeId, toTypeId: target, direction: 'out', viaTypeId });
        if (!options.directed) {
          add({ relationId: relation.id, fromTypeId: target, toTypeId: relation.sourceTypeId, direction: 'in', viaTypeId });
        }
      }
    }
  }
  const nameOf = (step: PathStep) => schema.relations.get(step.relationId)?.name ?? '';
  const sorted = new Map<string, PathStep[]>();
  for (const [typeId, steps] of adjacency) {
    sorted.set(typeId, [...steps.values()].sort((a, b) => stepRank(a) - stepRank(b)
      || nameOf(a).localeCompare(nameOf(b))
      || a.toTypeId.localeCompare(b.toTypeId)));
  }
  return sorted;
};

/**
 * Breadth-first search over the relations of the normalized schema.
 * Returns the path with the fewest relations, or null when the types are not connected.
 */
export const findShortestPath = (
  schema: NormalizedSchema,
  fromTypeId: string,
  toTypeId: string,
  options: FindPathOptions = DEFAULT_FIND_PATH_OPTIONS,
): SchemaPath | null => {
  if (!schema.types.has(fromTypeId) || !schema.types.has(toTypeId)) return null;
  if (fromTypeId === toTypeId) return { fromTypeId, toTypeId, typeIds: [fromTypeId], steps: [] };

  const adjacency = buildAdjacency(schema, options);
  const reachedBy = new Map<string, PathStep | null>([[fromTypeId, null]]);
  const queue = [fromTypeId];
  for (let head = 0; head < queue.length && !reachedBy.has(toTypeId); head += 1) {
    for (const step of adjacency.get(queue[head]) ?? []) {
      if (reachedBy.has(step.toTypeId)) continue;
      reachedBy.set(step.toTypeId, step);
      queue.push(step.toTypeId);
    }
  }
  if (!reachedBy.has(toTypeId)) return null;

  const steps: PathStep[] = [];
  for (let step = reachedBy.get(toTypeId); step; step = reachedBy.get(step.fromTypeId)) {
    steps.unshift(step);
  }
  return { fromTypeId, toTypeId, typeIds: [fromTypeId, ...steps.map((step) => step.toTypeId)], steps };
};
