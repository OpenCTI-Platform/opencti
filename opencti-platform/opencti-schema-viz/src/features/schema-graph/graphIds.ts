import type { PathStep, SchemaRelation } from '../../data/schemaTypes';

export type RelationDirection = 'out' | 'in';

// Canvas ids are prefixed so a type and a target group never collide.
const TYPE_PREFIX = 't:';

export const typeNodeId = (typeId: string) => `${TYPE_PREFIX}${typeId}`;
/** The type a canvas node stands for, null for a target group. */
export const typeIdOfNode = (nodeId: string) => (nodeId.startsWith(TYPE_PREFIX) ? nodeId.slice(TYPE_PREFIX.length) : null);
export const groupNodeId = (anchorTypeId: string, direction: RelationDirection, relationName: string) => `g:${direction}:${anchorTypeId}:${relationName}`;

export const inheritanceEdgeId = (parentNodeId: string, childNodeId: string) => `i:${parentNodeId}->${childNodeId}`;
export const relationEdgeId = (sourceNodeId: string, targetNodeId: string) => `e:${sourceNodeId}->${targetNodeId}`;

/** Endpoints of a path step as drawn on the canvas: the relation always points from its source type to the concrete target. */
export const pathStepEndpoints = (relation: SchemaRelation, step: PathStep) => ({
  sourceTypeId: relation.sourceTypeId,
  targetTypeId: step.direction === 'out' ? step.toTypeId : step.fromTypeId,
});

/** Key of a single relation revealed from the inspector, anchored on the type it was revealed from. */
export const revealKey = (direction: RelationDirection, anchorTypeId: string, relationId: string) => `${direction}|${anchorTypeId}|${relationId}`;

export const parseRevealKey = (key: string) => {
  const [direction, anchorTypeId, relationId] = key.split('|');
  return { direction: direction as RelationDirection, anchorTypeId, relationId };
};
