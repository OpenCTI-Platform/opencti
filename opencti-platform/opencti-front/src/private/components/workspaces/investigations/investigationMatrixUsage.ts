import { ObjectToParse } from '../../../../components/graph/utils/useGraphParser';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { MarkerShape, MARKER_SHAPES } from '../../techniques/attack_patterns/attack_patterns_matrix/MatrixEntityMarker';

// Categorical palette for entity "uses" markers. Red and green are deliberately
// excluded: those hues are reserved for the has-covered coverage donuts
// (red = low score, green = high score), so the two encodings cannot be
// confused. Colours are colour-blind-safe and keep >=3:1 non-text contrast
// against the matrix cell backgrounds (WCAG 1.4.11).
export const MATRIX_ENTITY_PALETTE: string[] = [
  '#56B4E9', // sky blue
  '#0072B2', // blue
  '#E69F00', // orange
  '#CC79A7', // reddish purple
  '#F0E442', // yellow
  '#999999', // grey
  '#9467BD', // violet
  '#17BECF', // teal
];

// A single entity that "uses" one or more attack patterns in the investigation.
export interface MatrixEntityUsage {
  id: string;
  name: string;
  entity_type: string;
  color: string;
  shape: MarkerShape;
}

export interface InvestigationMatrixUsage {
  // attack_pattern_id -> the entities that use it (directly or via a sub-technique).
  usageByAttackPattern: Map<string, MatrixEntityUsage[]>;
  // Stable, ordered list of every entity that uses at least one technique.
  legend: MatrixEntityUsage[];
}

const isRelationship = (o: ObjectToParse): boolean => (o.parent_types ?? []).includes('basic-relationship')
  || Boolean(o.relationship_type);

const isAttackPattern = (entityType?: string): boolean => entityType === 'Attack-Pattern';

// Deterministically assign a colour + shape to an entity based on its index so
// that the encoding stays stable across re-renders. Combining palette and shape
// rotation yields palette.length * shapes.length unique combinations.
const buildMarker = (index: number): Pick<MatrixEntityUsage, 'color' | 'shape'> => ({
  color: MATRIX_ENTITY_PALETTE[index % MATRIX_ENTITY_PALETTE.length],
  shape: MARKER_SHAPES[Math.floor(index / MATRIX_ENTITY_PALETTE.length) % MARKER_SHAPES.length],
});

/**
 * Build the "which entity uses which technique" model from the flat list of
 * investigation objects (nodes + relationships).
 *
 * Only STIX `uses` relationships are considered. The entity end of the
 * relationship (the one that is not the Attack-Pattern) is the "user".
 */
export const buildInvestigationMatrixUsage = (
  objects: ObjectToParse[],
): InvestigationMatrixUsage => {
  // Index every non-relationship node by id so we can resolve names/types from
  // the light-weight `from`/`to` references carried by relationships.
  const nodesById = new Map<string, ObjectToParse>();
  objects.forEach((o) => {
    if (!isRelationship(o)) {
      nodesById.set(o.id, o);
    }
  });

  // attackPatternId -> Set of using entity ids (dedupe multiple relationships).
  const usageIdsByAttackPattern = new Map<string, Set<string>>();
  // Preserve first-seen order of entities for stable colour assignment.
  const orderedEntityIds: string[] = [];
  const seenEntityIds = new Set<string>();

  objects
    .filter((o) => isRelationship(o) && o.relationship_type === 'uses' && o.from && o.to)
    .forEach((rel) => {
      const from = rel.from!;
      const to = rel.to!;
      let attackPatternId: string | undefined;
      let entityId: string | undefined;
      if (isAttackPattern(to.entity_type)) {
        attackPatternId = to.id;
        entityId = from.id;
      } else if (isAttackPattern(from.entity_type)) {
        attackPatternId = from.id;
        entityId = to.id;
      }
      if (!attackPatternId || !entityId) {
        return;
      }
      const entityNode = nodesById.get(entityId);
      // Ignore usages whose entity is not part of the investigation graph.
      if (!entityNode) {
        return;
      }
      if (!usageIdsByAttackPattern.has(attackPatternId)) {
        usageIdsByAttackPattern.set(attackPatternId, new Set<string>());
      }
      usageIdsByAttackPattern.get(attackPatternId)!.add(entityId);
      if (!seenEntityIds.has(entityId)) {
        seenEntityIds.add(entityId);
        orderedEntityIds.push(entityId);
      }
    });

  // Assign stable colour + shape per entity, sorted by name for predictable legend order.
  const sortedEntityIds = [...orderedEntityIds].sort((a, b) => {
    const nameA = getMainRepresentative(nodesById.get(a));
    const nameB = getMainRepresentative(nodesById.get(b));
    return nameA.localeCompare(nameB);
  });

  const entityById = new Map<string, MatrixEntityUsage>();
  const legend: MatrixEntityUsage[] = sortedEntityIds.map((id, index) => {
    const node = nodesById.get(id);
    const usage: MatrixEntityUsage = {
      id,
      name: getMainRepresentative(node),
      entity_type: node?.entity_type ?? 'Unknown',
      ...buildMarker(index),
    };
    entityById.set(id, usage);
    return usage;
  });

  const usageByAttackPattern = new Map<string, MatrixEntityUsage[]>();
  usageIdsByAttackPattern.forEach((entityIds, attackPatternId) => {
    const usages = [...entityIds]
      .map((id) => entityById.get(id))
      .filter((u): u is MatrixEntityUsage => Boolean(u))
      .sort((a, b) => a.name.localeCompare(b.name));
    usageByAttackPattern.set(attackPatternId, usages);
  });

  return { usageByAttackPattern, legend };
};
