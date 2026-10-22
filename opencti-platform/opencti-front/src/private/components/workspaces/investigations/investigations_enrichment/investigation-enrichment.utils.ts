import { InvestigationEnrichmentWork } from './investigation-enrichment.types';

export const addInEnrichmentMap = (
  map: Map<string, InvestigationEnrichmentWork[]>,
  work?: InvestigationEnrichmentWork,
) => {
  if (work && work.event_source_id) {
    if (map.has(work.event_source_id)) {
      map.get(work.event_source_id)?.push(work);
    } else {
      map.set(work.event_source_id, [work]);
    }
  }
};

/**
 * An element touched by an enrichment, reduced to what the expand needs.
 * A relationship has both ends, an entity has none.
 */
export interface ExpandElement {
  id: string;
  entity_type: string;
  fromId?: string | null;
  toId?: string | null;
}

/**
 * Whether a touched element is a relationship.
 */
const isRelationship = (element: ExpandElement) => !!element.fromId && !!element.toId;

/**
 * Counts of the touched entities by type, and of the touched relationships by type,
 * leaving out what is already on the graph.
 */
export const countExpandOptions = (
  elements: ExpandElement[],
  graphIds: Set<string>,
) => {
  const targetCounts = new Map<string, number>();
  const relationshipCounts = new Map<string, number>();

  elements.forEach((element) => {
    if (graphIds.has(element.id)) {
      return;
    }
    const counts = isRelationship(element) ? relationshipCounts : targetCounts;
    counts.set(
      element.entity_type,
      (counts.get(element.entity_type) ?? 0) + 1,
    );
  });

  return {
    targets: targetCounts,
    relationships: relationshipCounts,
  };
};

/**
 * Ids of what an expand adds to the graph: the touched entities of a ticked type, and the touched
 * relationships of a ticked type with their ends, so that no link points at a missing node.
 * What is already on the graph is left out.
 */
export const selectExpandIds = (
  elements: ExpandElement[],
  graphIds: Set<string>,
  entityTypes: string[],
  relationshipTypes: string[],
) => {
  const ids = new Set<string>();

  elements.forEach((element) => {
    if (graphIds.has(element.id)) {
      return;
    }
    if (!isRelationship(element)) {
      if (entityTypes.includes(element.entity_type)) {
        ids.add(element.id);
      }
      return;
    }
    if (relationshipTypes.includes(element.entity_type)) {
      ids.add(element.id);
      [element.fromId, element.toId].forEach((endId) => {
        if (endId && !graphIds.has(endId)) {
          ids.add(endId);
        }
      });
    }
  });

  return [...ids];
};
