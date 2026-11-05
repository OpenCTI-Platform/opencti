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
 * What the background task launcher needs from the graph selection to enrich it: the selected
 * elements by id, their count, and their entity type when they all share one.
 */
export const toEnrichmentSelection = <T extends { id: string; label: string; entity_type: string }>(elements: readonly T[]) => {
  const selectionMap = Object.fromEntries(elements.map((el) => [
    el.id,
    // We override name because for investigation, name contains also the date
    { ...el, name: el.label },
  ]));
  // Enrichment available only if elements are all of same type.
  const selectedEntityTypes = new Set(elements.map((el) => el.entity_type));
  const enrichmentType = selectedEntityTypes.size === 1 ? [...selectedEntityTypes][0] : undefined;
  return { selectionMap, selectionSize: elements.length, enrichmentType };
};

/**
 * The background task actions enriching with the given connectors.
 * The investigation id tags every enrichment work created by the task with this investigation.
 */
export const toEnrichmentTaskActions = (connectorIds: string[], investigationId: string) => [{
  type: 'ENRICHMENT' as const,
  context: {
    values: connectorIds,
    options: { investigationId },
  },
}];

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
 * The touched elements of works, from the ids and types loaded with the list of works.
 * An element touched by several works is kept once, so that it is counted once.
 */
export const toExpandElements = (works: InvestigationEnrichmentWork[]): ExpandElement[] => {
  const elements = new Map<string, ExpandElement>();
  works.forEach((work) => {
    (work.touchedElements ?? []).forEach((element) => {
      if (element?.id && element.entity_type) {
        elements.set(element.id, {
          id: element.id,
          entity_type: element.entity_type,
          fromId: element.fromId,
          toId: element.toId,
        });
      }
    });
  });
  return [...elements.values()];
};

/**
 * Whether a touched element is a relationship.
 */
export const isRelationship = (element: ExpandElement) => !!element.fromId && !!element.toId;

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
 * Whether an expand has nothing to add: everything touched is already on the graph.
 */
export const isNothingToExpand = (
  elements: ExpandElement[],
  graphIds: Set<string>,
) => elements.every((element) => graphIds.has(element.id));

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
