import { useMemo } from 'react';
import { graphql } from 'react-relay';
import { fetchQuery } from '../../../../../relay/environment';
import { useGraphContext } from '../../../../../components/graph/GraphContext';
import useGraphInteractions from '../../../../../components/graph/utils/useGraphInteractions';
import { ObjectToParse } from '../../../../../components/graph/utils/useGraphParser';
import { InvestigationEnrichmentWork } from './investigation-enrichment.types';
import { isRelationship, selectExpandIds } from './investigation-enrichment.utils';
import { useInvestigationEnrichmentExpandTouchedElementsQuery$data } from './__generated__/useInvestigationEnrichmentExpandTouchedElementsQuery.graphql';
import { expandRelationshipsQuery } from '../../../../../components/graph/components/GraphToolbarExpandTools';
import { GraphToolbarExpandToolsRelationshipsQuery$data } from '../../../../../components/graph/components/__generated__/GraphToolbarExpandToolsRelationshipsQuery.graphql';

// The touched elements of works, with what the graph needs to draw them (see graphNodeFragment).
// Fetched only on expand: the list of works is polled and only needs ids and types.
const touchedElementsQuery = graphql`
  query useInvestigationEnrichmentExpandTouchedElementsQuery(
    $id: String!
    $first: Int
    $entityIds: [String!]
    $filters: FilterGroup
  ) {
    workspace(id: $id) {
      enrichmentWorks(first: $first, entityIds: $entityIds, filters: $filters) {
        edges {
          node {
            touchedElements(first: 1000) {
              ...graphNodeFragment_node @relay(mask: false)
              ... on StixRelationship {
                id
                entity_type
                parent_types
                is_inferred
                ... on StixCoreRelationship {
                  relationship_type
                  start_time
                  stop_time
                  confidence
                  created
                  created_at
                  createdBy {
                    ... on Identity {
                      id
                      name
                      entity_type
                    }
                  }
                  objectMarking {
                    id
                    definition_type
                    definition
                    x_opencti_order
                    x_opencti_color
                  }
                }
                ... on StixSightingRelationship {
                  first_seen
                  last_seen
                  created_at
                  createdBy {
                    ... on Identity {
                      id
                      name
                      entity_type
                    }
                  }
                  objectMarking {
                    id
                    definition_type
                    definition
                    x_opencti_order
                    x_opencti_color
                  }
                }
                ... on StixRefRelationship {
                  relationship_type
                  start_time
                  stop_time
                  created_at
                }
                from {
                  ...graphNodeFragment_node @relay(mask: false)
                  ... on BasicRelationship {
                    id
                    entity_type
                    parent_types
                  }
                  ... on StixCoreRelationship {
                    relationship_type
                  }
                }
                to {
                  ...graphNodeFragment_node @relay(mask: false)
                  ... on BasicRelationship {
                    id
                    entity_type
                    parent_types
                  }
                  ... on StixCoreRelationship {
                    relationship_type
                  }
                }
              }
            }
          }
        }
      }
    }
  }
`;

/**
 * Filters the relationships between one of the enriched entities and one of the entities to add,
 * in either direction, of the given types; like the expand of the graph, no type means any type.
 */
const linkingFilterGroup = (
  sourceIds: string[],
  entityIds: string[],
  relationshipTypes: string[],
) => ({
  mode: 'or',
  filterGroups: [
    {
      mode: 'and',
      filterGroups: [],
      filters: [
        { key: 'fromId', values: sourceIds },
        { key: 'toId', values: entityIds },
        { key: 'relationship_type', values: relationshipTypes },
      ],
    },
    {
      mode: 'and',
      filterGroups: [],
      filters: [
        { key: 'toId', values: sourceIds },
        { key: 'fromId', values: entityIds },
        { key: 'relationship_type', values: relationshipTypes },
      ],
    },
  ],
  filters: [],
});

/**
 * The relationships between the enriched entities and the entities to add, with what the graph
 * needs to draw them, from the same query as the expand of the graph.
 */
const fetchLinkingRelationships = async (
  sourceIds: string[],
  entityIds: string[],
  relationshipTypes: string[],
): Promise<ObjectToParse[]> => {
  if (sourceIds.length === 0 || entityIds.length === 0) {
    return [];
  }
  const { stixRelationships } = (await fetchQuery(
    expandRelationshipsQuery,
    { filters: linkingFilterGroup(sourceIds, entityIds, relationshipTypes) },
  ).toPromise()) as GraphToolbarExpandToolsRelationshipsQuery$data;
  return (stixRelationships?.edges ?? []).flatMap((edge) => (
    edge?.node ? [edge.node as unknown as ObjectToParse] : []
  ));
};

export interface ExpandTypes {
  entityTypes?: string[];
  relationshipTypes?: string[];
}

const useInvestigationEnrichmentExpand = (
  investigationId: string,
  onExpand?: (newObjects: ObjectToParse[]) => void,
) => {
  const { rawObjects } = useGraphContext();
  const { setLinearProgress } = useGraphInteractions();
  const graphIds = useMemo(() => new Set(rawObjects.map((o) => o.id)), [rawObjects]);

  /**
   * Adds to the graph the touched entities of the given types with their relationships
   * to the enriched entities, and the touched relationships of the given types with their
   * ends, for all the works at once.
   */
  const expandWorks = async (
    works: InvestigationEnrichmentWork[],
    {
      entityTypes,
      relationshipTypes,
    }: ExpandTypes = {},
  ) => {
    const sourceIds = [...new Set(works.flatMap((work) => (work.eventSource?.id ? [work.eventSource.id] : [])))];
    if (sourceIds.length === 0) {
      return;
    }

    setLinearProgress(true);
    try {
      const { workspace } = (await fetchQuery(
        touchedElementsQuery,
        {
          id: investigationId,
          first: works.length,
          entityIds: sourceIds,
          filters: {
            mode: 'and',
            filters: [{ key: 'ids', values: works.map((work) => work.id) }],
            filterGroups: [],
          },
        },
      ).toPromise()) as useInvestigationEnrichmentExpandTouchedElementsQuery$data;

      const touchedElements = (workspace?.enrichmentWorks?.edges ?? [])
        .flatMap((edge) => edge?.node.touchedElements ?? [])
        .flatMap((element) => (element?.id ? [element] : []));

      // Ends of relationships first, so that a touched element replaces the end it also is.
      const objects = new Map<string, ObjectToParse>();
      touchedElements.forEach((element) => {
        [element.from, element.to].forEach((end) => {
          if (end?.id) {
            objects.set(end.id, end as unknown as ObjectToParse);
          }
        });
      });
      touchedElements.forEach((element) => {
        objects.set(element.id!, element as unknown as ObjectToParse);
      });

      const elements = touchedElements.map((element) => ({
        id: element.id!,
        entity_type: element.entity_type ?? '',
        fromId: element.from?.id,
        toId: element.to?.id,
      }));
      const allTypes = elements.map((element) => element.entity_type);
      const ids = selectExpandIds(
        elements,
        graphIds,
        entityTypes ?? allTypes,
        relationshipTypes ?? allTypes,
      );

      // Like the expand of the graph, the entities come with their relationships to the enriched entities.
      const idsToAdd = new Set(ids);
      const entityIds = elements
        .filter((element) => !isRelationship(element) && idsToAdd.has(element.id))
        .map((element) => element.id);
      // Adding all keeps every relationship, whatever its type.
      const linkingRelationships = await fetchLinkingRelationships(
        sourceIds.filter((id) => graphIds.has(id)),
        entityIds,
        relationshipTypes ?? [],
      );
      linkingRelationships.forEach((relationship) => {
        if (!graphIds.has(relationship.id) && !idsToAdd.has(relationship.id)) {
          idsToAdd.add(relationship.id);
          objects.set(relationship.id, relationship);
        }
      });

      onExpand?.([...idsToAdd].flatMap((id) => {
        const object = objects.get(id);
        return object ? [object] : [];
      }));
    } finally {
      setLinearProgress(false);
    }
  };

  return {
    graphIds,
    expandWorks,
  };
};

export default useInvestigationEnrichmentExpand;
