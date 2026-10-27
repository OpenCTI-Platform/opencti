import { useMemo } from 'react';
import { graphql } from 'react-relay';
import { fetchQuery } from '../../../../../relay/environment';
import { useGraphContext } from '../../../../../components/graph/GraphContext';
import useGraphInteractions from '../../../../../components/graph/utils/useGraphInteractions';
import { ObjectToParse } from '../../../../../components/graph/utils/useGraphParser';
import { InvestigationEnrichmentWork } from './investigation-enrichment.types';
import { selectExpandIds } from './investigation-enrichment.utils';
import { useInvestigationEnrichmentExpandTouchedElementsQuery$data } from './__generated__/useInvestigationEnrichmentExpandTouchedElementsQuery.graphql';

// The touched elements of one work, with what the graph needs to draw them (see graphNodeFragment).
// Fetched only on expand: the list of works is polled and only needs ids and types.
const touchedElementsQuery = graphql`
  query useInvestigationEnrichmentExpandTouchedElementsQuery(
    $id: String!
    $entityIds: [String!]
    $filters: FilterGroup
  ) {
    workspace(id: $id) {
      enrichmentWorks(entityIds: $entityIds, filters: $filters) {
        edges {
          node {
            touchedElements {
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
   * Adds to the graph the touched entities of the given types, and the touched
   * relationships of the given types with their ends.
   */
  const expandWork = async (
    work: InvestigationEnrichmentWork,
    {
      entityTypes,
      relationshipTypes,
    }: ExpandTypes = {},
  ) => {
    const sourceId = work.eventSource?.id;
    if (!sourceId) {
      return;
    }

    setLinearProgress(true);
    try {
      const { workspace } = (await fetchQuery(
        touchedElementsQuery,
        {
          id: investigationId,
          entityIds: [sourceId],
          filters: {
            mode: 'and',
            filters: [{ key: 'ids', values: [work.id] }],
            filterGroups: [],
          },
        },
      ).toPromise()) as useInvestigationEnrichmentExpandTouchedElementsQuery$data;

      const touchedElements = (workspace?.enrichmentWorks?.edges?.[0]?.node.touchedElements ?? [])
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

      onExpand?.(ids.flatMap((id) => {
        const object = objects.get(id);
        return object ? [object] : [];
      }));
    } finally {
      setLinearProgress(false);
    }
  };

  return {
    graphIds,
    expandWork,
  };
};

export default useInvestigationEnrichmentExpand;
