import { useMemo } from 'react';
import { Dialog, DialogTitle } from '@mui/material';
import { graphql } from 'react-relay';
import { fdsLayerClass, layerInputVars, SURFACE_LAYER } from '../../../../../utils/fdsLayer';
import InvestigationExpandForm, { InvestigationExpandFormProps } from '../InvestigationExpandForm';
import { useFormatter } from '../../../../../components/i18n';
import { InvestigationEnrichmentWork } from './investigation-enrichment.types';
import { getMainRepresentative } from '../../../../../utils/defaultRepresentatives';
import { fetchQuery } from '../../../../../relay/environment';
import { useGraphContext } from '../../../../../components/graph/GraphContext';
import useGraphInteractions from '../../../../../components/graph/utils/useGraphInteractions';
import { ObjectToParse } from '../../../../../components/graph/utils/useGraphParser';
import { countExpandOptions, ExpandElement, selectExpandIds } from './investigation-enrichment.utils';
import { InvestigationEnrichmentExpandTouchedElementsQuery$data } from './__generated__/InvestigationEnrichmentExpandTouchedElementsQuery.graphql';

// The touched elements of one work, with what the graph needs to draw them (see graphNodeFragment).
// Fetched only on expand: the list of works is polled and only needs ids and types.
const touchedElementsQuery = graphql`
  query InvestigationEnrichmentExpandTouchedElementsQuery(
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

/**
 * The touched elements of a work, from the ids and types loaded with the list of works.
 */
const toExpandElements = (work?: InvestigationEnrichmentWork): ExpandElement[] => {
  return (work?.touchedElements ?? []).flatMap((element) => (
    element?.id && element.entity_type
      ? [{
          id: element.id,
          entity_type: element.entity_type,
          fromId: element.fromId,
          toId: element.toId,
        }]
      : []
  ));
};

interface InvestigationEnrichmentExpandProps {
  investigationId: string;
  work?: InvestigationEnrichmentWork;
  onClose: () => void;
  onDismiss: (workId: string) => void;
  onExpand?: (newObjects: ObjectToParse[]) => void;
}

const InvestigationEnrichmentExpand = ({
  investigationId,
  work,
  onClose,
  onDismiss,
  onExpand,
}: InvestigationEnrichmentExpandProps) => {
  const { t_i18n } = useFormatter();
  const { rawObjects } = useGraphContext();
  const { setLinearProgress } = useGraphInteractions();

  const sourceId = work?.eventSource?.id ?? '';
  const graphIds = useMemo(() => new Set(rawObjects.map((o) => o.id)), [rawObjects]);

  /**
   * Options of the expand form from counts by type, sorted alphabetically.
   */
  const mapToOptions = (map: Map<string, number>, isRel = false) => {
    const prefix = isRel ? 'relationship' : 'entity';
    return [...map.entries()]
      .map(([key, value]) => ({
        label: `${t_i18n(`${prefix}_${key}`)} (${value})`,
        value: key,
      }))
      .sort((a, b) => a.label.localeCompare(b.label));
  };

  const { targets, relationships } = useMemo(() => {
    const counts = countExpandOptions(toExpandElements(work), graphIds);
    return {
      targets: mapToOptions(counts.targets),
      relationships: mapToOptions(counts.relationships, true),
    };
  }, [work, graphIds]);

  /**
   * Adds to the graph the touched entities of a ticked type, and the touched
   * relationships of a ticked type with their ends, then marks the work as reviewed.
   */
  const onSubmitExpand: InvestigationExpandFormProps['onSubmit'] = async (
    { entity_types, relationship_types },
    { resetForm },
  ) => {
    if (!work || !sourceId || (entity_types.length === 0 && relationship_types.length === 0)) {
      // Do not expand if nothing has been checked.
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
      ).toPromise()) as InvestigationEnrichmentExpandTouchedElementsQuery$data;

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

      const ids = selectExpandIds(
        touchedElements.map((element) => ({
          id: element.id!,
          entity_type: element.entity_type ?? '',
          fromId: element.from?.id,
          toId: element.to?.id,
        })),
        graphIds,
        entity_types.map((o) => o.value),
        relationship_types.map((o) => o.value),
      );

      onExpand?.(ids.flatMap((id) => {
        const object = objects.get(id);
        return object ? [object] : [];
      }));
      resetForm();
      // Expanding reviews the work: it moves to done, which also closes the dialog.
      onDismiss(work.id);
    } finally {
      setLinearProgress(false);
    }
  };

  return (
    <Dialog
      // A dialog is a layer-2 surface, like a drawer. See utils/fdsLayer.ts.
      slotProps={{
        paper: {
          className: fdsLayerClass(SURFACE_LAYER),
          sx: { ...layerInputVars },
        },
      }}
      fullWidth
      maxWidth={false}
      open={!!work}
      sx={{ '& .MuiDialog-paper': { width: 640 } }}
      onClose={onClose}
    >
      <DialogTitle>
        {t_i18n('Enrichment Results')} - {getMainRepresentative(work?.eventSource)}
      </DialogTitle>
      <InvestigationExpandForm
        onReset={onClose}
        onSubmit={onSubmitExpand}
        onDismiss={() => onDismiss(work!.id)}
        targets={targets}
        relationships={relationships}
      />
    </Dialog>
  );
};

export default InvestigationEnrichmentExpand;
