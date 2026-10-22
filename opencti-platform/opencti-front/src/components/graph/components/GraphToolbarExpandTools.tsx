import { OpenWithOutlined, Undo } from '@mui/icons-material';
import React, { useState } from 'react';
import Dialog from '@mui/material/Dialog';
import { graphql } from 'react-relay';
import { useParams } from 'react-router';
import InvestigationExpandDialogContent, { InvestigationExpandDialogContentProps } from '@components/workspaces/investigations/InvestigationExpandDialogContent';
import { useInvestigationState } from '@components/workspaces/investigations/utils/useInvestigationState';
import InvestigationRollBackExpandDialog from '@components/workspaces/investigations/dialog/InvestigationRollBackExpandDialog';
import GraphToolbarItem from './GraphToolbarItem';
import { useFormatter } from '../../i18n';
import { useGraphContext } from '../GraphContext';
import useGraphInteractions from '../utils/useGraphInteractions';
import { fetchQuery } from '../../../relay/environment';
import { GraphToolbarExpandToolsRelationshipsQuery$data } from './__generated__/GraphToolbarExpandToolsRelationshipsQuery.graphql';
import { ObjectToParse } from '../utils/useGraphParser';
import { SURFACE_LAYER, fdsLayerClass, layerInputVars } from '../../../utils/fdsLayer';

const expandRelationshipsQuery = graphql`
  query GraphToolbarExpandToolsRelationshipsQuery($filters: FilterGroup) {
    stixRelationships(
      filters: $filters
    ) {
      edges {
        node {
          id
          entity_type
          parent_types
          is_inferred
          ... on StixRefRelationship {
            created_at
          }
          ... on StixCoreRelationship {
            start_time
            stop_time
            confidence
            relationship_type
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
            start_time
            stop_time
            relationship_type
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
              start_time
              stop_time
              confidence
              created
              from {
                ... on BasicObject {
                  id
                  standard_id
                  entity_type
                  parent_types
                }
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
                ... on BasicObject {
                  id
                  standard_id
                  entity_type
                  parent_types
                }
                ... on BasicRelationship {
                  id
                  entity_type
                  parent_types
                }
                ... on StixCoreRelationship {
                  relationship_type
                }
              }
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
              start_time
              stop_time
              confidence
              created
              from {
                ... on BasicObject {
                  id
                  standard_id
                  entity_type
                  parent_types
                }
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
                ... on BasicObject {
                  id
                  standard_id
                  entity_type
                  parent_types
                }
                ... on BasicRelationship {
                  id
                  entity_type
                  parent_types
                }
                ... on StixCoreRelationship {
                  relationship_type
                }
              }
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
          }
        }
      }
    }
  }
`;

const expandFilterGroup = (
  id: string,
  entityTypes: string[],
  relationshipTypes: string[],
) => ({
  mode: 'or',
  filterGroups: [
    {
      mode: 'and',
      filterGroups: [],
      filters: [
        { key: 'fromId', values: [id] },
        { key: 'toTypes', values: entityTypes },
        { key: 'relationship_type', values: relationshipTypes },
      ],
    },
    {
      mode: 'and',
      filterGroups: [],
      filters: [
        { key: 'toId', values: [id] },
        { key: 'fromTypes', values: entityTypes },
        { key: 'relationship_type', values: relationshipTypes },
      ],
    },
  ],
  filters: [],
});

export interface GraphToolbarExpandToolsProps {
  onInvestigationExpand?: (newObjects: ObjectToParse[]) => void;
  onInvestigationRollback?: () => void;
}

const GraphToolbarExpandTools = ({
  onInvestigationExpand,
  onInvestigationRollback,
}: GraphToolbarExpandToolsProps) => {
  const { workspaceId } = useParams();
  const { t_i18n } = useFormatter();

  const {
    containsExpandOp,
  } = useInvestigationState(workspaceId ?? '');

  const {
    graphData,
    rawObjects,
    graphState: {
      selectedNodes,
      selectedLinks,
      isExpandOpen,
    },
  } = useGraphContext();

  const {
    setLinearProgress,
    setIsExpandOpen,
  } = useGraphInteractions();

  const [rollBackOpen, setRollBackOpen] = useState(false);

  const onRollbackExpand = () => {
    onInvestigationRollback?.();
  };

  const onExpand: InvestigationExpandDialogContentProps['onSubmit'] = async (
    { entity_types, relationship_types },
    { resetForm },
  ) => {
    if (entity_types.length === 0 && relationship_types.length === 0) {
      // Do not expand if nothing has been checked.
      return;
    }

    setLinearProgress(true);
    const entityTypes = entity_types.map((o) => o.value);
    const relationshipTypes = relationship_types.map((o) => o.value);
    const selectionIds = [...selectedNodes, ...selectedLinks].map((s) => s.id);
    const objectIds = rawObjects.map((o) => o.id);

    const allNewElements: ObjectToParse[] = [];
    for (const id of selectionIds) {
      const { stixRelationships } = (await fetchQuery(
        expandRelationshipsQuery,
        { filters: expandFilterGroup(id, entityTypes, relationshipTypes) },
      ).toPromise()) as GraphToolbarExpandToolsRelationshipsQuery$data;
      const newElements = (stixRelationships?.edges ?? []).flatMap((e) => {
        if (!e) return [];
        const entity = e.node.from?.id === id ? e.node.to : e.node.from;
        const toReturn: ObjectToParse[] = [];
        if (!objectIds.includes(e.node.id)) {
          toReturn.push(e.node as unknown as ObjectToParse);
        }
        if (!!entity?.id && !objectIds.includes(entity.id)) {
          toReturn.push(entity as unknown as ObjectToParse);
        }
        return toReturn;
      });
      allNewElements.push(...newElements);
    }
    onInvestigationExpand?.(allNewElements);

    resetForm();
    setRollBackOpen(false);
    setLinearProgress(false);
  };

  return (
    <>
      <GraphToolbarItem
        Icon={<Undo />}
        color="primary"
        onClick={() => setRollBackOpen(true)}
        title={t_i18n('Restore the state of the graphic before the last expansion')}
        disabledReason={containsExpandOp() ? undefined : t_i18n('No expansion to roll back yet')}
      />

      <InvestigationRollBackExpandDialog
        isOpen={rollBackOpen}
        closeDialog={() => setRollBackOpen(false)}
        handleRollBackToPreExpansionState={onRollbackExpand}
      />

      <GraphToolbarItem
        Icon={<OpenWithOutlined />}
        color="primary"
        onClick={() => setIsExpandOpen(true)}
        title={t_i18n('Expand the selected entities')}
        disabledReason={selectedNodes.length === 0 ? t_i18n('Select entities first') : undefined}
      />

      <Dialog
        // A dialog is a layer-2 surface, like a drawer. See utils/fdsLayer.ts.
        slotProps={{ paper: { className: fdsLayerClass(SURFACE_LAYER), sx: { ...layerInputVars } } }}
        fullWidth
        maxWidth={false}
        open={isExpandOpen}
        sx={{ '& .MuiDialog-paper': { width: 640 } }}
        onClose={() => setIsExpandOpen(false)}
      >
        <InvestigationExpandDialogContent
          links={graphData?.links ?? []}
          selectedNodes={selectedNodes}
          onSubmit={onExpand}
          onReset={() => setIsExpandOpen(false)}
        />
      </Dialog>
    </>
  );
};

export default GraphToolbarExpandTools;
