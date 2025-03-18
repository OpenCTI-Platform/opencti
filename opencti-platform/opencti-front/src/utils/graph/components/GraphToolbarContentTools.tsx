import ContainerAddStixCoreObjectsInGraph from '@components/common/containers/ContainerAddStixCoreObjectsInGraph';
import React, { useState } from 'react';
import { DeleteOutlined, LinkOutlined, VisibilityOutlined } from '@mui/icons-material';
import { GraphQLTaggedNode } from 'relay-runtime/lib/query/RelayModernGraphQLTag';
import StixCoreRelationshipCreation from '@components/common/stix_core_relationships/StixCoreRelationshipCreation';
import StixNestedRefRelationshipCreationFromKnowledgeGraph from '@components/common/stix_nested_ref_relationships/StixNestedRefRelationshipCreationFromKnowledgeGraph';
import StixNestedRefRelationshipCreation from '@components/common/stix_nested_ref_relationships/StixNestedRefRelationshipCreation';
import StixSightingRelationshipCreation from '@components/events/stix_sighting_relationships/StixSightingRelationshipCreation';
import InvestigationAddStixCoreObjects from '@components/workspaces/investigations/InvestigationAddStixCoreObjects';
import GraphToolbarEditObject from './GraphToolbarEditObject';
import GraphToolbarItem from './GraphToolbarItem';
import { useFormatter } from '../../../components/i18n';
import useGraphInteractions from '../utils/useGraphInteractions';
import { GraphEntity, GraphLink, GraphNode } from '../graph.types';
import { dateFormat, dayStartDate, minutesBefore, now } from '../../Time';
import { convertCreatedBy, convertMarkings } from '../../edition';
import { useGraphContext } from '../GraphContext';
import { ObjectToParse } from '../utils/useGraphParser';
import GraphToolbarRemoveConfirm, { GraphToolbarDeleteConfirmProps } from './GraphToolbarRemoveConfirm';

export interface GraphToolbarContentToolsProps {
  stixCoreObjectRefetchQuery?: GraphQLTaggedNode
  relationshipRefetchQuery?: GraphQLTaggedNode
  onAddRelation?: (rel: ObjectToParse, onCompleted: () => void) => void
  entity?: GraphEntity
  enableReferences?: boolean
  onDeleteRelation?: GraphToolbarDeleteConfirmProps['onDeleteRelation']
  onRemove?: GraphToolbarDeleteConfirmProps['onRemove']
}

const GraphToolbarContentTools = ({
  stixCoreObjectRefetchQuery,
  relationshipRefetchQuery,
  entity,
  enableReferences,
  onAddRelation,
  onDeleteRelation,
  onRemove,
}: GraphToolbarContentToolsProps) => {
  const { t_i18n } = useFormatter();

  const [relationReversed, setRelationReversed] = useState(false);

  const [addNestedOpen, setAddNestedOpen] = useState(false);
  const [hasNested, setHasNested] = useState(false);
  const [nestedReversed, setNestedReversed] = useState(false);

  const [addSightingOpen, setAddSightingOpen] = useState(false);
  const [sightingReversed, setSightingReversed] = useState(false);

  const [removeDialogOpen, setRemoveDialogOpen] = useState(false);

  const { setIsAddRelationOpen } = useGraphInteractions();

  const {
    graphData,
    context,
    rawObjects,
    graphState: {
      selectedNodes,
      selectedLinks,
      isAddRelationOpen,
    },
  } = useGraphContext();

  const {
    addNode,
    removeNode,
    removeLink,
    addLink,
  } = useGraphInteractions();

  const head = selectedNodes.slice(0, 1);
  const tail = selectedNodes.slice(-1);
  const mid = selectedNodes.slice(1, -1);

  const fromEntityTypes = Array.from(new Set([...head, ...mid].map((n) => n.entity_type)));
  const toEntityTypes = Array.from(new Set([...mid, ...tail].map((n) => n.entity_type)));

  const relBetweenNodes = selectedNodes.length >= 2 && selectedLinks.length === 0;
  const relBetweenNodeAndLink = selectedNodes.length === 1 && selectedLinks.length === 1;

  const selectionContainsInferred = selectedNodes.some((n) => n.isNestedInferred)
    || selectedLinks.some((n) => n.inferred || n.isNestedInferred);
  const canDelete = !selectionContainsInferred && (selectedNodes.length > 0 || selectedLinks.length > 0);

  const isReversed = relationReversed || sightingReversed || nestedReversed;

  let objectsFrom: (GraphNode | GraphLink)[] = [];
  let objectsTo: (GraphNode | GraphLink)[] = [];
  if (relBetweenNodes && fromEntityTypes.length === 1) {
    objectsFrom = isReversed ? tail : [...head, ...mid];
    objectsTo = isReversed ? [...head, ...mid] : tail;
  } else if (relBetweenNodes && toEntityTypes.length === 1) {
    objectsFrom = isReversed ? [...mid, ...tail] : head;
    objectsTo = isReversed ? head : [...mid, ...tail];
  } else if (relBetweenNodeAndLink) {
    objectsFrom = isReversed ? [selectedNodes[0]] : [selectedLinks[0]];
    objectsTo = isReversed ? [selectedLinks[0]] : [selectedNodes[0]];
  }

  const canAddRelation = objectsFrom.length > 0 && objectsTo.length > 0;

  const removeFromAddPanel = (node: { id: string }) => {
    // Remove links associated to removed node
    (graphData?.links ?? []).filter(({ source_id, target_id }) => {
      return source_id === node.id || target_id === node.id;
    }).forEach(({ id }) => removeLink(id));
    removeNode(node.id);
  };

  const addRelation = (rel: ObjectToParse) => {
    onAddRelation?.(rel, () => addLink(rel));
  };

  return (
    <>
      {entity && context !== 'investigation' && (
        <ContainerAddStixCoreObjectsInGraph
          knowledgeGraph={context !== 'correlation'}
          containerId={entity.id}
          containerStixCoreObjects={rawObjects.map((o) => ({ node: o }))}
          defaultCreatedBy={entity.createdBy ?? null}
          defaultMarkingDefinitions={entity.objectMarking ?? []}
          targetStixCoreObjectTypes={['Stix-Domain-Object', 'Stix-Cyber-Observable']}
          onAdd={addNode}
          onDelete={removeFromAddPanel}
          confidence={entity.confidence}
          enableReferences={enableReferences}
        />
      )}
      {entity && context === 'investigation' && (
        <InvestigationAddStixCoreObjects
          workspaceId={entity.id}
          workspaceStixCoreObjects={rawObjects.map((o) => ({ node: o }))}
          targetStixCoreObjectTypes={['Stix-Domain-Object', 'Stix-Cyber-Observable']}
          onAdd={addNode}
          onDelete={removeFromAddPanel}
        />
      )}

      {stixCoreObjectRefetchQuery && relationshipRefetchQuery && (
        <GraphToolbarEditObject
          stixCoreObjectRefetchQuery={stixCoreObjectRefetchQuery}
          relationshipRefetchQuery={relationshipRefetchQuery}
        />
      )}

      {onAddRelation && entity && (
        <>
          <GraphToolbarItem
            Icon={<LinkOutlined />}
            disabled={!canAddRelation}
            color="primary"
            onClick={() => setIsAddRelationOpen(true)}
            title={t_i18n('Create a relationship')}
          />
          <StixCoreRelationshipCreation
            open={isAddRelationOpen}
            confidence={entity.confidence}
            defaultCreatedBy={convertCreatedBy(entity)}
            defaultMarkingDefinitions={convertMarkings(entity)}
            fromObjects={objectsFrom}
            toObjects={objectsTo}
            startTime={minutesBefore(1, now())}
            stopTime={now()}
            handleResult={addRelation}
            handleReverseRelation={() => setRelationReversed((r) => !r)}
            handleClose={() => {
              setRelationReversed(false);
              setIsAddRelationOpen(false);
            }}
          />
          <StixNestedRefRelationshipCreationFromKnowledgeGraph
            nestedRelationExist={hasNested}
            openCreateNested={addNestedOpen}
            nestedEnabled={canAddRelation}
            relationFromObjects={objectsFrom}
            relationToObjects={objectsTo}
            handleSetNestedRelationExist={setHasNested}
            handleOpenCreateNested={() => setAddNestedOpen(true)}
          />
          <StixNestedRefRelationshipCreation
            open={addNestedOpen}
            fromObjects={objectsFrom}
            toObjects={objectsTo}
            startTime={dateFormat(entity.published)}
            stopTime={dateFormat(entity.published)}
            confidence={entity.confidence}
            handleResult={addRelation}
            handleReverseRelation={() => setNestedReversed((r) => !r)}
            defaultMarkingDefinitions={entity.objectMarking ?? []}
            handleClose={() => {
              setNestedReversed(false);
              setAddNestedOpen(false);
            }}
          />
        </>
      )}

      {entity && (
        <>
          <GraphToolbarItem
            Icon={<VisibilityOutlined />}
            disabled={!canAddRelation}
            color="primary"
            onClick={() => setAddSightingOpen(true)}
            title={t_i18n('Create a sighting')}
          />
          <StixSightingRelationshipCreation
            open={addSightingOpen}
            fromObjects={objectsFrom}
            toObjects={objectsTo}
            confidence={entity.confidence}
            firstSeen={dateFormat(entity.published) ?? dayStartDate()}
            lastSeen={dateFormat(entity.published) ?? dayStartDate()}
            defaultCreatedBy={convertCreatedBy(entity)}
            defaultMarkingDefinitions={convertMarkings(entity)}
            handleResult={addRelation}
            handleReverseSighting={() => setSightingReversed((r) => !r)}
            handleClose={() => {
              setSightingReversed(false);
              setAddSightingOpen(false);
            }}
          />
        </>
      )}

      {(onDeleteRelation || onRemove) && entity && (
        <>
          <GraphToolbarItem
            Icon={<DeleteOutlined />}
            disabled={!canDelete}
            color="primary"
            onClick={() => setRemoveDialogOpen(true)}
            title={t_i18n('Remove selected items')}
          />
          <GraphToolbarRemoveConfirm
            open={removeDialogOpen}
            entityId={entity.id}
            enableReferences={enableReferences}
            onClose={() => setRemoveDialogOpen(false)}
            onDeleteRelation={onDeleteRelation}
            onRemove={onRemove}
          />
        </>
      )}
    </>
  );
};

export default GraphToolbarContentTools;
