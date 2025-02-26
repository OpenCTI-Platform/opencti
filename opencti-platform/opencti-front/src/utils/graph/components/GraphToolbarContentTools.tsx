import ContainerAddStixCoreObjectsInGraph from '@components/common/containers/ContainerAddStixCoreObjectsInGraph';
import React, { useState } from 'react';
import { DeleteOutlined, LinkOutlined, VisibilityOutlined } from '@mui/icons-material';
import { GraphQLTaggedNode } from 'relay-runtime/lib/query/RelayModernGraphQLTag';
import StixCoreRelationshipCreation from '@components/common/stix_core_relationships/StixCoreRelationshipCreation';
import StixNestedRefRelationshipCreationFromKnowledgeGraph from '@components/common/stix_nested_ref_relationships/StixNestedRefRelationshipCreationFromKnowledgeGraph';
import StixNestedRefRelationshipCreation from '@components/common/stix_nested_ref_relationships/StixNestedRefRelationshipCreation';
import StixSightingRelationshipCreation from '@components/events/stix_sighting_relationships/StixSightingRelationshipCreation';
import GraphToolbarEditObject from './GraphToolbarEditObject';
import GraphToolbarItem from './GraphToolbarItem';
import { useFormatter } from '../../../components/i18n';
import useGraphInteractions from '../utils/useGraphInteractions';
import { GraphContainer, GraphLink, GraphNode } from '../graph.types';
import { dateFormat, minutesBefore, now } from '../../Time';
import { convertCreatedBy, convertMarkings } from '../../edition';
import { useGraphContext } from '../GraphContext';
import { ObjectToParse } from '../utils/useGraphParser';
import GraphToolbarRemoveConfirm, { GraphToolbarDeleteConfirmProps } from './GraphToolbarRemoveConfirm';

export interface GraphToolbarContentToolsProps {
  stixCoreObjectRefetchQuery: GraphQLTaggedNode
  relationshipRefetchQuery: GraphQLTaggedNode
  onAddRelation?: (rel: ObjectToParse) => void
  container?: GraphContainer
  enableReferences?: boolean
  onContainerDeleteRelation?: GraphToolbarDeleteConfirmProps['onContainerDeleteRelation']
}

const GraphToolbarContentTools = ({
  stixCoreObjectRefetchQuery,
  relationshipRefetchQuery,
  container,
  enableReferences,
  onAddRelation,
  onContainerDeleteRelation,
}: GraphToolbarContentToolsProps) => {
  const { t_i18n } = useFormatter();

  const { isAddRelationOpen, setIsAddRelationOpen } = useGraphContext();
  const [relationReversed, setRelationReversed] = useState(false);

  const [addNestedOpen, setAddNestedOpen] = useState(false);
  const [hasNested, setHasNested] = useState(false);
  const [nestedReversed, setNestedReversed] = useState(false);

  const [addSightingOpen, setAddSightingOpen] = useState(false);
  const [sightingReversed, setSightingReversed] = useState(false);

  const [removeDialogOpen, setRemoveDialogOpen] = useState(false);

  const {
    selectedNodes,
    selectedLinks,
    graphData,
  } = useGraphContext();

  const {
    addNode,
    removeNode,
    removeLink,
  } = useGraphInteractions();

  const head = selectedNodes.slice(0, 1);
  const tail = selectedNodes.slice(-1);
  const mid = selectedNodes.slice(1, -1);

  const fromEntityTypes = Array.from(new Set([...head, ...mid].map((n) => n.entity_type)));
  const toEntityTypes = Array.from(new Set([...mid, ...tail].map((n) => n.entity_type)));

  const relBetweenNodes = selectedNodes.length >= 2 && selectedLinks.length === 0;
  const relBetweenNodeAndLink = selectedNodes.length === 1 && selectedLinks.length === 1;
  const canAddRelation = relBetweenNodes || relBetweenNodeAndLink;

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

  const removeFromAddPanel = (node: { id: string }) => {
    // Remove links associated to removed node
    (graphData?.links ?? []).filter(({ source_id, target_id }) => {
      return source_id === node.id || target_id === node.id;
    }).forEach(({ id }) => removeLink(id));
    removeNode(node.id);
  };

  return (
    <>
      {container && (
        <ContainerAddStixCoreObjectsInGraph
          knowledgeGraph={true} // TODO change for correlation?
          containerId={container.id}
          containerStixCoreObjects={container.objects}
          defaultCreatedBy={container.createdBy ?? null}
          defaultMarkingDefinitions={container.objectMarking ?? []}
          targetStixCoreObjectTypes={['Stix-Domain-Object', 'Stix-Cyber-Observable']}
          onAdd={addNode}
          onDelete={removeFromAddPanel}
          confidence={container.confidence}
          enableReferences={enableReferences}
        />
      )}

      <GraphToolbarEditObject
        stixCoreObjectRefetchQuery={stixCoreObjectRefetchQuery}
        relationshipRefetchQuery={relationshipRefetchQuery}
      />

      {onAddRelation && container && (
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
            confidence={container.confidence}
            defaultCreatedBy={convertCreatedBy(container)}
            defaultMarkingDefinitions={convertMarkings(container)}
            fromObjects={objectsFrom}
            toObjects={objectsTo}
            startTime={minutesBefore(1, now())}
            stopTime={now()}
            handleResult={onAddRelation}
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
            startTime={dateFormat(container.published)}
            stopTime={dateFormat(container.published)}
            confidence={container.confidence}
            handleResult={onAddRelation}
            handleReverseRelation={() => setNestedReversed((r) => !r)}
            defaultMarkingDefinitions={container.objectMarking ?? []}
            handleClose={() => {
              setNestedReversed(false);
              setAddNestedOpen(false);
            }}
          />
        </>
      )}

      {container && (
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
            confidence={container.confidence}
            firstSeen={dateFormat(container.published)}
            lastSeen={dateFormat(container.published)}
            defaultCreatedBy={convertCreatedBy(container)}
            defaultMarkingDefinitions={convertMarkings(container)}
            handleResult={onAddRelation}
            handleReverseSighting={() => setSightingReversed((r) => !r)}
            handleClose={() => {
              setSightingReversed(false);
              setAddSightingOpen(false);
            }}
          />
        </>
      )}

      {onContainerDeleteRelation && container && (
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
            container={container}
            enableReferences={enableReferences}
            onClose={() => setRemoveDialogOpen(false)}
            onContainerDeleteRelation={onContainerDeleteRelation}
          />
        </>
      )}
    </>
  );
};

export default GraphToolbarContentTools;
