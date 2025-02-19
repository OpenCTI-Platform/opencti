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
  onAddRelation: (rel: ObjectToParse) => void
  container?: GraphContainer
  enableReferences?: boolean
  onContainerDeleteRelation: GraphToolbarDeleteConfirmProps['onContainerDeleteRelation']
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

  const [addRelationOpen, setAddRelationOpen] = useState(false);
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
  } = useGraphContext();

  const {
    addNode,
    removeNode,
  } = useGraphInteractions();

  if (!container) return null;

  const selectedEntityTypes = Array.from(new Set(selectedNodes.map((n) => n.entity_type)));
  const [entityType1, entityType2] = selectedEntityTypes;
  const nodesEntityType1 = selectedNodes.filter((n) => n.entity_type === entityType1);
  const nodesEntityType2 = selectedNodes.filter((n) => n.entity_type === entityType2);

  const relBetweenNodes = selectedEntityTypes.length === 2 && selectedLinks.length === 0;
  const relBetweenNodeAndLink = selectedNodes.length === 1 && selectedLinks.length === 1;
  const canAddRelation = relBetweenNodes || relBetweenNodeAndLink;

  const selectionContainsInferred = selectedNodes.some((n) => n.isNestedInferred)
    || selectedLinks.some((n) => n.inferred || n.isNestedInferred);
  const canDelete = !selectionContainsInferred && (selectedNodes.length > 0 || selectedLinks.length > 0);

  let objectsFrom: (GraphNode | GraphLink)[] = [];
  let objectsTo: (GraphNode | GraphLink)[] = [];
  if (relBetweenNodes) {
    objectsFrom = relationReversed || sightingReversed || nestedReversed ? nodesEntityType2 : nodesEntityType1;
    objectsTo = relationReversed || sightingReversed || nestedReversed ? nodesEntityType1 : nodesEntityType2;
  } else if (relBetweenNodeAndLink) {
    objectsFrom = relationReversed || sightingReversed || nestedReversed ? [selectedNodes[0]] : [selectedLinks[0]];
    objectsTo = relationReversed || sightingReversed || nestedReversed ? [selectedLinks[0]] : [selectedNodes[0]];
  }

  return (
    <>
      <ContainerAddStixCoreObjectsInGraph
        knowledgeGraph={true} // TODO change for correlation?
        containerId={container.id}
        containerStixCoreObjects={container.objects}
        defaultCreatedBy={container.createdBy ?? null}
        defaultMarkingDefinitions={container.objectMarking ?? []}
        targetStixCoreObjectTypes={['Stix-Domain-Object', 'Stix-Cyber-Observable']}
        onAdd={addNode}
        onDelete={({ id }: { id: string }) => removeNode(id)}
        confidence={container.confidence}
        enableReferences={enableReferences}
      />

      <GraphToolbarEditObject
        stixCoreObjectRefetchQuery={stixCoreObjectRefetchQuery}
        relationshipRefetchQuery={relationshipRefetchQuery}
      />

      <GraphToolbarItem
        Icon={<LinkOutlined />}
        disabled={!canAddRelation}
        color="primary"
        onClick={() => setAddRelationOpen(true)}
        title={t_i18n('Create a relationship')}
      />
      <StixCoreRelationshipCreation
        open={addRelationOpen}
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
          setAddRelationOpen(false);
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
  );
};

export default GraphToolbarContentTools;
