import { SelectAll, SelectGroup, SelectionDrag } from 'mdi-material-ui';
import { DeviceHubOutlined, GestureOutlined, SwipeDown, SwipeUp, SwipeVertical, TouchApp } from '@mui/icons-material';
import React, { useState } from 'react';
import Dialog from '@mui/material/Dialog';
import GraphToolbarOptionsList from './GraphToolbarOptionsList';
import GraphToolbarItem from './GraphToolbarItem';
import { useFormatter } from '../../i18n';
import { useGraphContext } from '../GraphContext';
import useGraphInteractions from '../utils/useGraphInteractions';
import InvestigationSelectByEdgeForm, { SelectByEdgeFormData } from '@components/workspaces/investigations/InvestigationSelectByEdgeForm';

const GraphToolbarSelectTools = () => {
  const { t_i18n } = useFormatter();
  const [selectByTypeAnchor, setSelectByTypeAnchor] = useState<Element>();

  const {
    stixCoreObjectTypes,
    graphData,
    graphState: {
      mode3D,
      selectFreeRectangle,
      selectFree,
      selectRelationshipMode,
      selectedNodes,
    },
  } = useGraphContext();

  const {
    toggleSelectFree,
    toggleSelectFreeRectangle,
    switchSelectRelationshipMode,
    selectByEntityType,
    selectAllNodes,
    setSelectedNodes,
    clearSelection,
  } = useGraphInteractions();

  const [isSelectByEdgeOpen, setIsSelectByEdgeOpen] = useState(false);

  const onSelectByEdge = ({ edge_count, entity_types }: SelectByEdgeFormData) => {
    if (entity_types.length === 0) return;

    const links = graphData?.links ?? [];
    const nodes = graphData?.nodes ?? [];
    const entityTypeFilter = entity_types.map((o) => o.value);
    const targetCount = Number(edge_count);

    const matchingNodes = nodes.filter((node) => {
      const edgeCount = links.filter(
        (link) => link.source_id === node.id || link.target_id === node.id,
      ).length;
      return edgeCount === targetCount && entityTypeFilter.includes(node.entity_type);
    });

    clearSelection();
    setSelectedNodes(matchingNodes);
    setIsSelectByEdgeOpen(false);
  };

  const titleSelectRelationshipMode = () => {
    if (selectRelationshipMode === 'children') return t_i18n('Select Child Relationships of Selected Nodes (From)');
    if (selectRelationshipMode === 'parent') return t_i18n('Select Parent Relationships of Selected Nodes (To)');
    if (selectRelationshipMode === 'deselect') return t_i18n('Deselect Relationships of Selected Nodes');
    return t_i18n('Select Relationships of Selected Nodes');
  };
  const iconSelectRelationshipMode = () => {
    if (selectRelationshipMode === 'children') return <SwipeDown />;
    if (selectRelationshipMode === 'parent') return <SwipeUp />;
    if (selectRelationshipMode === 'deselect') return <TouchApp />;
    return <SwipeVertical />;
  };

  return (
    <>
      <GraphToolbarItem
        Icon={<SelectionDrag />}
        disabled={mode3D}
        color={selectFreeRectangle ? 'secondary' : 'primary'}
        onClick={toggleSelectFreeRectangle}
        title={t_i18n('Free rectangle select')}
      />

      <GraphToolbarItem
        Icon={<GestureOutlined />}
        disabled={mode3D}
        color={selectFree ? 'secondary' : 'primary'}
        onClick={toggleSelectFree}
        title={t_i18n('Free select')}
      />

      <GraphToolbarItem
        Icon={<SelectGroup />}
        disabled={stixCoreObjectTypes.length === 0}
        color="primary"
        onClick={(e) => setSelectByTypeAnchor(e.currentTarget)}
        title={t_i18n('Select by entity type')}
      />
      <GraphToolbarOptionsList
        anchorEl={selectByTypeAnchor}
        onClose={() => setSelectByTypeAnchor(undefined)}
        options={stixCoreObjectTypes}
        getOptionKey={(type) => type}
        getOptionText={(type) => t_i18n(`entity_${type}`)}
        onSelect={(type) => {
          selectByEntityType(type);
          setSelectByTypeAnchor(undefined);
        }}
      />

      <GraphToolbarItem
        Icon={<SelectAll />}
        color="primary"
        onClick={selectAllNodes}
        title={t_i18n('Select all nodes')}
      />

      <GraphToolbarItem
        Icon={iconSelectRelationshipMode()}
        disabled={selectedNodes.length === 0}
        color="primary"
        onClick={() => switchSelectRelationshipMode()}
        title={titleSelectRelationshipMode()}
      />

      <GraphToolbarItem
        Icon={<DeviceHubOutlined />}
        color="primary"
        onClick={() => setIsSelectByEdgeOpen(true)}
        title={t_i18n('Select nodes by edge count')}
        disabled={(graphData?.nodes ?? []).length === 0}
      />

      <Dialog
        fullWidth
        maxWidth={false}
        open={isSelectByEdgeOpen}
        sx={{ '& .MuiDialog-paper': { width: 640 } }}
        onClose={() => setIsSelectByEdgeOpen(false)}
      >
        <InvestigationSelectByEdgeForm
          nodes={graphData?.nodes ?? []}
          links={graphData?.links ?? []}
          onSubmit={onSelectByEdge}
          onReset={() => setIsSelectByEdgeOpen(false)}
        />
      </Dialog>
    </>
  );
};

export default GraphToolbarSelectTools;
