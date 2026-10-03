import { SelectAll, SelectGroup, SelectionDrag } from 'mdi-material-ui';
import { GestureOutlined, HubOutlined, RouteOutlined, SwipeDown, SwipeUp, SwipeVertical, TouchApp } from '@mui/icons-material';
import React, { useState } from 'react';
import GraphToolbarOptionsList from './GraphToolbarOptionsList';
import GraphToolbarItem from './GraphToolbarItem';
import { useFormatter } from '../../i18n';
import { useGraphContext } from '../GraphContext';
import useGraphInteractions from '../utils/useGraphInteractions';
import { MESSAGING$ } from '../../../relay/environment';

const GraphToolbarSelectTools = () => {
  const { t_i18n } = useFormatter();
  const [selectByTypeAnchor, setSelectByTypeAnchor] = useState<Element>();

  const {
    stixCoreObjectTypes,
    graphState: {
      mode3D,
      selectFreeRectangle,
      selectFree,
      selectRelationshipMode,
      selectedNodes,
      highlightedPath,
    },
  } = useGraphContext();

  const {
    toggleSelectFree,
    toggleSelectFreeRectangle,
    switchSelectRelationshipMode,
    selectByEntityType,
    selectAllNodes,
    selectNeighbours,
    highlightShortestPath,
    clearHighlightedPath,
  } = useGraphInteractions();

  const toggleShortestPath = () => {
    if (highlightedPath) {
      clearHighlightedPath();
    } else if (!highlightShortestPath()) {
      MESSAGING$.notifyError(t_i18n('These two nodes are not connected in this graph'));
    }
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
        Icon={<HubOutlined />}
        disabled={selectedNodes.length === 0}
        color="primary"
        onClick={() => selectNeighbours()}
        title={t_i18n('Select the neighbours of the selected nodes')}
      />

      <GraphToolbarItem
        Icon={<RouteOutlined />}
        disabled={mode3D || selectedNodes.length !== 2}
        color={highlightedPath ? 'secondary' : 'primary'}
        onClick={toggleShortestPath}
        title={highlightedPath
          ? t_i18n('Clear the highlighted path')
          : t_i18n('Highlight the shortest path between the two selected nodes')}
      />
    </>
  );
};

export default GraphToolbarSelectTools;
