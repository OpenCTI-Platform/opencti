import { SelectAll, SelectGroup, SelectionDrag } from 'mdi-material-ui';
import { GestureOutlined, SwipeDown, SwipeUp, SwipeVertical, TouchApp } from '@mui/icons-material';
import React, { useState } from 'react';
import GraphToolbarOptionsList from './GraphToolbarOptionsList';
import GraphToolbarItem from './GraphToolbarItem';
import { useFormatter } from '../../../components/i18n';
import { useGraphContext } from '../utils/GraphContext';
import useGraphInteractions from '../utils/useGraphInteractions';

const GraphToolbarSelectTools = () => {
  const { t_i18n } = useFormatter();
  const [selectByTypeAnchor, setSelectByTypeAnchor] = useState<Element>();

  const {
    stixCoreObjectTypes,
    selectedNodes,
    graphState: {
      mode3D,
      selectFreeRectangle,
      selectFree,
      selectRelationshipMode,
    },
  } = useGraphContext();

  const {
    toggleSelectFree,
    toggleSelectFreeRectangle,
    switchSelectRelationshipMode,
    selectByEntityType,
    selectAllNodes,
  } = useGraphInteractions();

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
    </>
  );
};

export default GraphToolbarSelectTools;
