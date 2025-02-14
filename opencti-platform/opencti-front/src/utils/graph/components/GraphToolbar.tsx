import Drawer from '@mui/material/Drawer';
import React, { useState } from 'react';
import { AutoFix, FamilyTree, SelectAll, SelectGroup, SelectionDrag, Video3d } from 'mdi-material-ui';
import {
  AccountBalanceOutlined,
  Add,
  AspectRatioOutlined,
  CenterFocusStrongOutlined,
  DateRangeOutlined,
  DeleteOutlined,
  EditOutlined,
  FilterAltOffOutlined,
  FilterListOutlined,
  GestureOutlined,
  LinkOutlined,
  ScatterPlotOutlined,
  SwipeDown,
  SwipeUp,
  SwipeVertical,
  TouchApp,
  VisibilityOutlined,
} from '@mui/icons-material';
import Divider from '@mui/material/Divider';
import { useFormatter } from '../../../components/i18n';
import { useGraphContext } from '../utils/GraphContext';
import GraphToolbarItem from './GraphToolbarItem';
import useGraphInteractions from '../utils/useGraphInteractions';
import SearchInput from '../../../components/SearchInput';
import GraphToolbarEntityTypes from './GraphToolbarEntityTypes';

const GraphToolbar = () => {
  const { t_i18n } = useFormatter();
  const navOpen = localStorage.getItem('navOpen') === 'true';

  const [byEntityTypeAnchor, setByEntityTypeAnchor] = useState<Element>();

  const {
    stixCoreObjectTypes,
    graphState: {
      mode3D,
      modeTree,
      withForces,
      selectFreeRectangle,
      selectFree,
      selectRelationshipMode,
      showTimeRange,
    },
  } = useGraphContext();

  const {
    toggleSelectFree,
    toggleForces,
    toggleHorizontalTree,
    toggleMode3D,
    toggleSelectFreeRectangle,
    toggleTimeRange,
    toggleVerticalTree,
    switchSelectRelationshipMode,
    zoomToFit,
    unfixNodes,
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
    <Drawer
      anchor="bottom"
      variant="permanent"
      PaperProps={{
        elevation: 1,
        style: {
          zIndex: 1,
          paddingLeft: navOpen ? 180 : 60,
          height: 54,
        },
      }}
    >
      <div style={{ height: 54, display: 'flex', alignItems: 'center' }}>
        <GraphToolbarItem
          Icon={<Video3d />}
          color={mode3D ? 'secondary' : 'primary'}
          onClick={toggleMode3D}
          title={mode3D ? t_i18n('Disable 3D mode') : t_i18n('Enable 3D mode')}
        />
        <GraphToolbarItem
          Icon={<FamilyTree />}
          disabled={!withForces}
          color={modeTree === 'td' ? 'secondary' : 'primary'}
          onClick={toggleVerticalTree}
          title={modeTree ? t_i18n('Disable vertical tree mode') : t_i18n('Enable vertical tree mode')}
        />
        <GraphToolbarItem
          Icon={<FamilyTree style={{ transform: 'rotate(-90deg)' }} />}
          disabled={!withForces}
          color={modeTree === 'lr' ? 'secondary' : 'primary'}
          onClick={toggleHorizontalTree}
          title={modeTree ? t_i18n('Disable horizontal tree mode') : t_i18n('Enable horizontal tree mode')}
        />
        <GraphToolbarItem
          Icon={<ScatterPlotOutlined />}
          color={!withForces ? 'primary' : 'secondary'}
          onClick={toggleForces}
          title={modeTree ? t_i18n('Enable forces') : t_i18n('Disable forces')}
        />
        <GraphToolbarItem
          Icon={<AspectRatioOutlined />}
          color="primary"
          onClick={zoomToFit}
          title={t_i18n('Fit graph to canvas')}
        />
        <GraphToolbarItem
          Icon={<AutoFix />}
          disabled={!withForces}
          color="primary"
          onClick={unfixNodes}
          title={t_i18n('Unfix the nodes and re-apply forces')}
        />

        <Divider sx={{ margin: 1, height: '80%' }} orientation="vertical" />

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
          onClick={(e) => setByEntityTypeAnchor(e.currentTarget)}
          title={t_i18n('Select by entity type')}
        />
        <GraphToolbarEntityTypes
          anchorEl={byEntityTypeAnchor}
          onClose={() => setByEntityTypeAnchor(undefined)}
          onSelect={(type) => {
            selectByEntityType(type);
            setByEntityTypeAnchor(undefined);
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
          disabled={false}
          color="primary"
          onClick={() => switchSelectRelationshipMode()}
          title={titleSelectRelationshipMode()}
        />

        <Divider sx={{ margin: 1, height: '80%' }} orientation="vertical" />

        <GraphToolbarItem
          Icon={<DateRangeOutlined />}
          color={showTimeRange ? 'secondary' : 'primary'}
          onClick={toggleTimeRange}
          title={t_i18n('Display time range selector')}
        />
        <GraphToolbarItem
          Icon={<FilterListOutlined />}
          disabled={false}
          color="primary"
          onClick={() => console.log('handleOpenStixCoreObjectsTypes')}
          title={t_i18n('Filter entity types')}
        />
        <GraphToolbarItem
          Icon={<CenterFocusStrongOutlined />}
          disabled={false}
          color="primary"
          onClick={() => console.log('handleOpenMarkedBy')}
          title={t_i18n('Filter marking definitions')}
        />
        <GraphToolbarItem
          Icon={<AccountBalanceOutlined />}
          disabled={false}
          color="primary"
          onClick={() => console.log('handleOpenCreatedBy')}
          title={t_i18n('Filter authors (created by)')}
        />
        <GraphToolbarItem
          Icon={<FilterAltOffOutlined />}
          disabled={false}
          color="primary"
          onClick={() => console.log('resetAllFilters')}
          title={t_i18n('Clear all filters')}
        />

        <Divider sx={{ margin: 1, marginRight: 3, height: '80%' }} orientation="vertical" />

        <div style={{ flex: 1 }}>
          <SearchInput
            variant="thin"
            onSubmit={console.log}
          />
        </div>

        <GraphToolbarItem
          Icon={<Add />}
          color="primary"
          onClick={() => console.log('TODO')}
          title={t_i18n('Add an entity to this container')}
        />
        <GraphToolbarItem
          Icon={<EditOutlined />}
          disabled={false}
          color="primary"
          onClick={() => console.log('handleOpenEditItem')}
          title={t_i18n('Edit the selected item')}
        />
        <GraphToolbarItem
          Icon={<LinkOutlined />}
          disabled={false}
          color="primary"
          onClick={() => console.log('handleOpenCreateRelationship')}
          title={t_i18n('Create a relationship')}
        />
        <div>...</div>
        <GraphToolbarItem
          Icon={<VisibilityOutlined />}
          disabled={false}
          color="primary"
          onClick={() => console.log('handleOpenCreateSighting')}
          title={t_i18n('Create a sighting')}
        />
        <GraphToolbarItem
          Icon={<DeleteOutlined />}
          disabled={false}
          color="primary"
          onClick={() => console.log('handleOpenRemove')}
          title={t_i18n('Remove selected items')}
        />
      </div>
    </Drawer>
  );
};

export default GraphToolbar;
