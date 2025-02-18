import Drawer from '@mui/material/Drawer';
import React, { useState } from 'react';
import { AutoFix, FamilyTree, SelectAll, SelectGroup, SelectionDrag, Video3d } from 'mdi-material-ui';
import {
  AccountBalanceOutlined,
  AspectRatioOutlined,
  CenterFocusStrongOutlined,
  DateRangeOutlined,
  DeleteOutlined,
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
import { useTheme } from '@mui/material/styles';
import Badge from '@mui/material/Badge';
import ContainerAddStixCoreObjectsInGraph from '@components/common/containers/ContainerAddStixCoreObjectsInGraph';
import { GraphQLTaggedNode } from 'relay-runtime/lib/query/RelayModernGraphQLTag';
import { useFormatter } from '../../../components/i18n';
import { useGraphContext } from '../utils/GraphContext';
import GraphToolbarItem from './GraphToolbarItem';
import useGraphInteractions from '../utils/useGraphInteractions';
import SearchInput from '../../../components/SearchInput';
import GraphToolbarOptionsList from './GraphToolbarOptionsList';
import type { Theme } from '../../../components/Theme';
import { GraphContainer } from '../graph.types';
import GraphToolbarEditObject from './GraphToolbarEditObject';

interface GraphToolbarProps {
  stixCoreObjectRefetchQuery: GraphQLTaggedNode
  relationshipRefetchQuery: GraphQLTaggedNode
  container?: GraphContainer
  enableReferences?: boolean
}

const GraphToolbar = ({
  stixCoreObjectRefetchQuery,
  relationshipRefetchQuery,
  container,
  enableReferences,
}: GraphToolbarProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const navOpen = localStorage.getItem('navOpen') === 'true';

  const [selectByTypeAnchor, setSelectByTypeAnchor] = useState<Element>();
  const [filterByTypeAnchor, setFilterByTypeAnchor] = useState<Element>();
  const [filterByMarkingAnchor, setFilterByMarkingAnchor] = useState<Element>();
  const [filterByCreatorAnchor, setFilterByCreatorAnchor] = useState<Element>();

  const {
    stixCoreObjectTypes,
    markingDefinitions,
    creators,
    selectedNodes,
    graphState: {
      mode3D,
      modeTree,
      withForces,
      selectFreeRectangle,
      selectFree,
      selectRelationshipMode,
      showTimeRange,
      disabledEntityTypes,
      disabledMarkings,
      disabledCreators,
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
    toggleEntityType,
    toggleCreator,
    toggleMarkingDefinition,
    resetFilters,
    selectBySearch,
    addNode,
    removeNode,
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
      <div style={{
        height: 54,
        display: 'flex',
        alignItems: 'center',
        gap: theme.spacing(0.5),
        padding: `0 ${theme.spacing(0.5)}`,
      }}
      >
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

        <Divider sx={{ margin: 1, height: '80%' }} orientation="vertical" />

        <GraphToolbarItem
          Icon={<DateRangeOutlined />}
          color={showTimeRange ? 'secondary' : 'primary'}
          onClick={toggleTimeRange}
          title={t_i18n('Display time range selector')}
        />
        <GraphToolbarItem
          Icon={(
            <Badge badgeContent={disabledEntityTypes.length} color="secondary">
              <FilterListOutlined />
            </Badge>
          )}
          disabled={stixCoreObjectTypes.length === 0}
          color="primary"
          onClick={(e) => setFilterByTypeAnchor(e.currentTarget)}
          title={t_i18n('Filter entity types')}
        />
        <GraphToolbarOptionsList
          isMultiple
          anchorEl={filterByTypeAnchor}
          onClose={() => setFilterByTypeAnchor(undefined)}
          options={stixCoreObjectTypes}
          getOptionKey={(type) => type}
          getOptionText={(type) => t_i18n(`entity_${type}`)}
          isOptionSelected={(type) => !disabledEntityTypes.includes(type)}
          onSelect={toggleEntityType}
        />
        <GraphToolbarItem
          Icon={(
            <Badge badgeContent={disabledMarkings.length} color="secondary">
              <CenterFocusStrongOutlined />
            </Badge>
          )}
          disabled={markingDefinitions.length === 0}
          color="primary"
          onClick={(e) => setFilterByMarkingAnchor(e.currentTarget)}
          title={t_i18n('Filter marking definitions')}
        />
        <GraphToolbarOptionsList
          isMultiple
          anchorEl={filterByMarkingAnchor}
          onClose={() => setFilterByMarkingAnchor(undefined)}
          options={markingDefinitions}
          getOptionKey={(marking) => marking.id}
          getOptionText={(marking) => marking.definition}
          isOptionSelected={(marking) => !disabledMarkings.includes(marking.id)}
          onSelect={(marking) => toggleMarkingDefinition(marking.id)}
        />
        <GraphToolbarItem
          Icon={(
            <Badge badgeContent={disabledCreators.length} color="secondary">
              <AccountBalanceOutlined />
            </Badge>
          )}
          disabled={creators.length === 0}
          color="primary"
          onClick={(e) => setFilterByCreatorAnchor(e.currentTarget)}
          title={t_i18n('Filter authors (created by)')}
        />
        <GraphToolbarOptionsList
          isMultiple
          anchorEl={filterByCreatorAnchor}
          onClose={() => setFilterByCreatorAnchor(undefined)}
          options={creators}
          getOptionKey={(creator) => creator.id}
          getOptionText={(creator) => creator.name}
          isOptionSelected={(creator) => !disabledCreators.includes(creator.id)}
          onSelect={(creator) => toggleCreator(creator.id)}
        />
        <GraphToolbarItem
          Icon={<FilterAltOffOutlined />}
          color="primary"
          onClick={resetFilters}
          title={t_i18n('Clear all filters')}
        />

        <Divider sx={{ margin: 1, marginRight: 3, height: '80%' }} orientation="vertical" />

        <div style={{ flex: 1 }}>
          <SearchInput variant="thin" onSubmit={selectBySearch} />
        </div>

        {container && (
          <>
            <ContainerAddStixCoreObjectsInGraph
              knowledgeGraph={true} // TODO change for correlation?
              containerId={container.id}
              containerStixCoreObjects={container.objects}
              defaultCreatedBy={container.createdBy ?? null}
              defaultMarkingDefinitions={container.objectMarking ?? []}
              targetStixCoreObjectTypes={['Stix-Domain-Object', 'Stix-Cyber-Observable']}
              onAdd={addNode}
              onDelete={removeNode}
              confidence={container.confidence}
              enableReferences={enableReferences}
            />
            <GraphToolbarEditObject
              stixCoreObjectRefetchQuery={stixCoreObjectRefetchQuery}
              relationshipRefetchQuery={relationshipRefetchQuery}
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
          </>
        )}
      </div>
    </Drawer>
  );
};

export default GraphToolbar;
