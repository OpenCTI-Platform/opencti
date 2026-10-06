import React, { ReactNode } from 'react';
import { AutoFix, FamilyTree, SelectAll, SelectGroup, SelectionDrag, Video3d } from 'mdi-material-ui';
import {
  AccountBalanceOutlined,
  CenterFocusStrongOutlined,
  CenterFocusWeakOutlined,
  DateRangeOutlined,
  FilterAltOffOutlined,
  FilterCenterFocusOutlined,
  FilterListOutlined,
  FullscreenExitOutlined,
  FullscreenOutlined,
  GestureOutlined,
  HubOutlined,
  ImageOutlined,
  KeyboardOutlined,
  LegendToggleOutlined,
  MyLocationOutlined,
  PolylineOutlined,
  RouteOutlined,
  ScatterPlotOutlined,
  SwipeDown,
  SwipeUp,
  SwipeVertical,
  TouchApp,
  TrackChangesOutlined,
  ViewWeekOutlined,
  ZoomInOutlined,
  ZoomOutOutlined,
} from '@mui/icons-material';
import { useFormatter } from '../../i18n';
import { useGraphContext } from '../GraphContext';
import { useGraphView } from '../GraphViewContext';
import useGraphInteractions from '../utils/useGraphInteractions';
import type { ToolbarOverflowCandidate } from '../utils/graphToolbarOverflow';
import { selectableTypes } from '../utils/graphCollapse';
import { minutesBetweenDates } from '../../../utils/Time';
import { MESSAGING$ } from '../../../relay/environment';

/** Groups of the graph toolbar, in their order from left to right. */
export const GRAPH_TOOLBAR_GROUPS = ['view', 'layout', 'selection', 'filters', 'export', 'help'] as const;
export type GraphToolbarGroup = typeof GRAPH_TOOLBAR_GROUPS[number];

/** Names of the toolbar groups, for the groups of the toolbar and the headings of "More actions". */
export const useGraphToolbarGroupLabels = (): Record<GraphToolbarGroup, string> => {
  const { t_i18n } = useFormatter();
  return {
    view: t_i18n('View'),
    layout: t_i18n('Layout'),
    selection: t_i18n('Selection'),
    filters: t_i18n('Filters'),
    export: t_i18n('Export'),
    help: t_i18n('Help'),
  };
};

export interface GraphToolbarOption {
  key: string;
  label: string;
  /** Heading of the part of the list the option belongs to. */
  section?: string;
  selected?: boolean;
}

export interface GraphToolbarAction extends ToolbarOverflowCandidate {
  group: GraphToolbarGroup;
  /** Translated, sentence case; the same whatever the state of a toggle. */
  label: string;
  icon: ReactNode;
  shortcut?: string;
  /** Set for a toggle: whether it is on. */
  pressed?: boolean;
  /** Set when the action is not available now, saying why. */
  disabledReason?: string;
  /** Number of filters or choices in use. */
  badge?: number;
  onSelect?: () => void;
  /** A list to choose from: a menu from the toolbar, a submenu from "More actions". */
  options?: {
    items: GraphToolbarOption[];
    multiple?: boolean;
    onSelect: (key: string) => void;
  };
}

const ICON = { fontSize: 'medium' } as const;

/**
 * Every action of the graph toolbar that is a plain button, a toggle or a list, with what it needs
 * to be drawn in the toolbar or listed in its "More actions" menu. The priority decides which ones
 * stay in the toolbar when it is short of room; rare actions (priority 0) are always in the menu.
 */
const useGraphToolbarActions = ({ onUnfixNodes }: { onUnfixNodes?: () => void }): GraphToolbarAction[] => {
  const { t_i18n } = useFormatter();
  const view = useGraphView();
  const {
    context,
    isFullscreen,
    graphData,
    stixCoreObjectTypes,
    relationshipTypes,
    markingDefinitions,
    creators,
    timeRange,
    graphState: {
      mode3D,
      modeTree,
      withForces,
      layoutMode,
      selectFreeRectangle,
      selectFree,
      selectRelationshipMode,
      selectedNodes,
      highlightedPath,
      showTimeRange,
      disabledEntityTypes,
      disabledRelationshipTypes = [],
      disabledMarkings,
      disabledCreators,
      selectedTimeRangeInterval,
      correlationMode,
      showLegend = true,
    },
  } = useGraphContext();
  const {
    zoomIn,
    zoomOut,
    zoomToFit,
    zoomToSelection,
    locateNode,
    toggleMode3D,
    toggleVerticalTree,
    toggleHorizontalTree,
    toggleLayoutMode,
    toggleForces,
    unfixNodes,
    toggleSelectFreeRectangle,
    toggleSelectFree,
    selectNeighbours,
    highlightShortestPath,
    clearHighlightedPath,
    selectAllNodes,
    selectByEntityType,
    isNodeShown,
    switchSelectRelationshipMode,
    toggleTimeRange,
    toggleEntityType,
    toggleRelationshipType,
    toggleMarkingDefinition,
    toggleCreator,
    resetFilters,
    setCorrelationMode,
    toggleLegend,
  } = useGraphInteractions();

  const in3D = mode3D ? t_i18n('Not available in 3D mode') : undefined;
  // The 2D tree layouts break cycles; the 3D one cannot place a cycle and leaves such a graph as it is.
  const treeUnavailable = mode3D && !!view?.drawnHasCycle;
  let treeDisabledReason: string | undefined;
  if (!withForces) treeDisabledReason = t_i18n('Turn the forces on to use this layout');
  else if (treeUnavailable) treeDisabledReason = t_i18n('The graph has a cycle: use this layout in 2D mode');
  const hasSelection = selectedNodes.length > 0;
  const needsSelection = hasSelection ? undefined : t_i18n('Select entities first');

  // The time range counts as one filter per end moved away from the full range; a small margin
  // absorbs the rounding of the range scale.
  const [start, end] = timeRange.interval;
  const [selectedStart, selectedEnd] = selectedTimeRangeInterval ?? [];
  let timeRangeFilters = 0;
  if (selectedTimeRangeInterval) {
    if (minutesBetweenDates(start, selectedStart ?? new Date()) > 20) timeRangeFilters += 1;
    if (minutesBetweenDates(selectedEnd ?? new Date(), end) > 20) timeRangeFilters += 1;
  }
  const typeFilterCount = view?.typeFilterCount ?? disabledEntityTypes.length + disabledRelationshipTypes.length;
  // Clearing follows the stored filters, not the counts shown: a type filtered out that is not drawn any
  // more, or a time range moved by less than the counted margin, still filters the graph.
  const hasStoredFilters = disabledEntityTypes.length + disabledRelationshipTypes.length + disabledMarkings.length
    + disabledCreators.length > 0 || !!selectedTimeRangeInterval;

  const relationshipModeLabel = () => {
    if (selectRelationshipMode === 'children') return t_i18n('Select the child relationships of the selected nodes (from)');
    if (selectRelationshipMode === 'parent') return t_i18n('Select the parent relationships of the selected nodes (to)');
    if (selectRelationshipMode === 'deselect') return t_i18n('Deselect the relationships of the selected nodes');
    return t_i18n('Select the relationships of the selected nodes');
  };
  const relationshipModeIcon = () => {
    if (selectRelationshipMode === 'children') return <SwipeDown {...ICON} />;
    if (selectRelationshipMode === 'parent') return <SwipeUp {...ICON} />;
    if (selectRelationshipMode === 'deselect') return <TouchApp {...ICON} />;
    return <SwipeVertical {...ICON} />;
  };

  const toggleShortestPath = () => {
    if (highlightedPath) clearHighlightedPath();
    else if (!highlightShortestPath()) MESSAGING$.notifyError(t_i18n('These two nodes are not connected in this graph'));
  };
  let shortestPathReason = in3D;
  if (!shortestPathReason && !highlightedPath && selectedNodes.length !== 2) shortestPathReason = t_i18n('Select exactly two entities first');

  // The types drawn, as the legend lists them (the whole inventory for a toolbar outside a graph
  // view). A nested relationship drawn as a node is filtered with the relationships, as in the legend.
  const filterEntityTypes = view?.drawnTypes.entityTypes ?? stixCoreObjectTypes.filter((type) => !relationshipTypes.includes(type));
  const filterRelationshipTypes = view?.drawnTypes.relationshipTypes ?? relationshipTypes;
  const typeOptions = [
    ...filterEntityTypes.map((type) => ({
      key: `entity:${type}`,
      label: t_i18n(`entity_${type}`),
      section: t_i18n('Entities'),
      selected: !disabledEntityTypes.includes(type),
    })),
    ...filterRelationshipTypes.map((type) => ({
      key: `relationship:${type}`,
      label: t_i18n(`relationship_${type}`),
      section: t_i18n('Relationships'),
      selected: !disabledRelationshipTypes.includes(type),
    })),
  ];
  let typeFilterDisabledReason: string | undefined;
  if (stixCoreObjectTypes.length === 0) typeFilterDisabledReason = t_i18n('The graph has no entity yet');
  else if (typeOptions.length === 0) typeFilterDisabledReason = t_i18n('Every entity is hidden');

  const typesToSelect = selectableTypes(stixCoreObjectTypes, graphData?.nodes ?? [], isNodeShown);
  let selectByTypeDisabledReason: string | undefined;
  if (stixCoreObjectTypes.length === 0) selectByTypeDisabledReason = t_i18n('The graph has no entity yet');
  else if (typesToSelect.length === 0) selectByTypeDisabledReason = t_i18n('Every entity is hidden or collapsed into a group');

  const actions: GraphToolbarAction[] = [
    // --- View
    { id: 'zoom-in', group: 'view', priority: 30, label: t_i18n('Zoom in'), shortcut: '+', icon: <ZoomInOutlined {...ICON} />, disabledReason: in3D, onSelect: zoomIn },
    { id: 'zoom-out', group: 'view', priority: 30, label: t_i18n('Zoom out'), shortcut: '-', icon: <ZoomOutOutlined {...ICON} />, disabledReason: in3D, onSelect: zoomOut },
    { id: 'fit', group: 'view', priority: 100, label: t_i18n('Fit the whole graph'), shortcut: 'F', icon: <CenterFocusWeakOutlined {...ICON} />, onSelect: zoomToFit },
    {
      id: 'fit-selection',
      group: 'view',
      priority: 60,
      label: t_i18n('Fit the selection'),
      shortcut: 'Shift+F',
      icon: <FilterCenterFocusOutlined {...ICON} />,
      disabledReason: needsSelection,
      onSelect: () => zoomToSelection(),
    },
    {
      id: 'locate',
      group: 'view',
      priority: 40,
      label: t_i18n('Locate the selection'),
      shortcut: 'L',
      icon: <MyLocationOutlined {...ICON} />,
      disabledReason: in3D ?? needsSelection,
      onSelect: () => locateNode(),
    },
    ...(view ? [{
      id: 'fullscreen',
      group: 'view' as const,
      priority: 90,
      label: t_i18n('Full screen'),
      shortcut: 'Shift+M',
      icon: isFullscreen ? <FullscreenExitOutlined {...ICON} /> : <FullscreenOutlined {...ICON} />,
      pressed: isFullscreen,
      onSelect: view.toggleFullscreen,
    }] : []),
    // --- Layout
    { id: 'mode-3d', group: 'layout', priority: 75, label: t_i18n('3D mode'), icon: <Video3d {...ICON} />, pressed: mode3D, onSelect: toggleMode3D },
    {
      id: 'tree-vertical',
      group: 'layout',
      priority: 65,
      label: t_i18n('Vertical tree layout'),
      icon: <FamilyTree {...ICON} />,
      pressed: modeTree === 'td' && !treeUnavailable,
      disabledReason: treeDisabledReason,
      onSelect: toggleVerticalTree,
    },
    {
      id: 'tree-horizontal',
      group: 'layout',
      priority: 65,
      label: t_i18n('Horizontal tree layout'),
      icon: <FamilyTree {...ICON} style={{ transform: 'rotate(-90deg)' }} />,
      pressed: modeTree === 'lr' && !treeUnavailable,
      disabledReason: treeDisabledReason,
      onSelect: toggleHorizontalTree,
    },
    {
      id: 'layout-tiers',
      group: 'layout',
      priority: 55,
      label: t_i18n('Layout by entity tier'),
      icon: <ViewWeekOutlined {...ICON} />,
      pressed: layoutMode === 'tiers',
      disabledReason: in3D,
      onSelect: () => toggleLayoutMode('tiers'),
    },
    {
      id: 'layout-radial',
      group: 'layout',
      priority: 55,
      label: t_i18n('Radial layout around the selection'),
      icon: <TrackChangesOutlined {...ICON} />,
      pressed: layoutMode === 'radial',
      disabledReason: in3D,
      onSelect: () => toggleLayoutMode('radial'),
    },
    { id: 'forces', group: 'layout', priority: 70, label: t_i18n('Forces'), icon: <ScatterPlotOutlined {...ICON} />, pressed: withForces, onSelect: toggleForces },
    {
      id: 'reset-layout',
      group: 'layout',
      priority: 0,
      label: t_i18n('Unfix the nodes and re-apply forces'),
      icon: <AutoFix {...ICON} />,
      disabledReason: withForces ? undefined : t_i18n('Turn the forces on first'),
      onSelect: () => {
        unfixNodes();
        onUnfixNodes?.();
      },
    },
    // --- Selection
    {
      id: 'select-rectangle',
      group: 'selection',
      priority: 80,
      label: t_i18n('Rectangle selection'),
      icon: <SelectionDrag {...ICON} />,
      pressed: selectFreeRectangle,
      disabledReason: in3D,
      onSelect: toggleSelectFreeRectangle,
    },
    {
      id: 'select-free',
      group: 'selection',
      priority: 75,
      label: t_i18n('Free-shape selection'),
      icon: <GestureOutlined {...ICON} />,
      pressed: selectFree,
      disabledReason: in3D,
      onSelect: toggleSelectFree,
    },
    {
      id: 'select-neighbours',
      group: 'selection',
      priority: 50,
      label: t_i18n('Select the neighbours of the selected nodes'),
      shortcut: 'N',
      icon: <HubOutlined {...ICON} />,
      disabledReason: needsSelection,
      onSelect: () => selectNeighbours(),
    },
    {
      id: 'shortest-path',
      group: 'selection',
      priority: 50,
      label: t_i18n('Shortest path between the two selected nodes'),
      shortcut: 'P',
      icon: <RouteOutlined {...ICON} />,
      pressed: !!highlightedPath,
      disabledReason: shortestPathReason,
      onSelect: toggleShortestPath,
    },
    { id: 'select-all', group: 'selection', priority: 0, label: t_i18n('Select all nodes'), shortcut: 'Ctrl+A', icon: <SelectAll {...ICON} />, onSelect: selectAllNodes },
    {
      id: 'select-by-type',
      group: 'selection',
      priority: 0,
      label: t_i18n('Select by entity type'),
      icon: <SelectGroup {...ICON} />,
      disabledReason: selectByTypeDisabledReason,
      options: {
        items: typesToSelect.map((type) => ({ key: type, label: t_i18n(`entity_${type}`) })),
        onSelect: selectByEntityType,
      },
    },
    {
      id: 'select-relationships',
      group: 'selection',
      priority: 0,
      label: relationshipModeLabel(),
      icon: relationshipModeIcon(),
      disabledReason: needsSelection,
      onSelect: () => switchSelectRelationshipMode(),
    },
    // --- Filters
    ...(context === 'correlation' ? [
      {
        id: 'correlation-all',
        group: 'filters' as const,
        priority: 85,
        label: t_i18n('Show all correlated entities'),
        icon: <HubOutlined {...ICON} />,
        pressed: correlationMode === 'all',
        onSelect: () => setCorrelationMode('all'),
      },
      {
        id: 'correlation-observables',
        group: 'filters' as const,
        priority: 85,
        label: t_i18n('Show only correlated observables and indicators'),
        icon: <PolylineOutlined {...ICON} />,
        pressed: correlationMode === 'observables',
        onSelect: () => setCorrelationMode('observables'),
      },
    ] : []),
    {
      id: 'filter-types',
      group: 'filters',
      priority: 85,
      label: t_i18n('Filter by type'),
      icon: <FilterListOutlined {...ICON} />,
      badge: typeFilterCount,
      disabledReason: typeFilterDisabledReason,
      options: {
        multiple: true,
        items: typeOptions,
        onSelect: (key) => {
          const [kind, type] = [key.slice(0, key.indexOf(':')), key.slice(key.indexOf(':') + 1)];
          if (kind === 'relationship') toggleRelationshipType(type);
          else toggleEntityType(type);
        },
      },
    },
    {
      id: 'time-range',
      group: 'filters',
      priority: 70,
      label: t_i18n('Time range'),
      icon: <DateRangeOutlined {...ICON} />,
      pressed: showTimeRange,
      badge: timeRangeFilters,
      onSelect: toggleTimeRange,
    },
    {
      id: 'filter-markings',
      group: 'filters',
      priority: 45,
      label: t_i18n('Filter by marking'),
      icon: <CenterFocusStrongOutlined {...ICON} />,
      badge: disabledMarkings.length,
      disabledReason: markingDefinitions.length === 0 ? t_i18n('No marking in this graph') : undefined,
      options: {
        multiple: true,
        items: markingDefinitions.map((marking) => ({ key: marking.id, label: marking.definition, selected: !disabledMarkings.includes(marking.id) })),
        onSelect: toggleMarkingDefinition,
      },
    },
    {
      id: 'filter-authors',
      group: 'filters',
      priority: 45,
      label: t_i18n('Filter by author'),
      icon: <AccountBalanceOutlined {...ICON} />,
      badge: disabledCreators.length,
      disabledReason: creators.length === 0 ? t_i18n('No author in this graph') : undefined,
      options: {
        multiple: true,
        items: creators.map((creator) => ({ key: creator.id, label: creator.name, selected: !disabledCreators.includes(creator.id) })),
        onSelect: toggleCreator,
      },
    },
    {
      id: 'clear-filters',
      group: 'filters',
      priority: 60,
      label: t_i18n('Clear all filters'),
      icon: <FilterAltOffOutlined {...ICON} />,
      disabledReason: hasStoredFilters ? undefined : t_i18n('No filter is active'),
      onSelect: resetFilters,
    },
  ];

  if (view) {
    if (view.exportImage) {
      actions.push({
        id: 'export-image',
        group: 'export',
        priority: 35,
        label: t_i18n('Export the whole graph as a high-resolution image'),
        shortcut: 'Shift+E',
        icon: <ImageOutlined {...ICON} />,
        disabledReason: in3D,
        onSelect: view.exportImage,
      });
    }
    actions.push(
      {
        id: 'legend',
        group: 'help',
        priority: 65,
        label: t_i18n('Legend'),
        shortcut: 'G',
        icon: <LegendToggleOutlined {...ICON} />,
        pressed: !mode3D && showLegend,
        disabledReason: in3D,
        onSelect: toggleLegend,
      },
      { id: 'shortcuts', group: 'help', priority: 20, label: t_i18n('Keyboard shortcuts'), shortcut: '?', icon: <KeyboardOutlined {...ICON} />, onSelect: view.showShortcuts },
    );
  }
  return actions;
};

export default useGraphToolbarActions;
