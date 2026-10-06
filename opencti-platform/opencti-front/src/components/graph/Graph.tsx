import ForceGraph2D from 'react-force-graph-2d';
import ForceGraph3D from 'react-force-graph-3d';
import React, { type MutableRefObject, ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import { useTheme } from '@mui/material/styles';
import RectangleSelection from './components/RectangleSelection';
import { useGraphContext } from './GraphContext';
import useResizeObserver from '../../utils/hooks/useResizeObserver';
import { GraphLink, GraphNode, LibGraphProps, OctiGraphPositions } from './graph.types';
import useGraphPainter, { type GraphHoverTarget, isHoveredLink, linkHoverTarget } from './utils/useGraphPainter';
import useGraphInteractions from './utils/useGraphInteractions';
import LassoSelection from './components/LassoSelection';
import useGraphFilter from './utils/useGraphFilter';
import EntitiesDetailsRightsBar from './components/EntitiesDetailsRightBar';
import type { Theme } from '../Theme';
import RelationSelection from './components/RelationSelection';
import GraphLoadingAlert from './components/GraphLoadingAlert';
import type { GraphCounter } from './components/GraphCounters';
import GraphEmptyState, { type GraphEmptyKind } from './components/GraphEmptyState';
import GraphLegend, { type GraphLegendBadge, GraphLegendPill } from './components/GraphLegend';
import { type GraphViewActions, GraphViewContext } from './GraphViewContext';
import GraphHoverCard, { type GraphHoverCardTarget } from './components/GraphHoverCard';
import GraphAccessibleList, { graphElementKey } from './components/GraphAccessibleList';
import GraphShortcutsDialog from './components/GraphShortcutsDialog';
import { useFormatter } from '../i18n';
import { itemFamily } from '../../utils/Colors';
import { createCollapseCache, drawnOneByOne, drawnTypes, isCollapsedMember, isGroupLink, relationshipTotal, withCollapsedGroups } from './utils/graphCollapse';
import { entityTier, hasCycle, layeredLayout, radialLayout, tierLayout } from './utils/graphLayouts';
import useGraphLayoutEngine, { type GraphLayoutRequest } from './utils/useGraphLayoutEngine';
import useGraphKeyboardShortcuts from './utils/useGraphKeyboardShortcuts';
import useGraphFullscreen from './utils/useGraphFullscreen';
import { isPathDrawable, relationshipCounts } from './utils/graphFocus';
import { badgesOfNode, graphNodeActionsFor, useGraphBadgeRegistryVersion, useGraphNodeActionRegistryVersion } from './badges';
import { downloadCanvasAsPng, renderGraphImage } from './utils/graphExport';
import { APP_BASE_PATH, MESSAGING$ } from '../../relay/environment';
import useGraphStartInvestigation from './utils/useGraphStartInvestigation';
import { graphNodeTitle } from './utils/useGraphParser';
import useReaderActed from './utils/useReaderActed';
import useGranted, { KNOWLEDGE_KNFRONTENDEXPORT } from '../../utils/hooks/useGranted';
import {
  AccountTreeOutlined,
  DeselectOutlined,
  HubOutlined,
  LinkOutlined,
  ManageSearchOutlined,
  OpenInNewOutlined,
  PushPinOutlined,
  RouteOutlined,
  TrackChangesOutlined,
  UnfoldMoreOutlined,
  VisibilityOffOutlined,
  VisibilityOutlined,
} from '@mui/icons-material';
import { SelectInverse } from 'mdi-material-ui';
import GraphContextMenu, { type GraphContextMenuSection } from './components/GraphContextMenu';
import type { GraphMenuAction } from './components/GraphToolbarMoreActions';
import useGraphToolbarActions from './components/useGraphToolbarActions';
import useGraphContextMenuGesture, { isAdditiveClick, isMacContextClick } from './utils/useGraphContextMenuGesture';

export interface GraphProps {
  parentRef: MutableRefObject<HTMLDivElement | null>;
  onPositionsChanged?: (positions: OctiGraphPositions) => void;
  children?: ReactNode;
}

/** Delay before a hover card opens, so that sweeping the pointer across the graph opens none. */
const HOVER_OPEN_MS = 280;
/** Grace period to move the pointer from a node onto its card. */
const HOVER_CLOSE_MS = 220;
/** Nodes laid out by the simulation before the first paint, when nothing is placed yet. */
const WARMUP_TICKS = 60;
const MENU_ICON = { fontSize: 'small' } as const;

const endpointId = (end: GraphLink['source']) => (typeof end === 'object' && end !== null ? end.id : end);

const Graph = ({
  parentRef,
  onPositionsChanged,
  children,
}: GraphProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { width, height } = useResizeObserver(parentRef);
  const nodeClicked = useRef<{ node?: GraphNode; time?: number }>({});
  const pointer = useRef({ x: 0, y: 0 });
  const startInvestigation = useGraphStartInvestigation();
  const canExport = useGranted([KNOWLEDGE_KNFRONTENDEXPORT]);

  const {
    saveZoom,
    toggleNode,
    toggleLink,
    clearSelection,
    moveSelection,
    fixPositionsOnDragEnd,
    selectFromFreeRectangle,
    setSelectedNodes,
    setSelectedLinks,
    setIsAddRelationOpen,
    setRawPositions,
    setZoom,
    zoomToFit,
    applyForces,
    setIsExpandOpen,
    initForces,
    selectAllNodes,
    toggleEntityType,
    toggleLegend,
    hideNodes,
    showHiddenNodes,
    resetFilters,
    toggleCollapsedEntityType,
    ungroupAll,
    toggleRelationshipType,
    highlightShortestPath,
    clearHighlightedPath,
    selectNeighbours,
    zoomIn,
    zoomOut,
    zoomToSelection,
    frameNodes,
    locateNode,
    centreRadialLayoutOn,
    isNodeShown,
  } = useGraphInteractions();

  const {
    graphRef2D,
    graphRef3D,
    viewportRef: containerRef,
    toolbarRef,
    graphData,
    context,
    title,
    rawPositions,
    isFullscreen,
    setIsFullscreen,
    stixCoreObjectTypes,
    relationshipTypes,
    graphState: {
      mode3D,
      modeTree,
      selectFree,
      selectFreeRectangle,
      withForces,
      selectedNodes,
      selectedLinks,
      loadingCurrent,
      loadingTotal,
      search,
      detailsPreviewSelected,
      zoom,
      isExpandOpen,
      isAddRelationOpen,
      layoutMode,
      layoutCentreId,
      hiddenNodeIds = [],
      collapsedEntityTypes = [],
      disabledEntityTypes,
      disabledRelationshipTypes = [],
      showLegend = true,
      showTimeRange,
      highlightedPath,
    },
  } = useGraphContext();

  const filterToken = useGraphFilter();

  const isLoadingData = (loadingCurrent ?? 0) < (loadingTotal ?? 0);

  // --- Height of the canvas the toolbar docked under the graph covers, which the legend stays above:
  // some pages let the canvas run under the toolbar, and the time range selector grows it.
  const [toolbarOverlap, setToolbarOverlap] = useState(0);
  useEffect(() => {
    const measure = () => {
      const canvasBox = containerRef.current?.getBoundingClientRect();
      const toolbarBox = toolbarRef.current?.getBoundingClientRect();
      const overlap = canvasBox && toolbarBox ? Math.max(0, Math.round(canvasBox.bottom - toolbarBox.top)) : 0;
      setToolbarOverlap((current) => (current === overlap ? current : overlap));
    };
    measure();
    // The toolbar grows in a short transition when the time range selector opens.
    const settled = setTimeout(measure, 300);
    window.addEventListener('scroll', measure, true);
    window.addEventListener('resize', measure);
    return () => {
      clearTimeout(settled);
      window.removeEventListener('scroll', measure, true);
      window.removeEventListener('resize', measure);
    };
  }, [width, height, showTimeRange, isFullscreen]);

  // --- What is drawn: groups for collapsed types, hidden entities left out.
  const collapseCache = useRef(createCollapseCache());
  const hiddenIds = useMemo(() => new Set(hiddenNodeIds), [hiddenNodeIds]);
  // The hidden entities still in the graph: one removed or gone with a refresh has nothing to show back.
  const hiddenCount = useMemo(
    () => (graphData?.nodes ?? []).filter((node) => hiddenIds.has(node.id)).length,
    [graphData, hiddenIds],
  );
  const displayData = useMemo(() => (graphData
    ? withCollapsedGroups(
        graphData,
        collapsedEntityTypes,
        (entityType, count) => `${count} \u00d7 ${t_i18n(`entity_${entityType}`)}`,
        collapseCache.current,
        hiddenIds,
      )
    : graphData), [graphData, collapsedEntityTypes, filterToken, hiddenIds]);
  const nodeShown = (node: GraphNode) => !hiddenIds.has(node.id) && !isCollapsedMember(node, collapsedEntityTypes);
  const shownNodes = useMemo(() => (displayData?.nodes ?? []).filter(nodeShown), [displayData, hiddenIds, collapsedEntityTypes]);
  const shownNodeIds = useMemo(() => new Set(shownNodes.map((n) => n.id)), [shownNodes]);
  const linkShown = (link: GraphLink) => shownNodeIds.has(endpointId(link.source) ?? link.source_id)
    && shownNodeIds.has(endpointId(link.target) ?? link.target_id);
  const shownLinks = useMemo(() => (displayData?.links ?? []).filter(linkShown), [displayData, shownNodeIds]);
  // Only what is drawn is simulated: hidden entities and the members of collapsed groups exert no
  // force, and their positions stay on their objects for when they are drawn again.
  const drawnData = useMemo(() => ({ nodes: shownNodes, links: shownLinks }), [shownNodes, shownLinks]);
  // The 3D view lays a tree out with the DAG mode of its engine, which cannot place a cycle; the 2D layouts break cycles.
  const drawnHasCycle = useMemo(() => hasCycle(
    shownNodes.map((node) => node.id),
    shownLinks.map((link) => ({ id: link.id, sourceId: endpointId(link.source) ?? link.source_id, targetId: endpointId(link.target) ?? link.target_id })),
  ), [shownNodes, shownLinks]);

  // --- Nothing drawn: no data yet, everything hidden, or everything filtered out. Shown after a
  // short delay so that a graph still receiving its data never flashes it.
  const emptyKind = useMemo<GraphEmptyKind | null>(() => {
    if (!displayData || isLoadingData) return null;
    if (displayData.nodes.length === 0) return 'empty';
    if (shownNodes.length === 0) return 'hidden';
    if (shownNodes.every((node) => node.disabled)) return 'filtered';
    return null;
  }, [displayData, shownNodes, isLoadingData, filterToken]);
  const [shownEmptyKind, setShownEmptyKind] = useState<GraphEmptyKind | null>(null);
  useEffect(() => {
    if (!emptyKind) {
      setShownEmptyKind(null);
      return undefined;
    }
    const timer = setTimeout(() => setShownEmptyKind(emptyKind), 600);
    return () => clearTimeout(timer);
  }, [emptyKind]);
  const shapeSignature = useMemo(
    () => `${shownNodes.map((n) => n.id).sort().join()}|${shownLinks.map((l) => l.id).sort().join()}`,
    [shownNodes, shownLinks],
  );
  // A highlighted path that a filter, a hidden or collapsed entity or new data broke is dropped.
  const drawablePath = useMemo(() => {
    if (!highlightedPath) return null;
    const shownEnds = shownLinks.map((link) => ({
      id: link.id,
      sourceId: endpointId(link.source) ?? link.source_id,
      targetId: endpointId(link.target) ?? link.target_id,
      disabled: link.disabled,
    }));
    return isPathDrawable(highlightedPath, shownNodes, shownEnds) ? highlightedPath : null;
  }, [highlightedPath, shownNodes, shownLinks, filterToken]);
  useEffect(() => {
    if (highlightedPath && !drawablePath) clearHighlightedPath();
  }, [highlightedPath, drawablePath]);

  // --- Badges drawn in the graph, for the legend: one entry per badge with the entities carrying it,
  // and the entities whose badges call for attention (a warning or an error), for the counter row.
  const badgeRegistryVersion = useGraphBadgeRegistryVersion();
  const { legendBadges, attentionIds } = useMemo(() => {
    const entries = new Map<string, GraphLegendBadge & { nodeIds: Set<string> }>();
    const attention = new Set<string>();
    shownNodes.forEach((node) => {
      if (node.groupOf || node.disabled) return;
      badgesOfNode(node, { t_i18n }).forEach((badge) => {
        const entry = entries.get(badge.key)
          ?? { key: badge.key, label: badge.legendLabel ?? badge.label, tone: badge.tone, tooltip: badge.tooltip, count: 0, nodeIds: new Set<string>() };
        entry.count += 1;
        entry.nodeIds.add(node.id);
        entries.set(badge.key, entry);
        if (badge.tone === 'warning' || badge.tone === 'error') attention.add(node.id);
      });
    });
    return { legendBadges: [...entries.values()], attentionIds: attention };
  }, [shownNodes, badgeRegistryVersion, filterToken]);

  // --- Hover: focus on the canvas at once, card after a short delay.
  const [hovered, setHovered] = useState<GraphHoverTarget | null>(null);
  const [card, setCard] = useState<{ target: GraphHoverTarget; anchor: { x: number; y: number } } | null>(null);
  const [menu, setMenu] = useState<{ anchor: { x: number; y: number }; target: GraphHoverTarget | null } | null>(null);
  const openTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const closeTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const cancelClose = () => clearTimeout(closeTimer.current);
  const scheduleClose = () => {
    clearTimeout(closeTimer.current);
    closeTimer.current = setTimeout(() => setCard(null), HOVER_CLOSE_MS);
  };
  // No card opens while a button is held on the canvas: a drag (moving a node, drawing a
  // relationship with the right button) is under way and the card would cover its target.
  // A gesture taken over by the browser (touch scrolling) ends with pointercancel, without pointerup.
  const pressing = useRef(false);
  useEffect(() => {
    const release = () => {
      pressing.current = false;
    };
    window.addEventListener('pointerup', release, true);
    window.addEventListener('pointercancel', release, true);
    return () => {
      window.removeEventListener('pointerup', release, true);
      window.removeEventListener('pointercancel', release, true);
    };
  }, []);
  const onCanvasPointerDown = (event: React.PointerEvent) => {
    if (!(event.target instanceof HTMLCanvasElement)) return;
    pressing.current = true;
    clearTimeout(openTimer.current);
    setCard(null);
  };
  const onHover = (target: GraphHoverTarget | null) => {
    setHovered(target);
    clearTimeout(openTimer.current);
    if (!target || pressing.current || menu || selectFree || selectFreeRectangle || isExpandOpen || isAddRelationOpen) {
      scheduleClose();
      return;
    }
    cancelClose();
    openTimer.current = setTimeout(() => setCard({ target, anchor: { ...pointer.current } }), HOVER_OPEN_MS);
  };
  // A dialog opened from the graph takes over: no card lingers or opens behind it.
  useEffect(() => {
    if (!isExpandOpen && !isAddRelationOpen) return;
    clearTimeout(openTimer.current);
    clearTimeout(closeTimer.current);
    setCard(null);
  }, [isExpandOpen, isAddRelationOpen]);
  useEffect(() => () => {
    clearTimeout(openTimer.current);
    clearTimeout(closeTimer.current);
  }, []);

  // --- Deterministic layouts (2D): tree modes by relationship direction, tiers, radial.
  const layoutEnds = () => shownLinks.map((link) => ({
    id: link.id,
    sourceId: endpointId(link.source) ?? link.source_id,
    targetId: endpointId(link.target) ?? link.target_id,
  }));
  let layout: GraphLayoutRequest | null = null;
  if (modeTree) {
    layout = { key: `tree-${modeTree}`, compute: () => layeredLayout(shownNodes, layoutEnds(), modeTree) };
  } else if (layoutMode === 'tiers') {
    layout = { key: 'tiers', compute: () => tierLayout(shownNodes, layoutEnds(), (node) => entityTier(itemFamily(node.entity_type))) };
  } else if (layoutMode === 'radial') {
    layout = { key: `radial-${layoutCentreId ?? ''}`, compute: () => radialLayout(shownNodes, layoutEnds(), layoutCentreId ?? null) };
  }
  const { animating, targets: layoutTargets } = useGraphLayoutEngine({
    graphRef: graphRef2D,
    nodes: shownNodes,
    shapeSignature,
    layout,
    enabled: !mode3D && !isLoadingData && shownNodes.length > 0,
    released: mode3D,
    savedPositions: rawPositions,
    frameView: (padding, duration) => frameNodes(padding, duration),
  });

  const {
    palette,
    nodePaint,
    nodePointerAreaPaint,
    nodeThreeColor,
    nodeThreePaint,
    linkColorPaint,
    linkBaseColor,
    linkPaint,
    linkPointerAreaPaint,
    linkCurvature,
    curvatureOf,
    framePrePaint,
    framePostPaint,
    linkThreePaint,
    linkThreeLabelPosition,
  } = useGraphPainter({
    selectedLinks,
    selectedNodes,
    search,
    detailsPreviewSelected,
    links: shownLinks,
    hovered,
    highlightedPath: drawablePath,
    nodeCount: shownNodes.length,
    layoutTargets: mode3D ? null : layoutTargets,
  });

  // A graph opened without a saved view is framed once more when its first layout settles: the
  // forces keep moving the nodes after the first framing. Anything the reader does meanwhile (a
  // click, a key, a zoom, in the graph or in its toolbar) cancels it, so the view never moves
  // under the pointer.
  const frameWhenSettled = useRef(false);
  const readerActed = useReaderActed(mode3D, () => {
    frameWhenSettled.current = false;
  });
  const onEngineStop = () => {
    if (!frameWhenSettled.current) return;
    frameWhenSettled.current = false;
    zoomToFit();
  };

  // An investigation receives its first objects after it opens, outside any loading progress: they are framed too.
  const hasNodes = (graphData?.nodes.length ?? 0) > 0;
  useEffect(() => {
    let framing: ReturnType<typeof setTimeout> | undefined;
    // A short timeout to be sure graph is ready.
    const init = setTimeout(() => {
      if (isLoadingData) return;
      initForces();
      if (withForces) applyForces();

      // Another short timeout to wait forces to be applied
      framing = setTimeout(() => {
        if (readerActed.current) return;
        if (zoom) setZoom(zoom);
        else {
          zoomToFit();
          frameWhenSettled.current = withForces;
        }
      }, 1000);
    }, 100);
    return () => {
      clearTimeout(init);
      clearTimeout(framing);
      frameWhenSettled.current = false;
    };
  }, [mode3D, isLoadingData, hasNodes]);

  const selectedEntities = [...selectedLinks, ...selectedNodes];
  const selectedKeys = useMemo(() => new Set([
    ...selectedNodes.map((node) => graphElementKey({ kind: 'node', node })),
    ...selectedLinks.map((link) => graphElementKey({ kind: 'link', link })),
  ]), [selectedLinks, selectedNodes]);
  const hasNoSavedPosition = Object.keys(rawPositions).length === 0;

  const persistPositions = () => {
    const newPositions = (graphData?.nodes ?? []).reduce((acc, { id, x, y }) => ({
      ...acc,
      [id]: { id, x, y },
    }), {});
    setRawPositions(newPositions);
    onPositionsChanged?.(newPositions);
  };

  const onNodeDragEnd = (node: GraphNode) => {
    fixPositionsOnDragEnd(node);
    persistPositions();
  };

  const onNodeClick: LibGraphProps['onNodeClick'] = (node, e) => {
    // The macOS Control click opens the context menu (see the context-menu gesture), it selects nothing.
    if (isMacContextClick(e)) return;
    if (node.groupOf) {
      toggleCollapsedEntityType(node.groupOf.entityType);
      return;
    }
    let isDoubleClick = false;
    const now = new Date().getTime();
    if (!isAdditiveClick(e) && !e.ctrlKey) {
      if (nodeClicked.current.time && nodeClicked.current.node?.id === node.id) {
        isDoubleClick = now - nodeClicked.current.time < 500;
      }
      nodeClicked.current = isDoubleClick ? {} : { node, time: now };
      if (isDoubleClick && context === 'investigation') {
        setIsExpandOpen(true);
        return;
      }
    }
    toggleNode(node, e);
  };

  const onBackgroundClick = () => {
    setCard(null);
    clearSelection();
  };

  // --- Actions of the controls, the hover card and the keyboard.
  const { toggle: toggleFullscreen, exit: exitFullscreen } = useGraphFullscreen(
    parentRef,
    isFullscreen,
    setIsFullscreen,
    palette.background,
  );

  const selectNodes = (nodes: GraphNode[]) => {
    setSelectedLinks([]);
    setSelectedNodes(nodes);
  };
  const selectBadgeCarriers = (key: string) => {
    const carriers = legendBadges.find((entry) => entry.key === key)?.nodeIds;
    if (carriers) selectNodes(shownNodes.filter((node) => carriers.has(node.id)));
  };

  // --- Counter row: the entities and the relationships drawn one by one, the restricted entities
  // and those needing attention, each selecting exactly what it counts. Members of collapsed groups
  // and the links drawn towards their group are counted by the legend, where the group is expanded.
  // While something is selected, the first two read what the selection holds of them and frame it.
  const counters = useMemo<GraphCounter[]>(() => {
    const { entities: entityNodes, relationshipLinks, relationshipNodes } = drawnOneByOne(shownNodes, shownLinks);
    const entityCount = entityNodes.length;
    const relationshipCount = relationshipLinks.length + relationshipNodes.length;
    const restrictedNodes = entityNodes.filter((node) => node.isRestricted);
    const attentionNodes = entityNodes.filter((node) => attentionIds.has(node.id));
    const selection = drawnOneByOne(selectedNodes, selectedLinks);
    const selectedEntityCount = selection.entities.length;
    const selectedRelationshipCount = selection.relationshipLinks.length + selection.relationshipNodes.length;
    const totals: (GraphCounter & { count: number })[] = selectedEntityCount + selectedRelationshipCount > 0 ? [
      {
        key: 'selection',
        count: selectedEntityCount + selectedRelationshipCount,
        label: t_i18n(
          '{selectedEntities} of {entities, plural, one {# entity} other {# entities}} · {selectedRelationships} of {relationships, plural, one {# relationship} other {# relationships}} selected',
          { values: { selectedEntities: selectedEntityCount, entities: entityCount, selectedRelationships: selectedRelationshipCount, relationships: relationshipCount } },
        ),
        action: t_i18n('Fit the selection'),
        onSelect: () => zoomToSelection(),
      },
    ] : [
      {
        key: 'entities',
        count: entityCount,
        label: t_i18n('{count, plural, one {# entity} other {# entities}}', { values: { count: entityCount } }),
        action: t_i18n('Select the entities'),
        onSelect: () => selectNodes(entityNodes),
      },
      {
        key: 'relationships',
        count: relationshipCount,
        label: t_i18n('{count, plural, one {# relationship} other {# relationships}}', { values: { count: relationshipCount } }),
        action: t_i18n('Select the relationships'),
        onSelect: () => {
          setSelectedNodes(relationshipNodes);
          setSelectedLinks(relationshipLinks);
        },
      },
    ];
    const path: (GraphCounter & { count: number })[] = drawablePath?.hops ? [{
      key: 'path',
      count: drawablePath.count ?? 1,
      label: t_i18n(
        '{count, plural, one {# shortest path} other {# shortest paths}} · {hops, plural, one {# hop} other {# hops}}',
        { values: { count: drawablePath.count ?? 1, hops: drawablePath.hops } },
      ),
      action: t_i18n('Fit the highlighted paths'),
      onSelect: () => zoomToSelection(drawablePath.nodeIds),
    }] : [];
    const all: (GraphCounter & { count: number })[] = [
      ...totals,
      ...path,
      {
        key: 'restricted',
        count: restrictedNodes.length,
        label: t_i18n('{count, plural, one {# restricted} other {# restricted}}', { values: { count: restrictedNodes.length } }),
        action: t_i18n('Select the entities you do not have access to'),
        tone: 'neutral',
        onSelect: () => selectNodes(restrictedNodes),
      },
      {
        key: 'attention',
        count: attentionNodes.length,
        label: t_i18n('{count, plural, one {# needs attention} other {# need attention}}', { values: { count: attentionNodes.length } }),
        action: t_i18n('Select the entities with a warning or an error badge'),
        tone: 'warning',
        onSelect: () => selectNodes(attentionNodes),
      },
    ];
    return all.filter(({ key, count }) => key === 'entities' || count > 0);
  }, [shownNodes, shownLinks, selectedNodes, selectedLinks, drawablePath, attentionIds, filterToken]);
  const otherSelected = (node: GraphNode) => (selectedNodes.length === 1 && selectedNodes[0].id !== node.id ? selectedNodes[0] : null);
  const groupMembersOf = (group: GraphNode) => {
    const memberIds = new Set(group.groupOf?.memberIds ?? []);
    return (graphData?.nodes ?? [])
      .filter((node) => memberIds.has(node.id))
      .map((node) => ({ id: node.id, name: graphNodeTitle(node) }))
      .sort((a, b) => a.name.localeCompare(b.name));
  };

  const togglePin = (node: GraphNode) => {
    if (node.fx !== undefined && node.fx !== null) {
      node.fx = undefined;
      node.fy = undefined;
      graphRef2D.current?.d3ReheatSimulation();
    } else {
      node.fx = node.x;
      node.fy = node.y;
    }
    persistPositions();
    setCard((current) => (current ? { ...current } : current));
  };

  const exportImage = async () => {
    // The page title names what the graph shows (container, investigation, entity) when the
    // surface does not give a title of its own.
    const imageTitle = title || document.title || t_i18n('Graph');
    const families = new Map<string, { label: string; color: string; count: number }>();
    shownNodes.forEach((node) => {
      const type = node.groupOf?.entityType ?? node.entity_type;
      if (node.relationship_type) return;
      const entry = families.get(type) ?? { label: t_i18n(`entity_${type}`), color: node.color, count: 0 };
      entry.count += node.groupOf ? node.groupOf.memberIds.length : 1;
      families.set(type, entry);
    });
    const relationshipCount = relationshipTotal(shownNodes, shownLinks);
    const canvas = renderGraphImage({
      nodes: shownNodes,
      links: shownLinks,
      palette,
      curvatureOf,
      title: imageTitle,
      // The totals of the legend: members of collapsed groups included, nested relationships counted
      // as relationships.
      subtitle: `${t_i18n('{count, plural, one {# entity} other {# entities}}', { values: { count: [...families.values()].reduce((sum, family) => sum + family.count, 0) } })}, ${t_i18n('{count, plural, one {# relationship} other {# relationships}}', { values: { count: relationshipCount } })}`,
      typeLabel: (node) => (node.relationship_type ? t_i18n(`relationship_${node.relationship_type}`) : t_i18n(`entity_${node.entity_type}`)),
      badgesOf: (node) => badgesOfNode(node, { t_i18n }),
      linkColor: linkBaseColor,
      legend: {
        title: t_i18n('Legend'),
        entities: [...families.values()].sort((a, b) => b.count - a.count),
        lineStyles: [
          { label: t_i18n('Asserted relationship'), kind: 'asserted' },
          { label: t_i18n('Inferred relationship'), kind: 'inferred' },
          { label: t_i18n('Low confidence'), kind: 'lowConfidence' },
        ],
      },
      showConnectedCount: context === 'investigation',
    });
    if (!canvas) {
      MESSAGING$.notifyError(t_i18n('There is nothing to export in this graph'));
      return;
    }
    try {
      const fileName = `${imageTitle.replace(/[\\/:*?"<>|]+/g, '-').slice(0, 120)} - ${new Date().toISOString().slice(0, 10)}`;
      await downloadCanvasAsPng(canvas, fileName);
    } catch {
      MESSAGING$.notifyError(t_i18n('The graph image could not be generated'));
    }
  };

  const shortestPathOfSelection = () => {
    if (selectedNodes.length !== 2) {
      MESSAGING$.notifyError(t_i18n('Select exactly two nodes to highlight the shortest path between them'));
      return;
    }
    if (!highlightShortestPath()) {
      MESSAGING$.notifyError(t_i18n('These two nodes are not connected in this graph'));
    }
  };

  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  // Set once the context menu is built, further down.
  const keyboardMenu = useRef<() => void>(() => {});
  // The shortcuts of the actions the toolbar disables in 3D do nothing there either.
  const only2D = (action: () => void) => () => {
    if (!mode3D) action();
  };
  useGraphKeyboardShortcuts(containerRef, {
    fit: zoomToFit,
    fitSelection: () => zoomToSelection(),
    locate: only2D(() => locateNode()),
    zoomIn: only2D(zoomIn),
    zoomOut: only2D(zoomOut),
    selectAll: selectAllNodes,
    // Same rules as the toolbar actions: neighbours of selected entities only, and the path toggles off
    selectNeighbours: () => {
      if (selectedNodes.length > 0) selectNeighbours();
    },
    shortestPath: only2D(() => {
      if (highlightedPath) clearHighlightedPath();
      else shortestPathOfSelection();
    }),
    hideSelection: () => hideNodes(selectedNodes.map((n) => n.id)),
    showHidden: showHiddenNodes,
    clearSelection: () => {
      if (selectedEntities.length === 0 && isFullscreen) exitFullscreen();
      else onBackgroundClick();
    },
    toggleLegend: only2D(toggleLegend),
    toggleFullscreen,
    exportImage: only2D(() => {
      if (canExport) exportImage();
    }),
    focusSearch: () => {
      parentRef.current?.querySelector<HTMLInputElement>('[data-graph-search] input')?.focus();
    },
    showShortcuts: () => setShortcutsOpen(true),
    openContextMenu: only2D(() => keyboardMenu.current()),
  });

  // --- What the toolbar rendered inside the graph takes from it. The type filter offers and counts
  // the types drawn, as the legend lists them: a type whose only entities are hidden leaves both.
  const typeInventory = useMemo(
    () => drawnTypes(shownNodes, shownLinks, stixCoreObjectTypes, relationshipTypes),
    [shownNodes, shownLinks, stixCoreObjectTypes, relationshipTypes],
  );
  const typeFilterCount = disabledEntityTypes.filter((type) => typeInventory.entityTypes.includes(type)).length
    + disabledRelationshipTypes.filter((type) => typeInventory.relationshipTypes.includes(type)).length;
  const latestViewActions = useRef({ exportImage, toggleFullscreen });
  latestViewActions.current = { exportImage, toggleFullscreen };
  const viewActions = useMemo<GraphViewActions>(() => ({
    counters,
    drawnTypes: typeInventory,
    typeFilterCount,
    drawnHasCycle,
    exportImage: canExport ? () => {
      latestViewActions.current.exportImage();
    } : undefined,
    toggleFullscreen: () => latestViewActions.current.toggleFullscreen(),
    showShortcuts: () => setShortcutsOpen(true),
  }), [counters, typeInventory, typeFilterCount, drawnHasCycle, canExport]);

  const cardTarget: GraphHoverCardTarget | null = useMemo(() => {
    if (!card) return null;
    if (card.target.kind === 'node') {
      const node = (displayData?.nodes ?? []).find((n) => n.id === card.target.id);
      return node && nodeShown(node) ? { kind: 'node', node } : null;
    }
    const link = (displayData?.links ?? []).find((l) => isHoveredLink(card.target, linkHoverTarget(l)));
    return link && linkShown(link) ? { kind: 'link', link } : null;
  }, [card, displayData, shownNodeIds]);

  const canRelate = context !== 'analyses' && context !== 'correlation';

  // --- Context menu: what applies to the entity, group or relationship under the pointer, to the
  // selection it belongs to, or to the graph itself on the empty canvas. The hover card only previews.
  // An action registered, replaced or removed while the graph is open is in its next menu.
  useGraphNodeActionRegistryVersion();
  const toolbarActions = useGraphToolbarActions({ onUnfixNodes: () => onPositionsChanged?.({}) });
  const toolbarAction = (id: string) => toolbarActions.find((action) => action.id === id);
  const present = (actions: (GraphMenuAction | false | null | undefined)[]) => actions.filter((action): action is GraphMenuAction => !!action);
  const menuReturnFocus = useRef<HTMLElement | null>(null);
  const openMenuAt = (anchor: { x: number; y: number }, target: GraphHoverTarget | null) => {
    clearTimeout(openTimer.current);
    setCard(null);
    menuReturnFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setMenu({ anchor, target });
  };
  useGraphContextMenuGesture(containerRef, !mode3D, ({ clientX, clientY }) => {
    const box = containerRef.current?.getBoundingClientRect();
    if (box) openMenuAt({ x: clientX - box.left, y: clientY - box.top }, hovered);
  });
  // From the keyboard: the element active in the keyboard list, else the only selected entity, else the graph.
  const openKeyboardMenu = () => {
    const single = selectedNodes.length === 1 && selectedLinks.length === 0 ? selectedNodes[0] : null;
    const target: GraphHoverTarget | null = hovered ?? (single ? { kind: 'node', id: single.id } : null);
    const node = target?.kind === 'node' ? shownNodes.find((n) => n.id === target.id) : undefined;
    const at = node && Number.isFinite(node.x) ? graphRef2D.current?.graph2ScreenCoords(node.x, node.y) : undefined;
    openMenuAt(at ?? { x: width / 2, y: height / 3 }, target);
  };
  keyboardMenu.current = openKeyboardMenu;
  const openInNewTab = (id: string) => window.open(`${APP_BASE_PATH}/dashboard/id/${id}`, '_blank', 'noopener,noreferrer');
  const selectedEntityNodes = selectedNodes.filter((n) => !n.relationship_type && !n.groupOf);
  const investigateFrom = (node: GraphNode) => {
    if (!startInvestigation) return;
    const seeds = selectedEntityNodes.some((n) => n.id === node.id) ? selectedEntityNodes : [node];
    startInvestigation(graphNodeTitle(node), seeds.map((n) => n.id));
  };
  const nodeMenuActions = (node: GraphNode): GraphMenuAction[] => {
    const isPinned = node.fx !== undefined && node.fx !== null;
    const pin: GraphMenuAction = { id: 'pin', label: isPinned ? t_i18n('Unpin') : t_i18n('Pin in place'), icon: <PushPinOutlined {...MENU_ICON} />, onSelect: () => togglePin(node) };
    if (node.groupOf) {
      const { entityType } = node.groupOf;
      return [{ id: 'ungroup', label: t_i18n('Ungroup'), icon: <UnfoldMoreOutlined {...MENU_ICON} />, onSelect: () => toggleCollapsedEntityType(entityType) }, pin];
    }
    const other = otherSelected(node);
    return present([
      !node.relationship_type && { id: 'open', label: t_i18n('Open in a new tab'), icon: <OpenInNewOutlined {...MENU_ICON} />, onSelect: () => openInNewTab(node.id) },
      context === 'investigation' && {
        id: 'expand',
        label: t_i18n('Expand this entity'),
        icon: <AccountTreeOutlined {...MENU_ICON} />,
        onSelect: () => {
          selectNodes([node]);
          setIsExpandOpen(true);
        },
      },
      { id: 'select-entity-neighbours', label: t_i18n('Select entity and neighbours'), icon: <HubOutlined {...MENU_ICON} />, onSelect: () => selectNeighbours([node.id]) },
      pin,
      { id: 'hide', label: t_i18n('Hide'), icon: <VisibilityOffOutlined {...MENU_ICON} />, onSelect: () => hideNodes([node.id]) },
      { id: 'radial', label: t_i18n('Lay out the graph around it'), icon: <TrackChangesOutlined {...MENU_ICON} />, onSelect: () => centreRadialLayoutOn(node.id) },
      other && {
        id: 'path-from-selection',
        label: t_i18n('Highlight shortest path from the selection'),
        icon: <RouteOutlined {...MENU_ICON} />,
        onSelect: () => {
          selectNodes([other, node]);
          if (!highlightShortestPath(other.id, node.id)) MESSAGING$.notifyError(t_i18n('These two nodes are not connected in this graph'));
        },
      },
      canRelate && other && {
        id: 'relate-to-selection',
        label: t_i18n('Create a relationship from the selection'),
        icon: <LinkOutlined {...MENU_ICON} />,
        onSelect: () => {
          selectNodes([other, node]);
          setIsAddRelationOpen(true);
        },
      },
      !!startInvestigation && context !== 'investigation' && !node.relationship_type && {
        id: 'start-investigation',
        label: t_i18n('Start an investigation'),
        icon: <ManageSearchOutlined {...MENU_ICON} />,
        onSelect: () => investigateFrom(node),
      },
      ...graphNodeActionsFor(node, context).map((action): GraphMenuAction => {
        const Icon = action.icon;
        return {
          id: `registered-${action.id}`,
          label: action.label(t_i18n),
          icon: <Icon {...MENU_ICON} />,
          options: action.options?.(node, t_i18n),
          onSelect: () => {
            if (action.href) window.open(`${APP_BASE_PATH}${action.href(node)}`, '_blank', 'noopener,noreferrer');
            else action.onSelect?.(node);
          },
        };
      }),
    ]);
  };
  const linkMenuActions = (link: GraphLink): GraphMenuAction[] => present([
    link.entity_type !== 'basic-relationship' && !!link.label && {
      id: 'open',
      label: t_i18n('Open in a new tab'),
      icon: <OpenInNewOutlined {...MENU_ICON} />,
      onSelect: () => openInNewTab(link.id),
    },
    {
      id: 'select-link',
      label: t_i18n('Select this relationship'),
      icon: <LinkOutlined {...MENU_ICON} />,
      onSelect: () => {
        setSelectedNodes([]);
        setSelectedLinks([link]);
      },
    },
  ]);
  const selectionMenuActions = (): GraphMenuAction[] => present([
    toolbarAction('select-neighbours'),
    toolbarAction('shortest-path'),
    toolbarAction('select-relationships'),
    toolbarAction('fit-selection'),
    selectedNodes.length > 0 && {
      id: 'hide-selection',
      label: t_i18n('Hide'),
      shortcut: 'H',
      icon: <VisibilityOffOutlined {...MENU_ICON} />,
      onSelect: () => hideNodes(selectedNodes.map((n) => n.id)),
    },
    canRelate && selectedEntityNodes.length === 2 && {
      id: 'relate-selection',
      label: t_i18n('Create a relationship'),
      icon: <LinkOutlined {...MENU_ICON} />,
      onSelect: () => setIsAddRelationOpen(true),
    },
    !!startInvestigation && context !== 'investigation' && selectedEntityNodes.length > 0 && {
      id: 'start-investigation-selection',
      label: t_i18n('Start an investigation'),
      icon: <ManageSearchOutlined {...MENU_ICON} />,
      onSelect: () => investigateFrom(selectedEntityNodes[0]),
    },
  ]);
  const canvasMenuActions = (): GraphMenuAction[] => {
    const selectedIds = new Set(selectedNodes.map((n) => n.id));
    return present([
      toolbarAction('select-all'),
      toolbarAction('select-by-type'),
      {
        id: 'invert-selection',
        label: t_i18n('Invert selection'),
        icon: <SelectInverse {...MENU_ICON} />,
        onSelect: () => selectNodes(drawnOneByOne(shownNodes, []).entities.filter((n) => !selectedIds.has(n.id))),
      },
      {
        id: 'clear-selection',
        label: t_i18n('Clear selection'),
        shortcut: 'Esc',
        icon: <DeselectOutlined {...MENU_ICON} />,
        disabledReason: selectedEntities.length === 0 ? t_i18n('Nothing is selected') : undefined,
        onSelect: clearSelection,
      },
      {
        id: 'show-hidden',
        label: t_i18n('Show the hidden entities'),
        shortcut: 'Shift+H',
        icon: <VisibilityOutlined {...MENU_ICON} />,
        disabledReason: hiddenCount === 0 ? t_i18n('No entity is hidden') : undefined,
        onSelect: showHiddenNodes,
      },
      {
        id: 'ungroup-all',
        label: t_i18n('Ungroup all'),
        icon: <UnfoldMoreOutlined {...MENU_ICON} />,
        disabledReason: collapsedEntityTypes.length === 0 ? t_i18n('No entity type is grouped') : undefined,
        onSelect: ungroupAll,
      },
      toolbarAction('reset-layout'),
    ]);
  };
  const menuSections = (target: GraphHoverTarget | null): GraphContextMenuSection[] => {
    const selection = selectedEntities.length > 0 ? [{ key: 'selection', label: t_i18n('Selection'), actions: selectionMenuActions() }] : [];
    if (target?.kind === 'node') {
      const node = shownNodes.find((n) => n.id === target.id);
      if (node) {
        const own = { key: 'node', label: node.groupOf ? node.label : graphNodeTitle(node), actions: nodeMenuActions(node) };
        // On an entity of a larger selection, the selection comes first.
        const inSelection = selectedNodes.length > 1 && selectedNodes.some((n) => n.id === node.id);
        return inSelection ? [...selection, own] : [own];
      }
    }
    if (target?.kind === 'link') {
      const link = shownLinks.find((l) => isHoveredLink(target, linkHoverTarget(l)));
      if (link && !isGroupLink(link)) {
        return [{ key: 'link', label: t_i18n(`relationship_${link.relationship_type || link.entity_type}`), actions: linkMenuActions(link) }];
      }
    }
    return [...selection, { key: 'graph', label: t_i18n('Graph'), actions: canvasMenuActions() }];
  };

  return (
    <RectangleSelection
      disabled={!selectFreeRectangle}
      onSelection={selectFromFreeRectangle}
    >
      <div
        ref={containerRef}
        style={{ position: 'relative' }}
        onMouseMove={(event) => {
          const box = event.currentTarget.getBoundingClientRect();
          pointer.current = { x: event.clientX - box.left, y: event.clientY - box.top };
        }}
        // The canvas reports no hover change when the pointer leaves it fast, for the toolbar for example.
        onMouseLeave={() => onHover(null)}
        onPointerDownCapture={onCanvasPointerDown}
      >
        <GraphLoadingAlert />
        {selectedEntities.length > 0 && <EntitiesDetailsRightsBar />}
        {mode3D ? (
          <ForceGraph3D<GraphNode, GraphLink>
            ref={graphRef3D}
            width={width}
            height={height}
            backgroundColor={theme.palette.background.default}
            graphData={drawnData}
            dagMode={modeTree && !drawnHasCycle ? modeTree : undefined}
            // A cycle is laid out as it is, its links not forced along the tree, instead of breaking the graph.
            onDagError={() => {}}
            cooldownTicks={(!withForces || isLoadingData) ? 0 : 100}
            linkDirectionalArrowLength={3}
            linkDirectionalArrowRelPos={0.99}
            linkWidth={0.5}
            linkOpacity={0.8}
            linkThreeObjectExtend
            linkThreeObject={linkThreePaint}
            linkPositionUpdate={linkThreeLabelPosition}
            linkColor={linkColorPaint}
            nodeColor={nodeThreeColor}
            nodeOpacity={0.8}
            nodeThreeObjectExtend
            nodeThreeObject={nodeThreePaint}
            onLinkClick={toggleLink}
            onBackgroundClick={onBackgroundClick}
            onNodeClick={onNodeClick}
            onNodeDrag={moveSelection}
            onNodeDragEnd={onNodeDragEnd}
            onEngineStop={onEngineStop}
          />
        ) : (
          <>
            <LassoSelection
              width={width}
              height={height}
              activated={selectFree}
              graphDataNodes={(graphData?.nodes ?? []).filter(isNodeShown)}
              graph={graphRef2D}
              setSelectedNodes={(nodes) => setSelectedNodes(Array.from(nodes))}
            />
            <RelationSelection
              width={width}
              height={height}
              activated={!selectFree && !selectFreeRectangle}
              graphDataNodes={(graphData?.nodes ?? []).filter(isNodeShown)}
              graph={graphRef2D}
              setSelectedNodes={(nodes) => {
                setSelectedNodes(Array.from(nodes));
                setIsAddRelationOpen(true);
              }}
            />

            <ForceGraph2D<GraphNode, GraphLink>
              ref={graphRef2D}
              width={width}
              height={height}
              graphData={drawnData}
              nodeRelSize={4}
              maxZoom={24}
              warmupTicks={hasNoSavedPosition ? WARMUP_TICKS : 0}
              cooldownTicks={(!withForces || isLoadingData) ? 0 : 100}
              autoPauseRedraw={!animating}
              enablePanInteraction={!selectFree && !selectFreeRectangle}
              nodeLabel={() => ''}
              linkLabel={() => ''}
              linkCurvature={linkCurvature}
              linkWidth={2}
              linkDirectionalArrowLength={0}
              linkCanvasObjectMode={() => 'replace'}
              linkCanvasObject={(link, ctx, globalScale) => linkPaint(link, ctx, globalScale)}
              linkPointerAreaPaint={(link, color, ctx, globalScale) => linkPointerAreaPaint(link, color, ctx, globalScale)}
              linkColor={linkColorPaint}
              nodePointerAreaPaint={(node, color, ctx, globalScale) => nodePointerAreaPaint(node, color, ctx, globalScale)}
              nodeCanvasObject={(node, ctx, globalScale) => nodePaint(node, ctx, globalScale, context === 'investigation')}
              onRenderFramePre={framePrePaint}
              onRenderFramePost={framePostPaint}
              onEngineStop={onEngineStop}
              onNodeHover={(node) => onHover(node ? { kind: 'node', id: node.id } : null)}
              onLinkHover={(link) => onHover(link ? linkHoverTarget(link) : null)}
              onZoomEnd={saveZoom}
              onLinkClick={(link, event) => {
                if (!isMacContextClick(event)) toggleLink(link, event);
              }}
              onBackgroundClick={(event) => {
                if (!isMacContextClick(event)) onBackgroundClick();
              }}
              onNodeClick={onNodeClick}
              onNodeDrag={(node, translate) => {
                setCard(null);
                moveSelection(node, translate);
              }}
              onNodeDragEnd={onNodeDragEnd}
            />
          </>
        )}
        {shownEmptyKind && (
          <GraphEmptyState kind={shownEmptyKind} context={context} onClearFilters={resetFilters} onShowHidden={showHiddenNodes} />
        )}
        {!mode3D && shownNodes.length > 0 && (showLegend ? (
          <GraphLegend
            nodes={shownNodes}
            links={shownLinks}
            disabledEntityTypes={disabledEntityTypes}
            disabledRelationshipTypes={disabledRelationshipTypes}
            collapsedEntityTypes={collapsedEntityTypes}
            hiddenCount={hiddenCount}
            badges={legendBadges}
            bottomOffset={toolbarOverlap}
            onToggleEntityType={toggleEntityType}
            onToggleRelationshipType={toggleRelationshipType}
            onToggleCollapsed={toggleCollapsedEntityType}
            onShowHidden={showHiddenNodes}
            onSelectBadge={selectBadgeCarriers}
            onMinimize={toggleLegend}
          />
        ) : (
          <GraphLegendPill filterCount={typeFilterCount} bottomOffset={toolbarOverlap} onOpen={toggleLegend} />
        ))}
        {!mode3D && card && cardTarget && (
          <GraphHoverCard
            target={cardTarget}
            anchor={card.anchor}
            // The part of the canvas above the toolbar docked under the graph.
            bounds={{ width, height: Math.max(0, height - toolbarOverlap) }}
            context={context}
            badges={cardTarget.kind === 'node' ? badgesOfNode(cardTarget.node, { t_i18n }) : []}
            relationshipCounts={cardTarget.kind === 'node'
              ? relationshipCounts(shownLinks.map((link) => ({
                  id: link.id,
                  sourceId: endpointId(link.source) ?? link.source_id,
                  targetId: endpointId(link.target) ?? link.target_id,
                  relationship_type: link.relationship_type,
                  entity_type: link.entity_type,
                  represents: link.represents,
                })), cardTarget.node.id)
              : []}
            groupMembers={cardTarget.kind === 'node' && cardTarget.node.groupOf ? groupMembersOf(cardTarget.node) : undefined}
            onMouseEnter={cancelClose}
            onMouseLeave={scheduleClose}
          />
        )}
        <GraphContextMenu
          anchor={menu?.anchor ?? null}
          label={t_i18n('Graph actions')}
          sections={menu ? menuSections(menu.target) : []}
          onClose={() => setMenu(null)}
          onReturnFocus={() => menuReturnFocus.current?.focus()}
        />
        <GraphAccessibleList
          nodes={shownNodes}
          links={shownLinks}
          selectedKeys={selectedKeys}
          onSelectNode={(node, additive) => {
            if (node.groupOf) {
              toggleCollapsedEntityType(node.groupOf.entityType);
              return;
            }
            if (additive) {
              setSelectedNodes(selectedKeys.has(graphElementKey({ kind: 'node', node }))
                ? selectedNodes.filter((n) => n.id !== node.id)
                : [...selectedNodes, node]);
            } else selectNodes([node]);
          }}
          onSelectLink={(link, additive) => {
            // A link drawn towards a group is no relationship to select: choosing it expands its group, as choosing the group does.
            if (isGroupLink(link)) {
              const ends = [endpointId(link.source) ?? link.source_id, endpointId(link.target) ?? link.target_id];
              const group = shownNodes.find((node) => !!node.groupOf && ends.includes(node.id));
              if (group?.groupOf) toggleCollapsedEntityType(group.groupOf.entityType);
              return;
            }
            // By relationship, as on the canvas: the two connectors of a nested relationship share its id
            if (additive) {
              setSelectedLinks(selectedLinks.some((l) => l.id === link.id)
                ? selectedLinks.filter((l) => l.id !== link.id)
                : [...selectedLinks, link]);
            } else {
              setSelectedNodes([]);
              setSelectedLinks([link]);
            }
          }}
          onActiveChange={setHovered}
        />
        <GraphShortcutsDialog open={shortcutsOpen} onClose={() => setShortcutsOpen(false)} searchable={context !== 'analyses'} exportable={canExport} />
        <GraphViewContext.Provider value={viewActions}>
          {children}
        </GraphViewContext.Provider>
      </div>
    </RectangleSelection>
  );
};

export default Graph;
