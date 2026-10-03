import ForceGraph2D from 'react-force-graph-2d';
import ForceGraph3D from 'react-force-graph-3d';
import React, { type MutableRefObject, ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import { useTheme } from '@mui/material/styles';
import RectangleSelection from './components/RectangleSelection';
import { useGraphContext } from './GraphContext';
import useResizeObserver from '../../utils/hooks/useResizeObserver';
import { GraphLink, GraphNode, LibGraphProps, OctiGraphPositions } from './graph.types';
import useGraphPainter, { type GraphHoverTarget } from './utils/useGraphPainter';
import useGraphInteractions from './utils/useGraphInteractions';
import LassoSelection from './components/LassoSelection';
import useGraphFilter from './utils/useGraphFilter';
import EntitiesDetailsRightsBar from './components/EntitiesDetailsRightBar';
import type { Theme } from '../Theme';
import RelationSelection from './components/RelationSelection';
import GraphLoadingAlert from './components/GraphLoadingAlert';
import GraphControls from './components/GraphControls';
import GraphLegend from './components/GraphLegend';
import GraphHoverCard, { type GraphHoverCardTarget } from './components/GraphHoverCard';
import GraphAccessibleList from './components/GraphAccessibleList';
import GraphShortcutsDialog from './components/GraphShortcutsDialog';
import { useFormatter } from '../i18n';
import { itemFamily } from '../../utils/Colors';
import { createCollapseCache, isCollapsedMember, withCollapsedGroups } from './utils/graphCollapse';
import { entityTier, layeredLayout, radialLayout, tierLayout } from './utils/graphLayouts';
import useGraphLayoutEngine, { type GraphLayoutRequest } from './utils/useGraphLayoutEngine';
import useGraphKeyboardShortcuts from './utils/useGraphKeyboardShortcuts';
import useGraphFullscreen from './utils/useGraphFullscreen';
import { relationshipCounts } from './utils/graphFocus';
import { badgesOfNode } from './badges';
import { downloadCanvasAsPng, renderGraphImage } from './utils/graphExport';
import { MESSAGING$ } from '../../relay/environment';
import useGraphStartInvestigation from './utils/useGraphStartInvestigation';
import { graphNodeTitle } from './utils/useGraphParser';

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
  const containerRef = useRef<HTMLDivElement | null>(null);
  const pointer = useRef({ x: 0, y: 0 });
  const startInvestigation = useGraphStartInvestigation();

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
    toggleCollapsedEntityType,
    toggleRelationshipType,
    highlightShortestPath,
    selectNeighbours,
    zoomIn,
    zoomOut,
    zoomToSelection,
    locateNode,
    centreRadialLayoutOn,
    isNodeShown,
  } = useGraphInteractions();

  const {
    graphRef2D,
    graphRef3D,
    graphData,
    context,
    title,
    rawPositions,
    isFullscreen,
    setIsFullscreen,
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
      highlightedPath,
    },
  } = useGraphContext();

  useGraphFilter();

  const isLoadingData = (loadingCurrent ?? 0) < (loadingTotal ?? 0);

  // --- What is drawn: groups for collapsed types, hidden entities left out.
  const collapseCache = useRef(createCollapseCache());
  const displayData = useMemo(() => (graphData
    ? withCollapsedGroups(
        graphData,
        collapsedEntityTypes,
        (entityType, count) => `${count} \u00d7 ${t_i18n(`entity_${entityType}`)}`,
        collapseCache.current,
      )
    : graphData), [graphData, collapsedEntityTypes]);
  const hiddenIds = useMemo(() => new Set(hiddenNodeIds), [hiddenNodeIds]);
  const nodeShown = (node: GraphNode) => !hiddenIds.has(node.id) && !isCollapsedMember(node, collapsedEntityTypes);
  const shownNodes = useMemo(() => (displayData?.nodes ?? []).filter(nodeShown), [displayData, hiddenIds, collapsedEntityTypes]);
  const shownNodeIds = useMemo(() => new Set(shownNodes.map((n) => n.id)), [shownNodes]);
  const linkShown = (link: GraphLink) => shownNodeIds.has(endpointId(link.source) ?? link.source_id)
    && shownNodeIds.has(endpointId(link.target) ?? link.target_id);
  const shownLinks = useMemo(() => (displayData?.links ?? []).filter(linkShown), [displayData, shownNodeIds]);
  const shapeSignature = useMemo(
    () => `${shownNodes.map((n) => n.id).sort().join()}|${shownLinks.map((l) => l.id).sort().join()}`,
    [shownNodes, shownLinks],
  );

  // --- Hover: focus on the canvas at once, card after a short delay.
  const [hovered, setHovered] = useState<GraphHoverTarget | null>(null);
  const [card, setCard] = useState<{ target: GraphHoverTarget; anchor: { x: number; y: number } } | null>(null);
  const openTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const closeTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const cancelClose = () => clearTimeout(closeTimer.current);
  const scheduleClose = () => {
    clearTimeout(closeTimer.current);
    closeTimer.current = setTimeout(() => setCard(null), HOVER_CLOSE_MS);
  };
  const onHover = (target: GraphHoverTarget | null) => {
    setHovered(target);
    clearTimeout(openTimer.current);
    if (!target || selectFree || selectFreeRectangle || isExpandOpen || isAddRelationOpen) {
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

  const {
    palette,
    nodePaint,
    nodePointerAreaPaint,
    nodeThreePaint,
    linkColorPaint,
    linkPaint,
    linkCurvature,
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
    highlightedPath,
    nodeCount: shownNodes.length,
  });

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
  const { animating } = useGraphLayoutEngine({
    graphRef: graphRef2D,
    nodes: shownNodes,
    shapeSignature,
    layout,
    enabled: !mode3D && !isLoadingData && shownNodes.length > 0,
    savedPositions: rawPositions,
  });

  useEffect(() => {
    // A short timeout to be sure graph is ready.
    setTimeout(() => {
      if (!isLoadingData) {
        initForces();
        if (withForces) applyForces();

        // Another short timeout to wait forces to be applied
        setTimeout(() => {
          if (zoom) setZoom(zoom);
          else zoomToFit();
        }, 1000);
      }
    }, 100);
  }, [mode3D, isLoadingData]);

  const selectedEntities = [...selectedLinks, ...selectedNodes];
  const selectedIds = useMemo(() => new Set(selectedEntities.map((e) => e.id)), [selectedLinks, selectedNodes]);
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
    if (node.groupOf) {
      toggleCollapsedEntityType(node.groupOf.entityType);
      return;
    }
    let isDoubleClick = false;
    const now = new Date().getTime();
    if (!e.ctrlKey && !e.shiftKey && !e.altKey) {
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
  const otherSelected = (node: GraphNode) => (selectedNodes.length === 1 && selectedNodes[0].id !== node.id ? selectedNodes[0] : null);

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
    const canvas = renderGraphImage({
      nodes: shownNodes,
      links: shownLinks,
      palette,
      title: imageTitle,
      subtitle: `${t_i18n('{count} entities', { values: { count: shownNodes.length } })}, ${t_i18n('{count} relationships', { values: { count: shownLinks.filter((l) => !!l.label).length } })}`,
      typeLabel: (node) => (node.relationship_type ? t_i18n(`relationship_${node.relationship_type}`) : t_i18n(`entity_${node.entity_type}`)),
      badgesOf: (node) => badgesOfNode(node, { t_i18n }),
      linkColor: linkColorPaint,
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
  useGraphKeyboardShortcuts(containerRef, {
    fit: zoomToFit,
    fitSelection: () => zoomToSelection(),
    locate: () => locateNode(),
    zoomIn,
    zoomOut,
    selectAll: selectAllNodes,
    selectNeighbours: () => selectNeighbours(),
    shortestPath: shortestPathOfSelection,
    hideSelection: () => hideNodes(selectedNodes.map((n) => n.id)),
    showHidden: showHiddenNodes,
    clearSelection: () => {
      if (selectedEntities.length === 0 && isFullscreen) exitFullscreen();
      else onBackgroundClick();
    },
    toggleLegend,
    toggleFullscreen,
    exportImage: () => {
      exportImage();
    },
    focusSearch: () => {
      parentRef.current?.querySelector<HTMLInputElement>('[data-graph-search] input')?.focus();
    },
    showShortcuts: () => setShortcutsOpen(true),
  });

  const cardTarget: GraphHoverCardTarget | null = useMemo(() => {
    if (!card) return null;
    if (card.target.kind === 'node') {
      const node = (displayData?.nodes ?? []).find((n) => n.id === card.target.id);
      return node && nodeShown(node) ? { kind: 'node', node } : null;
    }
    const link = (displayData?.links ?? []).find((l) => l.id === card.target.id);
    return link && linkShown(link) ? { kind: 'link', link } : null;
  }, [card, displayData, shownNodeIds]);

  const canRelate = context !== 'analyses' && context !== 'correlation';

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
      >
        <GraphLoadingAlert />
        {selectedEntities.length > 0 && <EntitiesDetailsRightsBar />}
        {mode3D ? (
          <ForceGraph3D<GraphNode, GraphLink>
            ref={graphRef3D}
            width={width}
            height={height}
            backgroundColor={theme.palette.background.default}
            graphData={displayData}
            dagMode={modeTree ?? undefined}
            cooldownTicks={(!withForces || isLoadingData) ? 0 : 100}
            linkDirectionalArrowLength={3}
            linkDirectionalArrowRelPos={0.99}
            linkWidth={0.5}
            linkOpacity={0.8}
            linkThreeObjectExtend
            linkThreeObject={linkThreePaint}
            linkPositionUpdate={linkThreeLabelPosition}
            linkColor={linkColorPaint}
            linkVisibility={linkShown}
            nodeVisibility={nodeShown}
            nodeColor={(node) => (node.disabled ? palette.disabled : node.color)}
            nodeOpacity={0.8}
            nodeThreeObjectExtend
            nodeThreeObject={nodeThreePaint}
            onLinkClick={toggleLink}
            onBackgroundClick={onBackgroundClick}
            onNodeClick={onNodeClick}
            onNodeDrag={moveSelection}
            onNodeDragEnd={onNodeDragEnd}
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
              graphData={displayData}
              nodeRelSize={4}
              maxZoom={24}
              warmupTicks={hasNoSavedPosition ? WARMUP_TICKS : 0}
              cooldownTicks={(!withForces || isLoadingData) ? 0 : 100}
              autoPauseRedraw={!animating}
              enablePanInteraction={!selectFree && !selectFreeRectangle}
              nodeLabel={() => ''}
              linkLabel={() => ''}
              nodeVisibility={nodeShown}
              linkVisibility={linkShown}
              linkCurvature={linkCurvature}
              linkWidth={2}
              linkDirectionalArrowLength={0}
              linkCanvasObjectMode={() => 'replace'}
              linkCanvasObject={(link, ctx, globalScale) => linkPaint(link, ctx, globalScale)}
              linkColor={linkColorPaint}
              nodePointerAreaPaint={(node, color, ctx, globalScale) => nodePointerAreaPaint(node, color, ctx, globalScale)}
              nodeCanvasObject={(node, ctx, globalScale) => nodePaint(node, ctx, {
                showNbConnectedElements: context === 'investigation',
                globalScale,
              })}
              onRenderFramePre={framePrePaint}
              onRenderFramePost={framePostPaint}
              onNodeHover={(node) => onHover(node ? { kind: 'node', id: node.id } : null)}
              onLinkHover={(link) => onHover(link ? { kind: 'link', id: link.id } : null)}
              onZoomEnd={saveZoom}
              onLinkClick={toggleLink}
              onBackgroundClick={onBackgroundClick}
              onNodeClick={onNodeClick}
              onNodeDrag={(node, translate) => {
                setCard(null);
                moveSelection(node, translate);
              }}
              onNodeDragEnd={onNodeDragEnd}
            />
          </>
        )}
        <GraphControls
          hasSelection={selectedNodes.length > 0}
          is3D={mode3D}
          isFullscreen={isFullscreen}
          showLegend={showLegend}
          onZoomIn={zoomIn}
          onZoomOut={zoomOut}
          onFit={zoomToFit}
          onFitSelection={() => zoomToSelection()}
          onLocate={() => locateNode()}
          onToggleLegend={toggleLegend}
          onToggleFullscreen={toggleFullscreen}
          onExport={() => {
            exportImage();
          }}
          onShowShortcuts={() => setShortcutsOpen(true)}
        />
        {!mode3D && showLegend && shownNodes.length > 0 && (
          <GraphLegend
            nodes={shownNodes}
            links={shownLinks}
            disabledEntityTypes={disabledEntityTypes}
            disabledRelationshipTypes={disabledRelationshipTypes}
            collapsedEntityTypes={collapsedEntityTypes}
            hiddenCount={hiddenNodeIds.length}
            onToggleEntityType={toggleEntityType}
            onToggleRelationshipType={toggleRelationshipType}
            onToggleCollapsed={toggleCollapsedEntityType}
            onShowHidden={showHiddenNodes}
          />
        )}
        {!mode3D && card && cardTarget && (
          <GraphHoverCard
            target={cardTarget}
            anchor={card.anchor}
            bounds={{ width, height }}
            context={context}
            badges={cardTarget.kind === 'node' ? badgesOfNode(cardTarget.node, { t_i18n }) : []}
            relationshipCounts={cardTarget.kind === 'node'
              ? relationshipCounts(shownLinks.map((link) => ({
                  id: link.id,
                  sourceId: endpointId(link.source) ?? link.source_id,
                  targetId: endpointId(link.target) ?? link.target_id,
                  relationship_type: link.relationship_type,
                  entity_type: link.entity_type,
                })), cardTarget.node.id)
              : []}
            isPinned={cardTarget.kind === 'node' && cardTarget.node.fx !== undefined && cardTarget.node.fx !== null}
            onMouseEnter={cancelClose}
            onMouseLeave={scheduleClose}
            actions={{
              onOpen: (id) => window.open(`/dashboard/id/${id}`, '_blank', 'noopener,noreferrer'),
              onExpand: context === 'investigation'
                ? (node) => {
                    selectNodes([node]);
                    setIsExpandOpen(true);
                    setCard(null);
                  }
                : undefined,
              onTogglePin: togglePin,
              onHide: (node) => {
                hideNodes([node.id]);
                setCard(null);
              },
              onSelectNeighbours: (node) => selectNeighbours([node.id]),
              onCentreRadial: (node) => {
                centreRadialLayoutOn(node.id);
                setCard(null);
              },
              onPathFromSelection: cardTarget.kind === 'node' && otherSelected(cardTarget.node)
                ? (node) => {
                    const other = otherSelected(node);
                    if (!other) return;
                    selectNodes([other, node]);
                    if (!highlightShortestPath(other.id, node.id)) {
                      MESSAGING$.notifyError(t_i18n('These two nodes are not connected in this graph'));
                    }
                  }
                : undefined,
              onRelateToSelection: canRelate && cardTarget.kind === 'node' && otherSelected(cardTarget.node)
                ? (node) => {
                    const other = otherSelected(node);
                    if (!other) return;
                    selectNodes([other, node]);
                    setIsAddRelationOpen(true);
                    setCard(null);
                  }
                : undefined,
              onStartInvestigation: startInvestigation && context !== 'investigation'
                ? (node) => {
                    const selectedEntityNodes = selectedNodes.filter((n) => !n.relationship_type && !n.groupOf);
                    const seeds = selectedEntityNodes.some((n) => n.id === node.id) ? selectedEntityNodes : [node];
                    setCard(null);
                    startInvestigation(graphNodeTitle(node), seeds.map((n) => n.id));
                  }
                : undefined,
              onExpandGroup: (entityType) => {
                toggleCollapsedEntityType(entityType);
                setCard(null);
              },
              onSelectLink: (link) => {
                setSelectedNodes([]);
                setSelectedLinks([link]);
              },
            }}
          />
        )}
        <GraphAccessibleList
          nodes={shownNodes}
          links={shownLinks}
          selectedIds={selectedIds}
          onSelectNode={(node, additive) => {
            if (node.groupOf) {
              toggleCollapsedEntityType(node.groupOf.entityType);
              return;
            }
            if (additive) setSelectedNodes(selectedIds.has(node.id) ? selectedNodes.filter((n) => n.id !== node.id) : [...selectedNodes, node]);
            else selectNodes([node]);
          }}
          onSelectLink={(link, additive) => {
            if (additive) setSelectedLinks(selectedIds.has(link.id) ? selectedLinks.filter((l) => l.id !== link.id) : [...selectedLinks, link]);
            else {
              setSelectedNodes([]);
              setSelectedLinks([link]);
            }
          }}
        />
        <GraphShortcutsDialog open={shortcutsOpen} onClose={() => setShortcutsOpen(false)} />
        {children}
      </div>
    </RectangleSelection>
  );
};

export default Graph;
