import ForceGraph2D from 'react-force-graph-2d';
import ForceGraph3D from 'react-force-graph-3d';
import React, { type MutableRefObject, ReactNode, useEffect, useRef } from 'react';
import { v4 as uuid } from 'uuid';
import { useTheme } from '@mui/material/styles';
import RectangleSelection from './components/RectangleSelection';
import { useGraphContext } from './GraphContext';
import useResizeObserver from '../../utils/hooks/useResizeObserver';
import { GraphLink, GraphNode, LibGraphProps, OctiGraphPositions } from './graph.types';
import useGraphPainter from './utils/useGraphPainter';
import useGraphInteractions from './utils/useGraphInteractions';
import LassoSelection from './components/LassoSelection';
import useGraphFilter from './utils/useGraphFilter';
import EntitiesDetailsRightsBar from './components/EntitiesDetailsRightBar';
import type { Theme } from '../Theme';
import RelationSelection from './components/RelationSelection';
import GraphLoadingAlert from './components/GraphLoadingAlert';

export interface GraphProps {
  parentRef: MutableRefObject<HTMLDivElement | null>
  onPositionsChanged?: (positions: OctiGraphPositions) => void
  children?: ReactNode
}

const Graph = ({
  parentRef,
  onPositionsChanged,
  children,
}: GraphProps) => {
  const graphId = `graph-${uuid()}`;
  const theme = useTheme<Theme>();
  const { width, height } = useResizeObserver(parentRef);
  const nodeClicked = useRef<{ node?: GraphNode, time?: number }>({});

  const {
    saveZoom,
    toggleNode,
    toggleLink,
    clearSelection,
    moveSelection,
    fixPositionsOnDragEnd,
    selectFromFreeRectangle,
    setSelectedNodes,
    setIsAddRelationOpen,
    setRawPositions,
    setZoom,
    zoomToFit,
    applyForces,
    setIsExpandOpen,
    initForces,
  } = useGraphInteractions();

  const {
    graphRef2D,
    graphRef3D,
    graphData,
    context,
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
    },
  } = useGraphContext();

  const {
    nodePaint,
    nodePointerAreaPaint,
    nodeThreePaint,
    linkLabelPaint,
    linkColorPaint,
    linkThreePaint,
    linkThreeLabelPosition,
  } = useGraphPainter({
    selectedLinks,
    selectedNodes,
    search,
    detailsPreviewSelected,
  });

  useGraphFilter();

  const isLoadingData = (loadingCurrent ?? 0) < (loadingTotal ?? 0);

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

  const shouldDisplayLinks = graphData?.links.length ?? 0 < 200;
  const selectedEntities = [...selectedLinks, ...selectedNodes];

  const onNodeDragEnd = (node: GraphNode) => {
    fixPositionsOnDragEnd(node);
    const newPositions = (graphData?.nodes ?? []).reduce((acc, { id, x, y }) => ({
      ...acc,
      [id]: { id, x, y },
    }), {});
    setRawPositions(newPositions);
    onPositionsChanged?.(newPositions);
  };

  const onNodeClick: LibGraphProps['onNodeClick'] = (node, e) => {
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

  return (
    <RectangleSelection
      graphId={graphId}
      disabled={!selectFreeRectangle}
      onSelection={selectFromFreeRectangle}
    >
      <div style={{ position: 'relative' }} id={graphId}>
        <GraphLoadingAlert />
        {selectedEntities.length > 0 && <EntitiesDetailsRightsBar />}
        {mode3D ? (
          <ForceGraph3D<GraphNode, GraphLink>
            ref={graphRef3D}
            width={width}
            height={height}
            backgroundColor={theme.palette.background.default}
            graphData={graphData}
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
            nodeOpacity={0.8}
            nodeThreeObjectExtend
            nodeThreeObject={nodeThreePaint}
            onLinkClick={toggleLink}
            onBackgroundClick={clearSelection}
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
              graphDataNodes={graphData?.nodes ?? []}
              graph={graphRef2D}
              setSelectedNodes={(nodes) => setSelectedNodes(Array.from(nodes))}
            />
            <RelationSelection
              width={width}
              height={height}
              activated={!selectFree && !selectFreeRectangle}
              graphDataNodes={graphData?.nodes ?? []}
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
              graphData={graphData}
              dagMode={modeTree ?? undefined}
              dagLevelDistance={50}
              nodeRelSize={4}
              cooldownTicks={(!withForces || isLoadingData) ? 0 : 100}
              enablePanInteraction={!selectFree && !selectFreeRectangle}
              linkDirectionalArrowLength={3}
              linkDirectionalArrowRelPos={0.99}
              linkCanvasObjectMode={() => 'after'}
              linkCanvasObject={(link, ctx) => (shouldDisplayLinks ? linkLabelPaint(link, ctx) : null)}
              linkLineDash={(link) => (link.isNestedInferred ? [2, 1] : null)}
              linkColor={linkColorPaint}
              nodePointerAreaPaint={nodePointerAreaPaint} // What's for?
              nodeCanvasObject={(node, ctx) => nodePaint(node, ctx, {
                showNbConnectedElements: context === 'investigation',
              })}
              onZoomEnd={saveZoom}
              onLinkClick={toggleLink}
              onBackgroundClick={clearSelection}
              onNodeClick={onNodeClick}
              onNodeDrag={moveSelection}
              onNodeDragEnd={onNodeDragEnd}
            />
          </>
        )}
        {children}
      </div>
    </RectangleSelection>
  );
};

export default Graph;
