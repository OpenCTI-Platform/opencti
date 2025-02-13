import ForceGraph2D from 'react-force-graph-2d';
import React, { type MutableRefObject, useRef } from 'react';
import { GraphProvider, GraphState, useGraphContext } from './utils/GraphContext';
import useResizeObserver from '../hooks/useResizeObserver';
import GraphToolbar from './components/GraphToolbar';
import { GraphLink, GraphNode, LibGraphProps, OctiGraphPositions } from './graph.types';
import useGraphPainter from './utils/useGraphPainter';
import useGraphInteractions from './utils/useGraphInteractions';

const DEFAULT_STATE: GraphState = {
  mode3D: false,
  modeTree: null,
  withForces: true,
  selectFreeRectangle: false,
  selectFree: false,
  selectRelationshipMode: null,
  showTimeRange: false,
};

interface GraphComponentProps {
  containerRef: MutableRefObject<HTMLDivElement | null>
  graphData: LibGraphProps['graphData']
  onPositionsChanged: (positions: OctiGraphPositions) => void
}

const GraphComponent = ({
  containerRef,
  graphData,
  onPositionsChanged,
}: GraphComponentProps) => {
  const graphRef = useRef();
  const { width, height } = useResizeObserver(containerRef);

  const {
    saveZoom,
    toggleNode,
    toggleLink,
    clearSelection,
    moveSelection,
    fixPositionsOnDragEnd,
  } = useGraphInteractions();
  const {
    nodePaint,
    nodePointerAreaPaint,
    linkLabelPaint,
    linkColorPaint,
  } = useGraphPainter();

  const { graphState } = useGraphContext();
  const { modeTree, selectFree, selectFreeRectangle, withForces } = graphState;

  const shouldDisplayLinks = graphData?.links.length ?? 0 < 200;

  return (
    <>
      <ForceGraph2D<GraphNode, GraphLink>
        ref={graphRef}
        width={width}
        height={height}
        graphData={graphData}
        dagMode={modeTree ?? undefined}
        dagLevelDistance={50}
        cooldownTicks={!withForces ? 0 : 100}
        enablePanInteraction={!selectFree && !selectFreeRectangle} // Really useful?
        linkDirectionalArrowLength={3}
        linkDirectionalArrowRelPos={0.99}
        linkCanvasObjectMode={() => 'after'}
        linkCanvasObject={(link, ctx) => (shouldDisplayLinks ? linkLabelPaint(link, ctx) : null)}
        linkLineDash={(link) => (link.inferred || link.isNestedInferred ? [2, 1] : null)}
        linkColor={linkColorPaint}
        nodePointerAreaPaint={nodePointerAreaPaint} // What's for?
        nodeCanvasObject={(node, ctx) => nodePaint(node, ctx)}
        onZoomEnd={saveZoom}
        onLinkClick={toggleLink}
        onBackgroundClick={clearSelection}
        onNodeClick={toggleNode}
        onNodeDrag={moveSelection}
        onNodeDragEnd={(node) => {
          fixPositionsOnDragEnd(node);
          onPositionsChanged((graphData?.nodes ?? []).reduce((acc, { id, x, y }) => ({
            ...acc,
            [id]: { id, x, y },
          }), {}));
        }}
      />
      <GraphToolbar />
    </>
  );
};

interface GraphProps extends GraphComponentProps {
  localStorageKey: string
}

const Graph = ({ localStorageKey, ...props }: GraphProps) => {
  return (
    <GraphProvider
      defaultState={DEFAULT_STATE}
      localStorageKey={localStorageKey}
    >
      <GraphComponent {...props} />
    </GraphProvider>
  );
};

export default Graph;
