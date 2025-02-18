import ForceGraph2D from 'react-force-graph-2d';
import ForceGraph3D from 'react-force-graph-3d';
import React, { type MutableRefObject } from 'react';
import { v4 as uuid } from 'uuid';
import { useTheme } from '@mui/material/styles';
import { GraphQLTaggedNode } from 'relay-runtime/lib/query/RelayModernGraphQLTag';
import RectangleSelection from './components/RectangleSelection';
import { GraphProvider, GraphState, useGraphContext } from './utils/GraphContext';
import useResizeObserver from '../hooks/useResizeObserver';
import GraphToolbar from './components/GraphToolbar';
import { GraphContainer, GraphLink, GraphNode, LibGraphProps, OctiGraphPositions } from './graph.types';
import useGraphPainter from './utils/useGraphPainter';
import useGraphInteractions from './utils/useGraphInteractions';
import LassoSelection from './components/LassoSelection';
import useGraphFilter from './utils/useGraphFilter';
import EntitiesDetailsRightsBar from './components/EntitiesDetailsRightBar';
import type { Theme } from '../../components/Theme';

const DEFAULT_STATE: GraphState = {
  mode3D: false,
  modeTree: null,
  withForces: true,
  selectFreeRectangle: false,
  selectFree: false,
  selectRelationshipMode: null,
  showTimeRange: false,
  disabledEntityTypes: [],
  disabledCreators: [],
  disabledMarkings: [],
};

interface GraphComponentProps {
  parentRef: MutableRefObject<HTMLDivElement | null>
  onPositionsChanged: (positions: OctiGraphPositions) => void
  stixCoreObjectRefetchQuery: GraphQLTaggedNode
  relationshipRefetchQuery: GraphQLTaggedNode
  container?: GraphContainer
  enableReferences?: boolean
}

const GraphComponent = ({
  container,
  enableReferences,
  parentRef,
  onPositionsChanged,
  stixCoreObjectRefetchQuery,
  relationshipRefetchQuery,
}: GraphComponentProps) => {
  const graphId = `graph-${uuid()}`;
  const theme = useTheme<Theme>();
  const { width, height } = useResizeObserver(parentRef);

  const {
    saveZoom,
    toggleNode,
    toggleLink,
    clearSelection,
    moveSelection,
    fixPositionsOnDragEnd,
    selectFromFreeRectangle,
  } = useGraphInteractions();

  const {
    nodePaint,
    nodePointerAreaPaint,
    nodeThreePaint,
    linkLabelPaint,
    linkColorPaint,
    linkThreePaint,
    linkThreeLabelPosition,
  } = useGraphPainter();

  const {
    graphRef2D,
    graphRef3D,
    graphData,
    setSelectedNodes,
    selectedLinks,
    selectedNodes,
    graphState: {
      mode3D,
      modeTree,
      selectFree,
      selectFreeRectangle,
      withForces,
    },
  } = useGraphContext();

  useGraphFilter();

  const shouldDisplayLinks = graphData?.links.length ?? 0 < 200;
  const selectedEntities = [...selectedLinks, ...selectedNodes];

  return (
    <div id={graphId}>
      {selectedEntities.length > 0 && (
        // TODO update EntitiesDetailsRightsBar component when every refacto done
        <EntitiesDetailsRightsBar selectedEntities={selectedEntities} />
      )}
      {mode3D ? (
        <ForceGraph3D<GraphNode, GraphLink>
          ref={graphRef3D}
          width={width}
          height={height}
          backgroundColor={theme.palette.background.default}
          graphData={graphData}
          dagMode={modeTree ?? undefined}
          cooldownTicks={!withForces ? 0 : 100}
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
      ) : (
        <>
          <LassoSelection
            width={width}
            height={height}
            activated={selectFree}
            graphDataNodes={graphData?.nodes ?? []}
            graph={graphRef2D}
            // TODO update LassoSelection component when every refacto done
            setSelectedNodes={(nodes) => setSelectedNodes(Array.from(nodes) as GraphNode[])}
          />
          <RectangleSelection
            graphId={graphId}
            disabled={!selectFreeRectangle}
            onSelection={selectFromFreeRectangle}
          >
            <ForceGraph2D<GraphNode, GraphLink>
              ref={graphRef2D}
              width={width}
              height={height}
              graphData={graphData}
              dagMode={modeTree ?? undefined}
              dagLevelDistance={50}
              cooldownTicks={!withForces ? 0 : 100}
              enablePanInteraction={!selectFree && !selectFreeRectangle}
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
          </RectangleSelection>
        </>
      )}
      <GraphToolbar
        container={container}
        enableReferences={enableReferences}
        stixCoreObjectRefetchQuery={stixCoreObjectRefetchQuery}
        relationshipRefetchQuery={relationshipRefetchQuery}
      />
    </div>
  );
};

interface GraphProps extends GraphComponentProps {
  localStorageKey: string
  graphData: LibGraphProps['graphData']
}

const Graph = ({ localStorageKey, graphData, ...props }: GraphProps) => {
  return (
    <GraphProvider
      data={graphData}
      defaultState={DEFAULT_STATE}
      localStorageKey={localStorageKey}
    >
      <GraphComponent {...props} />
    </GraphProvider>
  );
};

export default Graph;
