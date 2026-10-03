import React, { MutableRefObject, useRef } from 'react';
import ForceGraph2D, { ForceGraphProps } from 'react-force-graph-2d';
import { GraphLink, GraphNode } from './graph.types';
import useResizeObserver from '../../utils/hooks/useResizeObserver';
import useGraphPainter from './utils/useGraphPainter';
import { GraphRef2D } from './GraphContext';

interface SimpleGraph2DProps extends ForceGraphProps<GraphNode, GraphLink> {
  parentRef: MutableRefObject<HTMLDivElement | null>;
  onReady?: (graphRef: GraphRef2D) => void;
  showParticules?: boolean;
}

const SimpleGraph2D = ({
  parentRef,
  onReady,
  showParticules = false,
  ...graphProps
}: SimpleGraph2DProps) => {
  const initialized = useRef(false);
  const graphRef = useRef<GraphRef2D>(undefined);
  const { width, height } = useResizeObserver(parentRef);

  if (!initialized.current && graphRef.current) {
    // A short timeout to be sure graph is ready.
    setTimeout(() => {
      if (graphRef.current) {
        onReady?.(graphRef.current);
        initialized.current = true;
      }
    }, 100);
  }

  const {
    nodePaint,
    nodePointerAreaPaint,
    linkPaint,
    linkCurvature,
    framePrePaint,
    framePostPaint,
    linkColorPaint,
  } = useGraphPainter({
    selectedLinks: [],
    selectedNodes: [],
    detailsPreviewSelected: undefined,
    search: undefined,
    links: graphProps.graphData?.links ?? [],
    nodeCount: graphProps.graphData?.nodes.length ?? 0,
  });

  return (
    <ForceGraph2D<GraphNode, GraphLink>
      ref={graphRef}
      width={width}
      height={height}
      dagLevelDistance={50}
      nodeLabel={() => ''}
      linkCurvature={linkCurvature}
      linkWidth={2}
      linkCanvasObjectMode={() => 'replace'}
      linkCanvasObject={(link, ctx, globalScale) => linkPaint(link, ctx, globalScale)}
      linkDirectionalParticles={(link) => (link.inferred && showParticules ? 20 : 0)}
      linkDirectionalParticleWidth={showParticules ? 2 : undefined}
      linkDirectionalParticleSpeed={showParticules ? 0.002 : undefined}
      linkColor={linkColorPaint}
      nodePointerAreaPaint={(node, color, ctx, globalScale) => nodePointerAreaPaint(node, color, ctx, globalScale)}
      nodeCanvasObject={(node, ctx, globalScale) => nodePaint(node, ctx, { globalScale })}
      onRenderFramePre={framePrePaint}
      onRenderFramePost={framePostPaint}
      {...graphProps}
    />
  );
};

export default SimpleGraph2D;
