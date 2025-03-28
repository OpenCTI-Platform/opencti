import React, { MutableRefObject, useRef } from 'react';
import ForceGraph2D, { ForceGraphProps } from 'react-force-graph-2d';
import { GraphLink, GraphNode } from './graph.types';
import useResizeObserver from '../../utils/hooks/useResizeObserver';
import useGraphPainter from './utils/useGraphPainter';
import { GraphRef2D } from './GraphContext';

interface SimpleGraph2DProps extends ForceGraphProps<GraphNode, GraphLink> {
  parentRef: MutableRefObject<HTMLDivElement | null>
  onReady?: (graphRef: GraphRef2D) => void
}

const SimpleGraph2D = ({
  parentRef,
  onReady,
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
    linkLabelPaint,
    linkColorPaint,
  } = useGraphPainter();

  return (
    <ForceGraph2D<GraphNode, GraphLink>
      ref={graphRef}
      width={width}
      height={height}
      dagLevelDistance={50}
      linkDirectionalArrowLength={3}
      linkDirectionalArrowRelPos={0.99}
      linkCanvasObjectMode={() => 'after'}
      linkCanvasObject={(link, ctx) => linkLabelPaint(link, ctx)}
      linkLineDash={(link) => (link.isNestedInferred ? [2, 1] : null)}
      linkDirectionalParticles={(link) => (link.inferred ? 20 : 0)}
      linkDirectionalParticleWidth={2}
      linkDirectionalParticleSpeed={() => 0.002}
      linkColor={linkColorPaint}
      nodePointerAreaPaint={nodePointerAreaPaint} // What's for?
      nodeCanvasObject={(node, ctx) => nodePaint(node, ctx)}
      {...graphProps}
    />
  );
};

export default SimpleGraph2D;
