import React, { MutableRefObject, useRef, useState } from 'react';
import ForceGraph2D, { ForceGraphProps } from 'react-force-graph-2d';
import { GraphLink, GraphNode } from './graph.types';
import useResizeObserver from '../../utils/hooks/useResizeObserver';
import useGraphPainter, { type GraphHoverTarget, linkHoverTarget } from './utils/useGraphPainter';
import { GraphRef2D } from './GraphContext';
import GraphAccessibleList from './components/GraphAccessibleList';

interface SimpleGraph2DProps extends ForceGraphProps<GraphNode, GraphLink> {
  parentRef: MutableRefObject<HTMLDivElement | null>;
  onReady?: (graphRef: GraphRef2D) => void;
  showParticules?: boolean;
}

const NO_SELECTION: ReadonlySet<string> = new Set();

/**
 * A small read-only graph, such as the explanation of an inferred relationship: drawn by the shared
 * painter, with the focus on what the pointer is over and the same keyboard and screen reader
 * mirror as the full graph, whose Enter does what a click on the canvas does.
 */
const SimpleGraph2D = ({
  parentRef,
  onReady,
  showParticules = false,
  ...graphProps
}: SimpleGraph2DProps) => {
  const initialized = useRef(false);
  const graphRef = useRef<GraphRef2D>(undefined);
  const { width, height } = useResizeObserver(parentRef);
  const [hovered, setHovered] = useState<GraphHoverTarget | null>(null);

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
    hovered,
  });

  const { onNodeClick, onLinkClick } = graphProps;

  return (
    <>
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
        nodeCanvasObject={(node, ctx, globalScale) => nodePaint(node, ctx, globalScale)}
        onRenderFramePre={framePrePaint}
        onRenderFramePost={framePostPaint}
        onNodeHover={(node) => setHovered(node ? { kind: 'node', id: node.id } : null)}
        onLinkHover={(link) => setHovered(link ? linkHoverTarget(link) : null)}
        {...graphProps}
      />
      <GraphAccessibleList
        nodes={graphProps.graphData?.nodes ?? []}
        links={graphProps.graphData?.links ?? []}
        selectedKeys={NO_SELECTION}
        onSelectNode={(node) => onNodeClick?.(node, new MouseEvent('click'))}
        onSelectLink={(link) => onLinkClick?.(link, new MouseEvent('click'))}
        onActiveChange={setHovered}
      />
    </>
  );
};

export default SimpleGraph2D;
