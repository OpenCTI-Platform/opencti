import { SimplePaletteColorOptions } from '@mui/material';
import { useTheme } from '@mui/styles';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent, MutableRefObject, useEffect, useRef } from 'react';
import { ForceGraphMethods, LinkObject, NodeObject } from 'react-force-graph-2d';
import type { Theme } from '../../Theme';
import { GraphLink, GraphNode } from '../graph.types';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles({
  canvas: {
    position: 'absolute',
    overflow: 'hidden',
    top: 0,
    left: 0,
  },
});

interface RelationSelectionProps {
  width: number;
  height: number;
  activated: boolean;
  setSelectedNodes: (nodes: Set<GraphNode>) => void;
  graphDataNodes: GraphNode[];
  graph: MutableRefObject<ForceGraphMethods<NodeObject<GraphNode>, LinkObject<GraphNode, GraphLink>> | undefined>;
}

type LineContext = CanvasRenderingContext2D & { reset: () => void };

const DISTANCE = 5;

/**
 * Right-button drag from one node to another: draws the gesture and selects its first and last
 * nodes to create a relationship between them. The gesture outlives the renders of the graph
 * (hover, cards, panels): its state and the latest props are kept in references, and the document
 * listeners are registered once while the gesture is available.
 */
const RelationSelection: FunctionComponent<RelationSelectionProps> = ({
  width,
  height,
  graphDataNodes,
  activated = false,
  setSelectedNodes,
  graph,
}) => {
  const classes = useStyles();
  const theme = useTheme<Theme>();
  const lineRef = useRef<HTMLCanvasElement>(null);
  const gesture = useRef({ freeHand: false, selectedNodes: new Set<GraphNode>() });
  const latest = useRef({ graphDataNodes, setSelectedNodes, theme });
  latest.current = { graphDataNodes, setSelectedNodes, theme };

  useEffect(() => {
    if (!activated) return undefined;
    const lineContext = () => lineRef.current?.getContext('2d') as LineContext | null | undefined;
    const strokeColor = () => (latest.current.theme.palette.success as SimplePaletteColorOptions)?.main ?? latest.current.theme.palette.common.white;
    // The canvas box and the pointer, both in viewport coordinates: a scrolled page offsets neither.
    const reposition = (event: MouseEvent) => {
      const { left, top } = lineRef.current?.getBoundingClientRect() ?? { left: 0, top: 0 };
      return { x: event.clientX - left, y: event.clientY - top };
    };
    // The canvases of this graph, the drawing and its overlays, share the parent of this one.
    const isGraphCanvas = (target: EventTarget | null) => target instanceof HTMLCanvasElement
      && !!lineRef.current?.parentElement?.contains(target);

    /** Adds the nodes under the pointer to the ones the drag passed over. */
    const pickNodesAt = (coord: { x: number; y: number }) => {
      if (!graph.current) return;
      const coords = graph.current.screen2GraphCoords(coord.x, coord.y);
      latest.current.graphDataNodes.forEach((node) => {
        if (Math.hypot(node.x - coords.x, node.y - coords.y) < DISTANCE) {
          gesture.current.selectedNodes.add(node);
        }
      });
    };

    const onMove = (event: MouseEvent) => {
      const ctx = lineContext();
      if (!gesture.current.freeHand || !graph.current || !ctx) return;
      const coord = reposition(event);
      ctx.lineTo(coord.x, coord.y);
      pickNodesAt(coord);
      ctx.stroke();
    };

    const onDown = (event: MouseEvent) => {
      const ctx = lineContext();
      ctx?.reset();
      if (!isGraphCanvas(event.target) || !ctx) {
        return;
      }
      if (event.button !== 2) {
        document.removeEventListener('mousemove', onMove);
        return;
      }
      event.stopPropagation();
      event.preventDefault();
      document.addEventListener('mousemove', onMove);
      gesture.current.freeHand = true;
      gesture.current.selectedNodes.clear();
      const coord = reposition(event);
      // The node under the press starts the relationship, however far the first move lands.
      pickNodesAt(coord);
      ctx.lineWidth = 1;
      ctx.setLineDash([1, 3]);
      ctx.lineCap = 'round';
      ctx.strokeStyle = strokeColor();
      ctx.beginPath();
      ctx.moveTo(coord.x, coord.y);
    };

    // Only the release of a right-button drag in progress is this gesture's, wherever it happens;
    // every other release on the page goes on untouched.
    const onUp = (event: MouseEvent) => {
      if (!gesture.current.freeHand || event.button !== 2) return;
      event.stopPropagation();
      event.preventDefault();
      document.removeEventListener('mousemove', onMove);
      gesture.current.freeHand = false;
      const ctx = lineContext();
      if (!ctx) return;
      ctx.closePath();
      ctx.setLineDash([]);
      ctx.reset();
      const nodes = Array.from(gesture.current.selectedNodes);
      const firstNode = nodes.at(0);
      const lastNode = nodes.at(-1);
      if (nodes.length < 2 || !firstNode || !lastNode || !graph.current) {
        return;
      }
      const firstNodeCoords = graph.current.graph2ScreenCoords(firstNode.x, firstNode.y);
      const lastNodeCoords = graph.current.graph2ScreenCoords(lastNode.x, lastNode.y);
      ctx.beginPath();
      ctx.strokeStyle = strokeColor();
      ctx.moveTo(firstNodeCoords.x, firstNodeCoords.y);
      ctx.lineTo(lastNodeCoords.x, lastNodeCoords.y);
      ctx.stroke();
      ctx.closePath();
      latest.current.setSelectedNodes(new Set([firstNode, lastNode]));
    };

    // The right button drags over the graph only: the rest of the page keeps its context menu.
    const onContextMenu = (event: MouseEvent) => {
      if (isGraphCanvas(event.target)) event.preventDefault();
    };

    document.addEventListener('mousedown', onDown);
    document.addEventListener('mouseup', onUp);
    document.addEventListener('contextmenu', onContextMenu);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('mouseup', onUp);
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('contextmenu', onContextMenu);
      gesture.current.freeHand = false;
    };
  }, [activated, graph]);

  return (
    <canvas
      ref={lineRef}
      width={(width - 30)}
      height={height}
      className={classes.canvas}
      id="relation-canvas"
    />
  );
};

export default RelationSelection;
