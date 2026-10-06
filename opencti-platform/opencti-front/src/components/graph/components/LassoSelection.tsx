import React, { FunctionComponent, MutableRefObject, useEffect, useRef } from 'react';
import { SimplePaletteColorOptions } from '@mui/material';
import { useTheme } from '@mui/styles';
import makeStyles from '@mui/styles/makeStyles';
import { ForceGraphMethods, LinkObject, NodeObject } from 'react-force-graph-2d';
import type { Theme } from '../../Theme';
import { GraphLink, GraphNode } from '../graph.types';
import { pointInPolygon } from '../utils/graphUtils';

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

interface LassoSelectionProps {
  width: number;
  height: number;
  activated: boolean;
  setSelectedNodes: (nodes: Set<GraphNode>) => void;
  graphDataNodes: GraphNode[];
  graph: MutableRefObject<ForceGraphMethods<NodeObject<GraphNode>, LinkObject<GraphNode, GraphLink>> | undefined>;
}

type LassoContext = CanvasRenderingContext2D & { reset: () => void };

/**
 * Free-shape selection: the left-button path drawn over the canvas selects the nodes it encloses.
 * The gesture outlives the renders of the graph (hover, cards, panels): its state and the latest
 * props are kept in references, and the document listeners are registered once while the tool is on.
 */
const LassoSelection: FunctionComponent<LassoSelectionProps> = ({
  width,
  height,
  graphDataNodes,
  activated = false,
  setSelectedNodes,
  graph,
}) => {
  const classes = useStyles();
  const theme = useTheme<Theme>();
  const lassoRef = useRef<HTMLCanvasElement>(null);
  const gesture = useRef<{ freeHand: boolean; path: number[][] }>({ freeHand: false, path: [] });
  const latest = useRef({ graphDataNodes, setSelectedNodes, theme });
  latest.current = { graphDataNodes, setSelectedNodes, theme };

  useEffect(() => {
    if (!activated) return undefined;
    const lassoContext = () => lassoRef.current?.getContext('2d') as LassoContext | null | undefined;
    // The canvas box and the pointer, both in viewport coordinates: a scrolled page offsets neither.
    const reposition = (event: MouseEvent) => {
      const { left, top } = lassoRef.current?.getBoundingClientRect() ?? { left: 0, top: 0 };
      return { x: event.clientX - left, y: event.clientY - top };
    };
    // The canvases of this graph, the drawing and its overlays, share the parent of this one.
    const isGraphCanvas = (target: EventTarget | null) => target instanceof HTMLCanvasElement
      && !!lassoRef.current?.parentElement?.contains(target);

    const onMove = (event: MouseEvent) => {
      const ctx = lassoContext();
      if (!gesture.current.freeHand || !graph.current || !ctx) return;
      const coord = reposition(event);
      ctx.lineTo(coord.x, coord.y);
      const coords = graph.current.screen2GraphCoords(coord.x, coord.y);
      gesture.current.path.push([coords.x, coords.y]);
      ctx.stroke();
    };

    const onDown = (event: MouseEvent) => {
      const ctx = lassoContext();
      if (!isGraphCanvas(event.target) || !ctx) {
        return;
      }
      if (event.button !== 0) {
        document.removeEventListener('mousemove', onMove);
        return;
      }
      document.addEventListener('mousemove', onMove);
      gesture.current.freeHand = true;
      const coord = reposition(event);
      // The path starts where the button is pressed, not at the first move reported after it.
      const origin = graph.current?.screen2GraphCoords(coord.x, coord.y);
      gesture.current.path = origin ? [[origin.x, origin.y]] : [];
      ctx.moveTo(coord.x, coord.y);
      ctx.lineWidth = 1;
      ctx.setLineDash([1, 3]);
      ctx.lineCap = 'round';
      ctx.strokeStyle = (latest.current.theme.palette.warning as SimplePaletteColorOptions)?.main ?? latest.current.theme.palette.common.white;
      ctx.beginPath();
    };

    // The path is followed over the whole document: the gesture ends wherever the button is released.
    const onUp = () => {
      if (!gesture.current.freeHand) return;
      document.removeEventListener('mousemove', onMove);
      gesture.current.freeHand = false;
      const { path } = gesture.current;
      gesture.current.path = [];
      const ctx = lassoContext();
      if (!ctx) return;
      ctx.closePath();
      const selectedNodes = new Set(latest.current.graphDataNodes.filter((node) => pointInPolygon(path, [node.x, node.y])));
      ctx.setLineDash([]);
      ctx.reset();
      latest.current.setSelectedNodes(selectedNodes);
    };

    document.addEventListener('mousedown', onDown);
    document.addEventListener('mouseup', onUp);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('mouseup', onUp);
      document.removeEventListener('mousemove', onMove);
      gesture.current.freeHand = false;
    };
  }, [activated, graph]);

  return (
    <canvas
      ref={lassoRef}
      width={(width - 30)}
      height={height}
      className={classes.canvas}
      id="lasso-canvas"
    />
  );
};

export default LassoSelection;
