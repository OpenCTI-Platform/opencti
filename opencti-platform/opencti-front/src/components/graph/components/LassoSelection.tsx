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
    const reposition = (event: MouseEvent) => {
      const { left, top } = lassoRef.current?.getBoundingClientRect() ?? { left: 0, top: 0 };
      return { x: event.pageX - left, y: event.pageY - top };
    };

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
      if ((event.target as HTMLElement | null)?.tagName !== 'CANVAS' || !ctx) {
        return;
      }
      if (event.button === 2) {
        document.removeEventListener('mousemove', onMove);
        return;
      }
      document.addEventListener('mousemove', onMove);
      gesture.current.freeHand = true;
      gesture.current.path = [];
      const coord = reposition(event);
      ctx.moveTo(coord.x, coord.y);
      ctx.lineWidth = 1;
      ctx.setLineDash([1, 3]);
      ctx.lineCap = 'round';
      ctx.strokeStyle = (latest.current.theme.palette.warning as SimplePaletteColorOptions)?.main ?? latest.current.theme.palette.common.white;
      ctx.beginPath();
    };

    const onUp = (event: MouseEvent) => {
      const ctx = lassoContext();
      if ((event.target as HTMLElement | null)?.tagName !== 'CANVAS' || !ctx) {
        return;
      }
      document.removeEventListener('mousemove', onMove);
      gesture.current.freeHand = false;
      ctx.closePath();
      const { path } = gesture.current;
      const selectedNodes = new Set(latest.current.graphDataNodes.filter((node) => pointInPolygon(path, [node.x, node.y])));
      gesture.current.path = [];
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
