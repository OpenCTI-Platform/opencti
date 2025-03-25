import { SimplePaletteColorOptions } from '@mui/material';
import { useTheme } from '@mui/styles';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent, MutableRefObject, useCallback, useEffect, useRef } from 'react';
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
  width: number
  height: number
  activated: boolean
  setSelectedNodes: (nodes: Set<GraphNode>) => void
  graphDataNodes: GraphNode[]
  graph: MutableRefObject<ForceGraphMethods<NodeObject<GraphNode>, LinkObject<GraphNode, GraphLink>> | undefined>
}

interface Coord {
  x: number,
  y: number
}

interface ContextHandlerProps {
  ctx?: CanvasRenderingContext2D | null
  coord?: Coord
  freeHand?: boolean
  freePathCoords?: Coord[]
  selectedNodes?: Set<GraphNode>
  graphDataNodes?: GraphNode[]
  canvas?: HTMLCanvasElement
  theme?: Theme
  setSelectedNodes?: (nodes: Set<GraphNode>) => void
  activated?: boolean
  storeFreeSelectionFunction?: (event: MouseEvent) => void
  graph?: MutableRefObject<ForceGraphMethods<NodeObject<GraphNode>, LinkObject<GraphNode, GraphLink>> | undefined>
}

const DISTANCE = 5;

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

  let currentContext = lineRef.current?.getContext('2d') as CanvasRenderingContext2D & { reset: () => void };

  const contextHandler = useRef<ContextHandlerProps>({});

  const reposition = (event: MouseEvent) => {
    const { left, top } = lineRef.current?.getBoundingClientRect() ?? { left: 0, top: 0 };
    return { x: event.pageX - left, y: event.pageY - top };
  };

  let freeHand = false;
  let coord = { x: 0, y: 0 };
  let freePathCoords: number[][] = [];
  const selectedNodes = new Set<GraphNode>();

  const startFreeHand = (e: MouseEvent, mouseMoveFunction: (e: MouseEvent) => void) => {
    currentContext.reset();
    if ((e.target as HTMLDivElement)?.tagName !== 'CANVAS' || !currentContext) {
      return;
    }
    if (e.button !== 2) {
      document.removeEventListener('mousemove', mouseMoveFunction);
      return;
    }
    e.stopPropagation();
    e.preventDefault();
    document.addEventListener('mousemove', mouseMoveFunction);
    freeHand = true;
    coord = reposition(e);
    currentContext.moveTo(coord.x, coord.y);
    currentContext.lineWidth = 1;
    currentContext.setLineDash([1, 3]);
    currentContext.lineCap = 'round';
    currentContext.strokeStyle = (theme.palette.success as SimplePaletteColorOptions)?.main ?? theme.palette.common.white;
    currentContext.beginPath();
    selectedNodes.clear();
  };

  const stopFreeHand = (e: MouseEvent, mouseMoveFunction: (e: MouseEvent) => void) => {
    e.stopPropagation();
    e.preventDefault();
    if ((e.target as HTMLDivElement)?.tagName !== 'CANVAS' || !currentContext) {
      return;
    }
    if (e.button !== 2) {
      document.removeEventListener('mousemove', mouseMoveFunction);
      return;
    }
    document.removeEventListener('mousemove', mouseMoveFunction);
    freeHand = false;
    currentContext.closePath();
    freePathCoords = [];
    currentContext.setLineDash([]);
    currentContext.reset();
    if (selectedNodes.size > 1) {
      const firstNode = Array.from(selectedNodes).at(0);
      const lastNode = Array.from(selectedNodes).at(-1);

      if (!firstNode || !lastNode || !graph.current) {
        return;
      }
      const firstNodeCoords: Coord = graph.current.graph2ScreenCoords(firstNode.x, firstNode.y);
      const lastNodeCoords: Coord = graph.current.graph2ScreenCoords(lastNode.x, lastNode.y);

      currentContext.beginPath();
      currentContext.strokeStyle = (theme.palette.success as SimplePaletteColorOptions)?.main ?? theme.palette.common.white;
      coord = reposition(e);
      currentContext.moveTo(firstNodeCoords.x, firstNodeCoords.y);
      currentContext.lineTo(lastNodeCoords.x, lastNodeCoords.y);
      currentContext.stroke();
      currentContext.closePath();

      setSelectedNodes(new Set([firstNode, lastNode]));
    }
  };

  const storeFreeSelection = (e: MouseEvent) => {
    if (freeHand && activated && graph.current) {
      coord = reposition(e);
      currentContext.lineTo(coord.x, coord.y);
      const { left, top } = lineRef.current?.getBoundingClientRect() ?? { left: 0, top: 0 };
      const coords: Coord = graph.current.screen2GraphCoords(e.pageX - left, e.pageY - top);
      graphDataNodes?.forEach((g) => {
        const a = g.x - coords.x;
        const b = g.y - coords.y;
        const c = Math.sqrt(a * a + b * b);
        if (c < DISTANCE) {
          selectedNodes.add(g);
        }
      });
      freePathCoords.push([coords.x, coords.y]);
      currentContext.stroke();
    }
  };

  const storeFreeSelectionFunction = useCallback((event: MouseEvent) => {
    storeFreeSelection(event);
  }, [graph, activated, graphDataNodes]);
  const stopFreeHandFunction = useCallback((event: MouseEvent) => {
    stopFreeHand(event, storeFreeSelectionFunction);
  }, [graph, activated, graphDataNodes]);
  const startFreeHandFunction = useCallback((event: MouseEvent) => {
    startFreeHand(event, storeFreeSelectionFunction);
  }, [graph, activated, graphDataNodes]);

  const contextEvent = useCallback((e: MouseEvent) => e.preventDefault(), []);
  useEffect(() => {
    if (lineRef.current) {
      contextHandler.current = {
        ctx: currentContext,
        coord: { x: 0, y: 0 },
        freeHand: false,
        freePathCoords: [],
        selectedNodes: new Set(),
        graphDataNodes,
        canvas: lineRef.current,
        theme,
        setSelectedNodes,
        activated,
        storeFreeSelectionFunction,
        graph,
      };
      currentContext = lineRef.current?.getContext('2d') as CanvasRenderingContext2D & { reset: () => void };
    }
    if (activated) {
      document.addEventListener('mousedown', startFreeHandFunction);
      document.addEventListener('mouseup', stopFreeHandFunction);
      document.addEventListener('contextmenu', contextEvent);
    } else {
      document.removeEventListener('mousedown', startFreeHandFunction);
      document.removeEventListener('mouseup', stopFreeHandFunction);
      document.removeEventListener('mousemove', storeFreeSelectionFunction);
    }
    return () => {
      document.removeEventListener('mousedown', startFreeHandFunction);
      document.removeEventListener('mouseup', stopFreeHandFunction);
      document.removeEventListener('mousemove', storeFreeSelectionFunction);
      document.removeEventListener('contextmenu', contextEvent);
    };
  }, [activated, graphDataNodes, graph]);

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
