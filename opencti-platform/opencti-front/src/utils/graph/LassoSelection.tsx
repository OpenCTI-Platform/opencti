import { SimplePaletteColorOptions } from '@mui/material';
import { useTheme } from '@mui/styles';
import makeStyles from '@mui/styles/makeStyles';
import { FunctionComponent, MutableRefObject, useCallback, useEffect, useRef } from 'react';
import { ForceGraphMethods } from 'react-force-graph-2d';
import { Theme } from '../../components/Theme';
import { pointInPolygon } from '../Graph';

const useStyles = makeStyles({
  canvas: {
    position: 'absolute',
    overflow: 'hidden',
  },
});

interface LassoSelectionProps {
  width: number
  height: number
  activated: boolean
  setSelectedNodes: (nodes: Set<Coord>) => void
  graphDataNodes: Coord[]
  graph: MutableRefObject<ForceGraphMethods>
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
  selectedNodes?: Set<Coord>
  graphDataNodes?: Coord[]
  canvas?: HTMLCanvasElement
  theme?: Theme
  setSelectedNodes?: (nodes: Set<Coord>) => void
  activated?: boolean
  storeFreeSelectionFunction?: (event: MouseEvent) => void
  graph?: MutableRefObject<ForceGraphMethods>
}

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

  const currentContext = lassoRef.current?.getContext('2d') as CanvasRenderingContext2D & { reset: () => void };

  const contextHandler = useRef<ContextHandlerProps>({});

  const reposition = (event: MouseEvent) => {
    const { left, top } = lassoRef.current?.getBoundingClientRect() ?? { left: 0, top: 0 };
    return { x: event.pageX - left, y: event.pageY - top };
  };

  let freeHand = false;
  let coord = { x: 0, y: 0 };
  let freePathCoords: number[][] = [];
  const selectedNodes = new Set<Coord>();

  const startFreeHand = (e: MouseEvent, mouseMoveFunction: (e: MouseEvent) => void) => {
    e.stopPropagation();
    e.preventDefault();
    if ((e.target as HTMLDivElement)?.tagName !== 'CANVAS' || !currentContext) {
      return;
    }
    document.addEventListener('mousemove', mouseMoveFunction);
    freeHand = true;
    coord = reposition(e);
    currentContext.moveTo(coord.x, coord.y);
    currentContext.lineWidth = 1;
    currentContext.setLineDash([1, 3]);
    currentContext.lineCap = 'round';
    currentContext.strokeStyle = (theme.palette.warning as SimplePaletteColorOptions)?.main ?? theme.palette.common.white;
    currentContext.beginPath();
  };

  const stopFreeHand = (e: MouseEvent, mouseMoveFunction: (e: MouseEvent) => void) => {
    e.stopPropagation();
    e.preventDefault();
    if ((e.target as HTMLDivElement)?.tagName !== 'CANVAS' || !currentContext) {
      return;
    }
    document.removeEventListener('mousemove', mouseMoveFunction);
    freeHand = false;
    currentContext.closePath();
    selectedNodes.clear();
    graphDataNodes?.forEach((g) => {
      if (pointInPolygon(freePathCoords, [g.x, g.y])) {
        selectedNodes.add(g);
      }
    });
    freePathCoords = [];
    currentContext.setLineDash([]);
    currentContext.reset();
    setSelectedNodes(selectedNodes);
  };

  const storeFreeSelection = (e: MouseEvent) => {
    if (freeHand && activated) {
      coord = reposition(e);
      currentContext.lineTo(coord.x, coord.y);
      const { left, top } = lassoRef.current?.getBoundingClientRect() ?? { left: 0, top: 0 };
      const coords: Coord = graph.current.screen2GraphCoords(e.pageX - left, e.pageY - top);
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

  useEffect(() => {
    if (lassoRef.current) {
      contextHandler.current = {
        ctx: currentContext,
        coord: { x: 0, y: 0 },
        freeHand: false,
        freePathCoords: [],
        selectedNodes: new Set(),
        graphDataNodes,
        canvas: lassoRef.current,
        theme,
        setSelectedNodes,
        activated,
        storeFreeSelectionFunction,
        graph,
      };
    }
    if (activated) {
      document.addEventListener('mousedown', startFreeHandFunction);
      document.addEventListener('mouseup', stopFreeHandFunction);
    } else {
      document.removeEventListener('mousedown', startFreeHandFunction);
      document.removeEventListener('mouseup', stopFreeHandFunction);
      document.removeEventListener('mousemove', storeFreeSelectionFunction);
    }
    return () => {
      document.removeEventListener('mousedown', startFreeHandFunction);
      document.removeEventListener('mouseup', stopFreeHandFunction);
      document.removeEventListener('mousemove', storeFreeSelectionFunction);
    };
  }, [activated, graphDataNodes, graph]);

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
