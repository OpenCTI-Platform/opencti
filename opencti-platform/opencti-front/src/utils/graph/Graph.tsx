import ForceGraph2D from 'react-force-graph-2d';
import React, { type MutableRefObject } from 'react';
import { GraphProvider } from './utils/GraphContext';
import useResizeObserver from '../hooks/useResizeObserver';
import GraphToolbar from './components/GraphToolbar';
import type { GraphState } from './graph.types';

const DEFAULT_STATE: GraphState = {
  mode3D: false,
  modeTree: null,
  withForces: true,
  selectFreeRectangle: false,
  selectFree: false,
  selectRelationshipMode: null,
  showTimeRange: false,
};

interface GraphProps {
  containerRef: MutableRefObject<HTMLDivElement | null>
}

const Graph = ({
  containerRef,
}: GraphProps) => {
  const { width, height } = useResizeObserver(containerRef);

  return (
    <GraphProvider defaultState={DEFAULT_STATE}>
      <ForceGraph2D
        width={width}
        height={height}
      />
      <GraphToolbar />
    </GraphProvider>
  );
};

export default Graph;
