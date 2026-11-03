import { createContext } from 'react';

export interface EdgeRef {
  id: string;
  source: string;
  target: string;
}

// Actions the edge menu triggers. Workflow provides them, because opening the drawer and
// changing the graph live there; edges reach them without props going through React Flow.
export interface WorkflowEdgeActions {
  insertStatus: (edge: EdgeRef) => void;
  deleteConnection: (edgeId: string) => void;
}

const noop = () => {};

export const WorkflowEdgeActionsContext = createContext<WorkflowEdgeActions>({ insertStatus: noop, deleteConnection: noop });
