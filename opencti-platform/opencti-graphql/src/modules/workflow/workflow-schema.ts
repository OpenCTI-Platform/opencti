/**
 * Serialized configuration for a side effect action.
 */
export interface ActionConfig {
  type: string;
  params?: any;
  mode: 'sync' | 'async';
}

/**
 * Serialized configuration for a guard condition.
 */
export interface ConditionConfig {
  field: string;
  operator: 'eq' | 'neq' | 'gt' | 'lt' | 'gte' | 'lte' | 'contains';
  value: any;
}

/**
 * Serialized representation of a workflow state.
 */
export interface SerializedState {
  name: string;
  onEnter?: ActionConfig[];
  onExit?: ActionConfig[];
}

/**
 * Serialized representation of a transition between states.
 */
export interface SerializedTransition {
  from: string;
  to: string;
  event: string;
  actions?: ActionConfig[];
  conditions?: ConditionConfig[];
}

/**
 * Complete serialized schema of a workflow machine.
 * This structure is intended to be stored in the database.
 */
export interface WorkflowSchema {
  id: string;
  name: string;
  initialState: string;
  states: SerializedState[];
  transitions: SerializedTransition[];
}
