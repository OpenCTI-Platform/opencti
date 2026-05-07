import type { FilterGroup, WorkflowActionMode } from '../../../generated/graphql';

/**
 * Serialized configuration for a side effect action.
 */
export interface ActionConfig {
  type: string;
  params?: any;
  mode: WorkflowActionMode;
}

/**
 * Serialized representation of a workflow state.
 * Tied to a global StatusTemplate entity.
 */
export interface SerializedState {
  statusId: string; // Refers to the internal ID of a StatusTemplate entity
  onEnter?: ActionConfig[];
  onExit?: ActionConfig[];
}

/**
 * Serialized representation of a transition between states.
 */
export interface SerializedTransition {
  from: string; // ID of the source StatusTemplate
  to: string; // ID of the destination StatusTemplate
  event: string;
  /** @deprecated Use syncActions instead. Kept for backward compatibility. */
  actions?: ActionConfig[];
  /** Phase 1: async background task actions. Run before syncActions. */
  asyncActions?: ActionConfig[];
  /** Phase 2: sync actions run after all asyncActions succeed (or immediately if none). */
  syncActions?: ActionConfig[];
  conditions?: { filters: FilterGroup };
  requiresOrganizationInput?: boolean;
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
