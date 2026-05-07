import type { FilterGroup } from '../../../generated/graphql';
import { ENTITY_TYPE_STATUS, ENTITY_TYPE_STATUS_TEMPLATE } from '../../../schema/internalObject';
import type { BasicStoreIdentifier, BasicWorkflowStatus, BasicWorkflowTemplateEntity } from '../../../types/store';

export const isEntityStatus
  = (entity: BasicStoreIdentifier): entity is BasicWorkflowStatus => entity.entity_type === ENTITY_TYPE_STATUS;

export const isEntityStatusTemplate
  = (entity: BasicStoreIdentifier): entity is BasicWorkflowTemplateEntity => entity.entity_type === ENTITY_TYPE_STATUS_TEMPLATE;

export const ENTITY_TYPE_WORKFLOW_DEFINITION = 'WorkflowDefinition';
export const ENTITY_TYPE_WORKFLOW_INSTANCE = 'WorkflowInstance';

/**
 * Execution Engine Types
 */

/**
 * Represents a status or position in the workflow graph.
 */
export type State = string;

/**
 * Represents a trigger that initiates a transition between states.
 */
export type Event = string;

/**
 * A slot tracking one async background action spawned during a pending transition.
 */
export interface AsyncActionSlot {
  id: string;        // UUID generated at trigger time; also stored on the BackgroundTask
  workId: string;    // The Work entity id for live progress lookup
  type: string;      // e.g. 'asyncBulkAction'
  status: 'pending' | 'success' | 'failed';
}

/**
 * The full pending-transition record persisted on WorkflowInstance while async tasks run.
 */
export interface WorkflowPendingTransition {
  event: string;
  toState: string;
  triggeredBy: string;
  triggeredAt: string;  // ISO 8601
  runtimeParams: Record<string, unknown>;
  asyncActions: AsyncActionSlot[];
  syncActions: WorkflowActionConfig[];
}

/**
 * Information available during workflow execution (conditions and side effects).
 */
export interface Context {
  user?: any;
  entity?: any;
  context?: any;
  /** Mutable accumulator: asyncBulkAction pushes slots here; engine reads them after phase 1. */
  pendingAsyncSlots?: AsyncActionSlot[];
  [key: string]: any;
}

/**
 * Functional guard that must return true for a transition to be valid.
 */
export type ConditionValidator<TContext extends Context = Context> = (
  context: TContext,
) => boolean | Promise<boolean>;

/**
 * Side effect executed during state entry, exit, or transition.
 */
export type SideEffect<TContext extends Context = Context> = (
  context: TContext,
) => void | Promise<void>;

/**
 * Definition of a path between two states.
 */
export interface Transition<TContext extends Context = Context> {
  from: State;
  to: State;
  event: Event;
  conditions?: ConditionValidator<TContext>[];
  /** Phase 1: async effects (background tasks). State does NOT advance until all succeed. */
  asyncSideEffects?: SideEffect<TContext>[];
  /** Phase 2: sync effects run after all async succeed (or immediately if no async). */
  onTransition?: SideEffect<TContext>[];
  actionTypes?: string[];
  requiresOrganizationInput?: boolean;
}

/**
 * Extended configuration for a specific state, including lifecycle hooks.
 */
export interface StateDefinition<TContext extends Context = Context> {
  name: State;
  onEnter?: SideEffect<TContext>[];
  onExit?: SideEffect<TContext>[];
}

/**
 * Abstract interface for a workflow definition provider.
 */
export interface MachineDefinition<TContext extends Context = Context> {
  getInitialState(): State;
  getTransition(
    currentState: State,
    event: Event
  ): Transition<TContext> | undefined;
  getTransitions(currentState: State): Transition<TContext>[];
  getStateDefinition(state: State): StateDefinition<TContext> | undefined;
}

/**
 * Result of a transition attempt.
 */
export interface TriggerResult {
  success: boolean;
  reason?: string;
  newState?: string;
  status?: any;
  instance?: any;
  entity?: any;
  /** Present when the transition spawned async background tasks. */
  executionStatus?: 'pending' | 'completed' | 'error';
  asyncActionSlots?: AsyncActionSlot[];
}

/**
 * Serialization models for the database
 */
export interface WorkflowActionConfig {
  type: string;
  params?: string;
  mode: 'sync' | 'async';
}

export interface WorkflowConditionConfig {
  field?: string;
  operator?: string;
  value?: any;
  type?: string;
}

export interface WorkflowSerializedState {
  statusId: string;
  onEnter?: WorkflowActionConfig[];
  onExit?: WorkflowActionConfig[];
}

export interface WorkflowSerializedTransition {
  from: string | string[];
  to: string;
  event: string;
  /** @deprecated Use syncActions instead. Kept for backward compatibility. */
  actions?: WorkflowActionConfig[];
  /** Phase 1: async background task actions. Run before syncActions. */
  asyncActions?: WorkflowActionConfig[];
  /** Phase 2: sync actions. Run after all asyncActions succeed (or immediately if no asyncActions). */
  syncActions?: WorkflowActionConfig[];
  conditions?: FilterGroup;
  requiresOrganizationInput?: boolean;
}

export interface WorkflowDefinitionData {
  initialState: string;
  states: WorkflowSerializedState[];
  transitions: WorkflowSerializedTransition[];
}
