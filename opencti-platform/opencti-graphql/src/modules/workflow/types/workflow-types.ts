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
 * Information available during workflow execution (conditions and side effects).
 */
export interface Context {
  user?: any;
  entity?: any;
  context?: any;
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
  onTransition?: SideEffect<TContext>[];
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
  name: string;
  onEnter?: WorkflowActionConfig[];
  onExit?: WorkflowActionConfig[];
}

export interface WorkflowSerializedTransition {
  from: string;
  to: string;
  event: string;
  actions?: WorkflowActionConfig[];
  conditions?: WorkflowConditionConfig[];
}

export interface WorkflowDefinitionData {
  initialState: string;
  states: WorkflowSerializedState[];
  transitions: WorkflowSerializedTransition[];
}
