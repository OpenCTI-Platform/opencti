import { StateMachine } from './workflow-engine';
import type { Context, Event, State, TriggerResult } from './workflow-types';

/**
 * Audit record of a state transition attempt.
 */
export interface TransitionRecord {
  from: State;
  to: State;
  event: Event;
  date: Date;
  success: boolean;
  reason?: string;
}

/**
 * A specific execution instance of a workflow, including history tracking.
 * This class extends StateMachine with persistence-ready audit logs.
 */
export class WorkflowInstance<TContext extends Context = Context> extends StateMachine<TContext> {
  private history: TransitionRecord[] = [];

  /**
   * Triggers an event and records the transition attempt in the instance history.
   */
  public async trigger(event: Event): Promise<TriggerResult> {
    const from = this.currentState;
    const result = await super.trigger(event);

    this.history.push({
      from,
      to: this.currentState,
      event,
      date: new Date(),
      success: result.success,
      reason: result.reason,
    });
    
    return result;
  }

  /**
   * Returns the complete history of transitions for this instance.
   */
  public getHistory(): TransitionRecord[] {
    return this.history;
  }

  /**
   * Checks if an event can potentially be triggered from the current state (without running conditions).
   */
  public canTransition(event: Event): boolean {
    const transition = this.definition.getTransition(this.currentState, event);
    return !!transition;
  }

  // TODO: add DB persistence of the workflow instance
}
