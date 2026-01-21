import type { Context, Event, MachineDefinition, State, TriggerResult } from './workflow-types';

/**
 * Stateful execution engine for a workflow definition.
 * Manages the current state and handles event triggering.
 */
export class StateMachine<TContext extends Context = Context> {
  protected definition: MachineDefinition<TContext>;
  protected currentState: State;
  protected context: TContext;

  /**
   * Creates an instance of a state machine.
   * @param definition The workflow configuration graph.
   * @param initialState Optional starting state (defaults to definition's initial state).
   * @param context Context used for condition validation and side effects.
   */
  constructor(
    definition: MachineDefinition<TContext>,
    initialState: State | undefined,
    context: TContext
  ) {
    this.definition = definition;
    this.context = context;
    this.currentState = initialState || definition.getInitialState();
  }

  /**
   * Returns the current state of the machine.
   */
  public getCurrentState(): State {
    return this.currentState;
  }

  /**
   * Returns the context attached to this machine execution.
   */
  public getContext(): TContext {
    return this.context;
  }

  /**
   * Lists all events that can be triggered from the current state.
   */
  public getAvailableEvents(): Event[] {
    const transitions = this.definition.getTransitions(this.currentState);
    return transitions.map((t) => t.event);
  }

  /**
   * Attempts to transition to a new state by triggering an event.
   * This involves:
   * 1. Validating guard conditions.
   * 2. Executing 'onExit' hooks of the current state.
   * 3. Executing 'onTransition' side effects.
   * 4. Updating the internal state.
   * 5. Executing 'onEnter' hooks of the new state.
   * @returns a TriggerResult object indicating success or failure with a reason.
   */
  public async trigger(event: Event): Promise<TriggerResult> {
    const transition = this.definition.getTransition(this.currentState, event);

    if (!transition) {
      const reason = `No transition found from state '${this.currentState}' on event '${event}'`;
      // eslint-disable-next-line no-console
      console.warn(reason);
      return { success: false, reason };
    }

    // Check conditions
    if (transition.conditions) {
      for (const condition of transition.conditions) {
        const isValid = await condition(this.context);
        if (!isValid) {
          const reason = `Condition failed for transition '${event}'`;
          // eslint-disable-next-line no-console
          console.error(reason);
          return { success: false, reason };
        }
      }
    }

    // Execute onExit of current state
    const currentStateDef = this.definition.getStateDefinition(this.currentState);
    if (currentStateDef?.onExit) {
      for (const hook of currentStateDef.onExit) {
        await hook(this.context);
      }
    }

    // Execute transition side effects
    if (transition.onTransition) {
      for (const effect of transition.onTransition) {
        await effect(this.context);
      }
    }

    // Update state
    this.currentState = transition.to;

    // Execute onEnter of new state
    const newStateDef = this.definition.getStateDefinition(this.currentState);
    if (newStateDef?.onEnter) {
      for (const hook of newStateDef.onEnter) {
        await hook(this.context);
      }
    }

    return { success: true };
  }
}
