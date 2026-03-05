import type { ConditionValidator, Context, Event, SideEffect, State, StateDefinition, Transition } from '../types/workflow-types';

/**
 * Represents a stateless definition of a workflow graph.
 * Defines states, transitions, guard conditions, and side effects.
 */
export class WorkflowDefinition<TContext extends Context = Context> {
  private states: Map<State, StateDefinition<TContext>> = new Map();
  private transitions: Transition<TContext>[] = [];
  private initialState: State;

  /**
   * Initializes a new workflow definition with a mandatory initial state.
   */
  constructor(initialState: State) {
    this.initialState = initialState;
    this.addState(initialState);
  }

  /**
   * Adds a new state to the workflow.
   */
  addState(name: State, definition?: Omit<StateDefinition<TContext>, 'name'>) {
    this.states.set(name, { name, ...definition });
    return this;
  }

  /**
   * Checks if a state exists in the definition.
   */
  hasState(name: State): boolean {
    return this.states.has(name);
  }

  /**
   * Defines a directed transition between two states triggered by an event.
   */
  addTransition(
    from: State,
    to: State,
    event: Event,
    options?: {
      conditions?: ConditionValidator<TContext>[];
      onTransition?: SideEffect<TContext>[];
    },
  ) {
    // Ensure states exist
    if (!this.states.has(from)) this.addState(from);
    if (!this.states.has(to)) this.addState(to);

    this.transitions.push({
      from,
      to,
      event,
      conditions: options?.conditions || [],
      onTransition: options?.onTransition || [],
    });
    return this;
  }

  /**
   * Returns the initial state of the workflow.
   */
  public getInitialState(): State {
    return this.initialState;
  }

  /**
   * Searches for a valid transition from a current state given a specific event.
   */
  public getTransition(
    currentState: State,
    event: Event,
  ): Transition<TContext> | undefined {
    return this.transitions.find(
      (t) => t.from === currentState && t.event === event,
    );
  }

  /**
   * Returns all possible transitions outgoing from a specific state.
   */
  public getTransitions(currentState: State): Transition<TContext>[] {
    return this.transitions.filter((t) => t.from === currentState);
  }

  /**
   * Retrieves the definition (hooks, etc.) for a specific state.
   */
  public getStateDefinition(
    state: State,
  ): StateDefinition<TContext> | undefined {
    return this.states.get(state);
  }
}
