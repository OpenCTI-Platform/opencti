import type { ActionConfig, ConditionConfig, WorkflowSchema } from './workflow-schema';
import { ActionRegistry } from './workflow-actions';
import { ConditionRegistry } from './workflow-conditions';
import type { ConditionValidator, Context, SideEffect } from './workflow-types';
import { WorkflowDefinition } from './workflow-definition';
import { WorkflowInstance } from './workflow-instance';

/**
 * Utility factory to create workflow definitions and instances from various sources.
 * Handles the mapping between JSON configuration (schemas) and executable logic.
 */
export class WorkflowFactory {
  // Helper to access nested properties: "user.role" -> ctx.user.role
  private static getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((acc, part) => acc && acc[part], obj);
  }

  /**
   * Translates a list of condition configurations into executable validator functions.
   */
  public static createConditions<TContext extends Context>(configs?: ConditionConfig[]): ConditionValidator<TContext>[] {
    if (!configs || configs.length === 0) return [];

    return configs.map((config) => {
      // 1. Check if it's a named condition from registry
      if (config.type) {
        const conditionFn = ConditionRegistry[config.type];
        if (!conditionFn) {
          // eslint-disable-next-line no-console
          console.warn(`Condition type '${config.type}' not found in registry.`);
          return () => true; // Default to true if not found to avoid blocking
        }
        return (ctx: TContext) => conditionFn(ctx, config.params);
      }

      // 2. Otherwise it's a field comparison
      return (ctx: TContext) => {
        if (!config.field || !config.operator) return true;

        const actualValue = this.getNestedValue(ctx, config.field);

        switch (config.operator) {
          case 'eq': return actualValue == config.value;
          case 'neq': return actualValue != config.value;
          case 'gt': return actualValue > config.value;
          case 'gte': return actualValue >= config.value;
          case 'lt': return actualValue < config.value;
          case 'lte': return actualValue <= config.value;
          case 'contains':
            return Array.isArray(actualValue)
              ? actualValue.includes(config.value)
              : String(actualValue).includes(String(config.value));
          default:
            // eslint-disable-next-line no-console
            console.error(`Unknown operator '${config.operator}'`);
            return false;
        }
      };
    });
  }

  /**
   * Translates a list of action configurations into executable side effect functions.
   */
  public static createSideEffects<TContext extends Context>(configs?: ActionConfig[]): SideEffect<TContext>[] {
    if (!configs || configs.length === 0) return [];

    return configs.map((config) => {
      const actionFn = ActionRegistry[config.type];
      if (!actionFn) {
        // eslint-disable-next-line no-console
        console.warn(`Action type '${config.type}' not found in registry.`);
        return async () => {};
      }

      return async (ctx: TContext) => {
        if (config.mode === 'async') {
          // Fire and forget
          Promise.resolve(actionFn(ctx, config.params)).catch((err: any) =>
            // eslint-disable-next-line no-console
            console.error(`Async action '${config.type}' failed`, err)
          );
        } else {
          // Await completion
          await actionFn(ctx, config.params);
        }
      };
    });
  }

  /**
   * Creates a stateless WorkflowDefinition from a serialized schema.
   */
  static createDefinition<TContext extends Context>(schema: WorkflowSchema): WorkflowDefinition<TContext> {
    const definition = new WorkflowDefinition<TContext>(schema.initialState);

    schema.states.forEach((state) => {
      definition.addState(state.name, {
        onEnter: this.createSideEffects<TContext>(state.onEnter),
        onExit: this.createSideEffects<TContext>(state.onExit),
      });
    });

    schema.transitions.forEach((t) => {
      definition.addTransition(t.from, t.to, t.event, {
        conditions: this.createConditions<TContext>(t.conditions),
        onTransition: this.createSideEffects<TContext>(t.actions),
      });
    });

    return definition;
  }

  /**
   * Resolves and returns a WorkflowInstance from either a schema or a pre-defined definition.
   * @param schema Serialized database configuration.
   * @param defaultDefinition Fallback definition if no schema is provided.
   * @param currentState The persistent state of the entity.
   * @param context Execution context for conditions and actions.
   */
  static getInstance<TContext extends Context>(
    schema: WorkflowSchema | undefined,
    defaultDefinition: WorkflowDefinition<TContext> | undefined,
    currentState: string,
    context: TContext,
  ): WorkflowInstance<TContext> {
    let definition = defaultDefinition;

    if (schema) {
      definition = this.createDefinition<TContext>(schema);
    }

    if (!definition) {
      throw new Error('No workflow definition provided');
    }

    return new WorkflowInstance<TContext>(definition, currentState, context);
  }
}
