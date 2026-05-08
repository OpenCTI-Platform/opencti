import { ActionRegistry } from '../registry/workflow-actions';
import type { ActionConfig, WorkflowSchema } from './workflow-schema';
import type { ConditionValidator, Context, SideEffect } from '../types/workflow-types';
import { WorkflowDefinition } from './workflow-definition';
import { WorkflowInstance } from './workflow-instance';
import { FilterMode, FilterOperator, type Filter, type FilterGroup } from '../../../generated/graphql';

/**
 * Utility factory to create workflow definitions and instances from various sources.
 * Handles the mapping between JSON configuration (schemas) and executable logic.
 */
export class WorkflowFactory {
  // Helper to access nested properties: "workflow_role" -> ctx.user.role
  private static getNestedValue(ctx: any, key: string): string | string[] {
    if (key === 'workflow_group') {
      return ((ctx as any)?.user?.groups || []).map((g: any) => g.id);
    } else if (key === 'workflow_organization') {
      return ((ctx as any)?.user?.organizations || []).map((o: any) => o.id);
    } else if (key === 'workflow_role') {
      return ((ctx as any)?.user?.roles || []).map((r: any) => r.name);
    } else if (key === 'workflow_user') {
      return ((ctx as any)?.user?.id || ((ctx as any)?.user?.internal_id) || null);
    } else if (key === 'name') {
      return ctx.entity.name;
    } else {
      return key.split('.').reduce((acc, part) => acc && acc[part], ctx);
    }
  }

  /**
   * Translates a list of condition configurations into executable validator functions.
   */
  public static createConditions<TContext extends Context>(configs?: { filters: FilterGroup }): ConditionValidator<TContext>[] {
    const { filters } = configs || {};
    if (!filters) return [];

    // We return a single validator that evaluates the entire recursive tree
    const rootValidator = async (ctx: TContext): Promise<boolean> => {
      return this.evaluateFilterGroup(ctx, filters);
    };

    return [rootValidator];
  }

  private static evaluateFilterGroup<TContext extends Context>(ctx: TContext, group: FilterGroup): boolean {
    const { mode, filters, filterGroups } = group;

    // Evaluate individual filters in this group
    const filterResults = filters.map((f) => this.evaluateFilter(ctx, f));

    // Recursively evaluate nested filter groups
    const groupResults = filterGroups.map((g) => this.evaluateFilterGroup(ctx, g));

    const allResults = [...filterResults, ...groupResults];

    if (allResults.length === 0) return true;

    return mode === FilterMode.And
      ? allResults.every((res) => res === true)
      : allResults.some((res) => res === true);
  }

  private static evaluateFilter<TContext extends Context>(ctx: TContext, filter: Filter): boolean {
    const { key, operator, values, mode } = filter;
    // OpenCTI filters usually use the first element of the key array as the field path
    if (!key || !operator) return true;

    const actualValue: string | string[] = Array.isArray(key)
      ? key.flatMap((k) => this.getNestedValue(ctx, k))
      : this.getNestedValue(ctx, key);

    // Evaluate each value against the operator
    const results = values.map((expectedValue) => {
      switch (operator) {
        case FilterOperator.Eq:
          // If actualValue is an array, check if any element matches
          if (Array.isArray(actualValue)) {
            return actualValue.includes(expectedValue);
          }
          return actualValue == expectedValue;
        case FilterOperator.NotEq:
          if (Array.isArray(actualValue)) {
            return !actualValue.includes(expectedValue);
          }
          return actualValue != expectedValue;
        case FilterOperator.Gt:
          return actualValue > expectedValue;
        case FilterOperator.Gte:
          return actualValue >= expectedValue;
        case FilterOperator.Lt:
          return actualValue < expectedValue;
        case FilterOperator.Lte:
          return actualValue <= expectedValue;
        case FilterOperator.Nil:
          return actualValue === null || actualValue === undefined || actualValue === '';
        case FilterOperator.NotNil:
          return actualValue !== null && actualValue !== undefined && actualValue !== '';
        case FilterOperator.Contains:
          return Array.isArray(actualValue)
            ? actualValue.includes(expectedValue)
            : String(actualValue).toLowerCase().includes(String(expectedValue).toLowerCase());
        case FilterOperator.StartsWith:
          return String(actualValue).toLowerCase().startsWith(String(expectedValue).toLowerCase());
        default:
          console.warn(`Operator '${operator}' not yet implemented in engine, defaulting to false.`);
          return false;
      }
    });

    // Combine results based on filter mode: AND or OR
    return mode === FilterMode.And
      ? results.every((res) => res === true)
      : results.some((res) => res === true);
  }

  /**
   * Translates a list of action configurations into executable side effect functions.
   */
  public static createSideEffects<TContext extends Context>(configs?: ActionConfig[]): SideEffect<TContext>[] {
    if (!configs || configs.length === 0) return [];

    return configs.map((config) => {
      const actionFn = ActionRegistry[config.type];
      if (!actionFn) {
        console.warn(`Action type '${config.type}' not found in registry.`);
        return async () => {};
      }

      return async (ctx: TContext) => {
        if (config.mode === 'async') {
          // Fire and forget
          Promise.resolve(actionFn(ctx, config.params)).catch((err: any) =>

            console.error(`Async action '${config.type}' failed`, err),
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
      definition.addState(state.statusId, {
        onEnter: this.createSideEffects<TContext>(state.onEnter),
        onExit: this.createSideEffects<TContext>(state.onExit),
      });
    });

    schema.transitions.forEach((t) => {
      definition.addTransition(t.from, t.to, t.event, {
        comment: t.comment,
        conditions: this.createConditions<TContext>(t.conditions),
        onTransition: this.createSideEffects<TContext>(t.actions),
        actionTypes: t.actions?.map((a) => a.type) || [],
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
