import { ActionRegistry } from '../registry/workflow-actions';
import type { ActionConfig, WorkflowSchema } from './workflow-schema';
import type { ConditionValidator, Context, SideEffect } from '../types/workflow-types';
import { WorkflowDefinition } from './workflow-definition';
import { WorkflowInstance } from './workflow-instance';
import { FilterMode, FilterOperator, type Filter, type FilterGroup } from '../../../generated/graphql';
import { stixLoadById, stixLoadByIds } from '../../../database/middleware';
import { isStixMatchFilterGroup_MockableForUnitTests } from '../../../utils/filtering/filtering-stix/stix-filtering';
import { buildResolutionMapForFilterGroup, extractFilterGroupValuesToResolveForCache } from '../../../utils/filtering/filtering-resolution';
import { SYSTEM_USER } from '../../../utils/access';
import { logApp } from '../../../config/conf';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';
import { FILTER_KEYS_WITH_ME_VALUE, ME_FILTER_VALUE } from '../../../utils/filtering/filtering-constants';
import type { FilterResolutionMap } from '../../../utils/filtering/filtering-resolution';

// Filter keys evaluated against the workflow context (triggering user, entity name).
// Every other key is an entity attribute, evaluated by the stix filtering engine.
const CONTEXT_FILTER_KEYS = ['workflow_user', 'workflow_group', 'workflow_organization', 'workflow_role', 'name'];

// What entity attribute filters are evaluated against: the entity as stix and the resolved filter values.
interface EntityFilterInput {
  stixEntity: any;
  resolutionMap: FilterResolutionMap;
}

// Per workflow context cache, shared by all the transitions evaluated with that context
// (allowed transitions listing evaluates every transition of the current state with the same context).
interface EntityFilterCache {
  stixEntity?: Promise<any>;
  resolvedValues: Map<string, Promise<any>>;
}

/**
 * Utility factory to create workflow definitions and instances from various sources.
 * Handles the mapping between JSON configuration (schemas) and executable logic.
 */
export class WorkflowFactory {
  // Helper to access nested properties: "workflow_role" -> ctx.user.role
  // Conditions always evaluate against the triggering user (the actual caller),
  // while actions run as WORKFLOW_MANAGER_USER. triggeringUser is set by workflow-domain.ts.
  private static getNestedValue(ctx: any, key: string): string | string[] {
    const ctxUser = (ctx as any).triggeringUser ?? (ctx as any).user;
    if (key === 'workflow_group') {
      return (ctxUser?.groups || []).map((g: any) => g.id);
    } else if (key === 'workflow_organization') {
      return (ctxUser?.organizations || []).map((o: any) => o.id);
    } else if (key === 'workflow_role') {
      return (ctxUser?.roles || []).map((r: any) => r.name);
    } else if (key === 'workflow_user') {
      return (ctxUser?.id || ctxUser?.internal_id || null);
    }
    return ctx.entity.name;
  }

  private static isContextFilter(filter: Filter): boolean {
    const keys = Array.isArray(filter.key) ? filter.key : [filter.key];
    return keys.every((k) => CONTEXT_FILTER_KEYS.includes(k));
  }

  private static entityFilterCaches = new WeakMap<object, EntityFilterCache>();

  private static getEntityFilterCache(ctx: Context): EntityFilterCache {
    let cache = this.entityFilterCaches.get(ctx);
    if (!cache) {
      cache = { resolvedValues: new Map() };
      this.entityFilterCaches.set(ctx, cache);
    }
    return cache;
  }

  // Stix filtering expects array keys; the frontend may store a plain string.
  // Context filters are kept as stored: their evaluator reads string and array keys differently.
  private static normalizeFilterGroup(group: FilterGroup): FilterGroup {
    return {
      ...group,
      filters: group.filters.map((f) => (this.isContextFilter(f) || Array.isArray(f.key) ? f : { ...f, key: [f.key] })),
      filterGroups: group.filterGroups.map((g) => this.normalizeFilterGroup(g)),
    };
  }

  private static hasEntityFilter(group: FilterGroup): boolean {
    return group.filters.some((f) => !this.isContextFilter(f)) || group.filterGroups.some((g) => this.hasEntityFilter(g));
  }

  // Loads the entity as stix and the filter values to resolve (labels, markings, authors...), once per workflow context.
  // Workflow filters are not part of the platform "Resolved-Filters" cache (streams, triggers, playbooks), so they are loaded here.
  // Loaded as SYSTEM_USER so the condition reflects the entity itself, not what the caller can see.
  private static async loadEntityFilterInput(ctx: Context, filters: FilterGroup): Promise<EntityFilterInput | undefined> {
    const cache = this.getEntityFilterCache(ctx);
    if (!cache.stixEntity) {
      const entityId = ctx.entity?.internal_id ?? ctx.entity?.id;
      cache.stixEntity = stixLoadById(ctx.context, SYSTEM_USER, entityId);
    }
    const missingIds = extractFilterGroupValuesToResolveForCache(filters).filter((id) => !cache.resolvedValues.has(id));
    if (missingIds.length > 0) {
      const loading = stixLoadByIds(ctx.context, SYSTEM_USER, missingIds) as Promise<any[]>;
      missingIds.forEach((id) => {
        cache.resolvedValues.set(id, loading.then((entities) => entities.find((e) => e.extensions[STIX_EXT_OCTI].id === id)));
      });
    }
    const stixEntity = await cache.stixEntity;
    if (!stixEntity) return undefined;
    const resolvedEntries = await Promise.all([...cache.resolvedValues].map(async ([id, value]) => [id, await value] as const));
    const resolutionCache = new Map(resolvedEntries.filter(([, value]) => value));
    const resolutionMap = await buildResolutionMapForFilterGroup(ctx.context, SYSTEM_USER, filters, resolutionCache);
    return { stixEntity, resolutionMap };
  }

  /**
   * Translates a list of condition configurations into executable validator functions.
   */
  public static createConditions<TContext extends Context>(configs?: { filters: FilterGroup }): ConditionValidator<TContext>[] {
    const { filters } = configs || {};
    if (!filters) return [];

    // We return a single validator that evaluates the entire recursive tree
    const normalizedFilters = this.normalizeFilterGroup(filters);
    const hasEntityFilter = this.hasEntityFilter(normalizedFilters);
    const rootValidator = async (ctx: TContext): Promise<boolean> => {
      let entityFilterInput: EntityFilterInput | undefined;
      if (hasEntityFilter) {
        try {
          entityFilterInput = await this.loadEntityFilterInput(ctx, normalizedFilters);
        } catch (error) {
          logApp.warn('[WORKFLOW] Condition entity cannot be loaded, entity filters considered as not matching', { cause: error });
        }
      }
      return this.evaluateFilterGroup(ctx, normalizedFilters, entityFilterInput);
    };

    return [rootValidator];
  }

  private static async evaluateFilterGroup<TContext extends Context>(ctx: TContext, group: FilterGroup, entityFilterInput?: EntityFilterInput): Promise<boolean> {
    const { mode, filters, filterGroups } = group;

    // Evaluate individual filters in this group
    const filterResults = await Promise.all(filters.map((f) => (this.isContextFilter(f)
      ? this.evaluateFilter(ctx, f)
      : this.evaluateEntityFilter(ctx, f, entityFilterInput))));

    // Recursively evaluate nested filter groups
    const groupResults = await Promise.all(filterGroups.map((g) => this.evaluateFilterGroup(ctx, g, entityFilterInput)));

    const allResults = [...filterResults, ...groupResults];

    if (allResults.length === 0) return true;

    return mode === FilterMode.And
      ? allResults.every((res) => res === true)
      : allResults.some((res) => res === true);
  }

  private static async evaluateEntityFilter<TContext extends Context>(ctx: TContext, filter: Filter, entityFilterInput?: EntityFilterInput): Promise<boolean> {
    if (!entityFilterInput) return false;
    // @me is the user triggering the transition, not the SYSTEM_USER used for the evaluation
    const ctxUser = ctx.triggeringUser ?? ctx.user;
    const values = filter.key.some((k) => FILTER_KEYS_WITH_ME_VALUE.includes(k))
      ? filter.values.map((v) => (v === ME_FILTER_VALUE ? ctxUser?.id : v))
      : filter.values;
    const filterGroup: FilterGroup = { mode: FilterMode.And, filters: [{ ...filter, values }], filterGroups: [] };
    try {
      return await isStixMatchFilterGroup_MockableForUnitTests(ctx.context, SYSTEM_USER, entityFilterInput.stixEntity, filterGroup, entityFilterInput.resolutionMap);
    } catch (error) {
      logApp.warn('[WORKFLOW] Condition filter cannot be evaluated, considered as not matching', { cause: error, key: filter.key });
      return false;
    }
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
        await actionFn(ctx, config.params);
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
      // asyncActions (phase 1) — absent means no async effects
      const asyncSideEffects = this.createSideEffects<TContext>(t.asyncActions);
      const resolvedSyncActions = t.syncActions;
      const syncSideEffects = this.createSideEffects<TContext>(resolvedSyncActions);
      const allActionTypes = [
        ...(t.asyncActions?.map((a) => a.type) || []),
        ...(resolvedSyncActions?.map((a) => a.type) || []),
      ];

      // Compute org-input requirements from asyncAction params — more reliable than the stored boolean.
      const requiresShareOrganizationInput = (t.asyncActions ?? []).some((a) =>
        a.type === 'asyncBulkAction'
        && ((a.params as any)?.actions ?? []).some((ia: any) => ia.type === 'SHARE' && !ia.context?.values?.length),
      );
      const requiresUnshareOrganizationInput = (t.asyncActions ?? []).some((a) =>
        a.type === 'asyncBulkAction'
        && ((a.params as any)?.actions ?? []).some((ia: any) => ia.type === 'UNSHARE' && !ia.context?.values?.length),
      );

      definition.addTransition(t.from, t.to, t.event, {
        comment: t.comment,
        conditions: this.createConditions<TContext>(t.conditions),
        asyncSideEffects,
        onTransition: syncSideEffects,
        actionTypes: allActionTypes,
        requiresShareOrganizationInput,
        requiresUnshareOrganizationInput,
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
