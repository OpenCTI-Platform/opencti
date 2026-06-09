import { z } from 'zod';
import { ValidationError } from '../../config/errors';
import { fullEntitiesList, storeLoadById, storeLoadByIds } from '../../database/middleware-loader';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { ENTITY_TYPE_STATUS_TEMPLATE } from '../../schema/internalObject';
import { isBasicObject } from '../../schema/stixCoreObject';
import type { AuthContext, AuthUser } from '../../types/user';
import { ActionDefinitions } from './registry/workflow-actions';
import type { WorkflowValidationError } from './types/workflow-types';
import { ENTITY_TYPE_WORKFLOW_DEFINITION, ENTITY_TYPE_WORKFLOW_INSTANCE } from './types/workflow-types';

const filterModeValues = Object.values(FilterMode) as [string, ...string[]];
const filterOperatorValues = Object.values(FilterOperator) as [string, ...string[]];

export const workflowActionConfigSchema = z.object({
  type: z.string().max(255),
  params: z.any().optional(),
});

export const workflowFilterSchema = z.object({
  id: z.string().optional(),
  key: z.string().max(255),
  values: z.array(z.any()),
  operator: z.string().optional(),
  mode: z.string().optional(),
});

export const workflowFilterGroupSchema: z.ZodType<any> = z.lazy(() => z.object({
  mode: z.string(),
  filters: z.array(workflowFilterSchema),
  filterGroups: z.array(workflowFilterGroupSchema),
}));

export const workflowConditionConfigSchema = z.object({
  filters: workflowFilterGroupSchema.optional(),
});

export const workflowSerializedStateSchema = z.object({
  statusId: z.string().max(255).optional(),
  name: z.string().max(255).optional(),
  onEnter: z.array(workflowActionConfigSchema).optional(),
  onExit: z.array(workflowActionConfigSchema).optional(),
});

export const workflowSerializedTransitionSchema = z.object({
  from: z.union([z.string().max(255), z.array(z.string().max(255))]).nullable(),
  to: z.string().max(255).nullable(),
  event: z.string().max(255),
  /** Phase 1: async background task actions. Only action types with allowedModes: ['async'] are valid here. */
  asyncActions: z.array(workflowActionConfigSchema).optional(),
  /** Phase 2: sync actions run after all asyncActions succeed (or immediately if none). */
  syncActions: z.array(workflowActionConfigSchema).optional(),
  conditions: workflowConditionConfigSchema.optional(),
  comment: z.enum(['allowed', 'required', 'disabled']).optional(),
});

export const workflowDefinitionSchema = z.object({
  id: z.string().max(255).optional(),
  name: z.string().max(255).optional(),
  initialState: z.string().max(255),
  states: z.array(workflowSerializedStateSchema).optional(),
  transitions: z.array(workflowSerializedTransitionSchema),
});

const extractAllStatesFromDefinition = (definition: z.infer<typeof workflowDefinitionSchema>): Set<string> => {
  const stateIds = new Set<string>();

  if (definition.initialState !== '*') {
    stateIds.add(definition.initialState);
  }

  (definition.states ?? []).forEach((state) => {
    if (state.name) stateIds.add(state.name);
    if (state.statusId) stateIds.add(state.statusId);
  });

  definition.transitions.forEach((transition) => {
    if (transition.from !== null) {
      const fromStates = Array.isArray(transition.from) ? transition.from : [transition.from];
      fromStates.forEach((s) => {
        if (s !== '*') stateIds.add(s);
      });
    }
    if (transition.to !== null && transition.to !== '*') {
      stateIds.add(transition.to);
    }
  });

  return stateIds;
};

const validateAction = (action: z.infer<typeof workflowActionConfigSchema>, source: string) => {
  const definition = ActionDefinitions[action.type];
  if (!definition) {
    throw ValidationError(`Side effect (action) type '${action.type}' doesn't exist`);
  }
  if (definition.paramsSchema) {
    const result = definition.paramsSchema.safeParse(action.params);
    if (!result.success) {
      throw ValidationError(`Invalid params for action '${action.type}' in ${source}`, { errors: result.error.issues });
    }
  }
};

export const validateWorkflowDefinitionData = async (
  context: AuthContext,
  user: AuthUser,
  definitionStr: string,
  entityType: string,
  existingWorkflowId?: string,
): Promise<WorkflowValidationError[]> => {
  let parsed;
  const errors: WorkflowValidationError[] = [];
  try {
    parsed = JSON.parse(definitionStr);
  } catch (_error) {
    return [{ type: 'INVALID_JSON', message: 'Invalid workflow definition JSON' }];
  }

  const validationResult = workflowDefinitionSchema.safeParse(parsed);
  if (!validationResult.success) {
    errors.push({
      type: 'SCHEMA_VALIDATION_FAILED',
      message: 'Workflow definition schema validation failed',
    });
    return errors;
  }

  const { id, initialState, states = [], transitions } = validationResult.data;

  if (!isBasicObject(entityType) && !['DraftWorkspace'].includes(entityType)) {
    errors.push({
      type: 'INVALID_ENTITY_TYPE',
      message: `Entity type '${entityType}' doesn't exist`,
    });
  }

  if (id) {
    const existingWorkflows = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_WORKFLOW_DEFINITION]);
    const conflict = existingWorkflows.find((workflow) =>
      workflow.id !== existingWorkflowId
      && (workflow.id === id || workflow.name === id || (typeof workflow.draft_version?.content === 'string' && workflow.draft_version.content.includes(`"id":"${id}"`))),
    );
    if (conflict) {
      errors.push({
        type: 'DUPLICATE_WORKFLOW_ID',
        message: 'Workflow id already exists',
        path: [{ id: conflict.id, entity_type: ENTITY_TYPE_WORKFLOW_DEFINITION }],
      });
    }
  }

  const definedStates = new Set<string>();
  states.forEach((state: z.infer<typeof workflowSerializedStateSchema>) => {
    if (state.name) definedStates.add(state.name);
    if (state.statusId) definedStates.add(state.statusId);

    [...(state.onEnter || []), ...(state.onExit || [])].forEach((action) => {
      validateAction(action, `state ${state.name || state.statusId}`);
    });
  });

  const stateIdsToCheck = new Set<string>();
  if (initialState !== '*' && !definedStates.has(initialState)) {
    stateIdsToCheck.add(initialState);
  }

  // Track (fromState, event) pairs to prevent duplicate transitions from the same source.
  const fromEventPairs = new Set<string>();
  let hasValidateDraft = false;
  const statesWithIncomingTransition = new Set<string>();

  for (const transition of transitions) {
    if (transition.from === null || transition.to === null) {
      errors.push({
        type: 'UNLINKED_TRANSITION',
        message: `Transition ${transition.event} should be linked to at least one status`,
      });
    }

    const fromStatesForCheck = Array.isArray(transition.from) ? transition.from : [transition.from];
    for (const fromState of fromStatesForCheck) {
      const key = `${fromState}::${transition.event}`;
      if (fromEventPairs.has(key)) {
        errors.push({
          type: 'DUPLICATE_TRANSITION_EVENT',
          message: `Transition '${transition.event}' referenced in multiple transitions`,
        });
      }
      fromEventPairs.add(key);
    }

    const fromStates = Array.isArray(transition.from) ? transition.from : [transition.from];
    for (const fromState of fromStates) {
      if (fromState && fromState !== '*' && !definedStates.has(fromState)) {
        stateIdsToCheck.add(fromState);
      }
    }
    if (transition.to && transition.to !== '*' && !definedStates.has(transition.to)) {
      stateIdsToCheck.add(transition.to);
    }
    if (transition.to && transition.to !== '*') {
      statesWithIncomingTransition.add(transition.to);
    }

    if (transition.conditions) {
      // Validate filters recursively
      const validateFilterGroup = (group: any): void => {
        if (!group.filters || !Array.isArray(group.filters)) {
          return;
        }
        group.filters.forEach((filter: any) => {
          if (!filter.key) {
            errors.push({ type: 'MISSING_FILTER_KEY', message: 'Filter key is required' });
          }
          if (!filter.values || !Array.isArray(filter.values)) {
            errors.push({ type: 'INVALID_FILTER_VALUES', message: 'Filter values must be an array' });
          }
          if (filter.operator && !filterOperatorValues.includes(filter.operator)) {
            errors.push({ type: 'INVALID_FILTER_OPERATOR', message: `Invalid filter operator '${filter.operator}'` });
          }
          if (filter.mode && !filterModeValues.includes(filter.mode)) {
            errors.push({ type: 'INVALID_FILTER_MODE', message: `Invalid filter mode '${filter.mode}'` });
          }
        });
        if (group.filterGroups && Array.isArray(group.filterGroups)) {
          group.filterGroups.forEach(validateFilterGroup);
        }
      };
      if (transition.conditions.filters) {
        validateFilterGroup(transition.conditions.filters);
      }
    }

    // Validate asyncActions — enforce that the action type allows async-only execution
    if (transition.asyncActions) {
      for (const action of transition.asyncActions) {
        const def = ActionDefinitions[action.type];
        if (!def) {
          throw ValidationError(`Side effect (action) type '${action.type}' doesn't exist`);
        }
        if (def.allowedModes && !def.allowedModes.includes('async')) {
          throw ValidationError(`Action type '${action.type}' is not allowed in asyncActions (must support 'async' mode) in transition ${transition.event}`);
        }
        validateAction(action, `transition ${transition.event} (asyncActions)`);
      }
    }

    // Validate syncActions — enforce that the action type allows sync execution
    if (transition.syncActions) {
      for (const action of transition.syncActions) {
        const def = ActionDefinitions[action.type];
        if (!def) {
          throw ValidationError(`Side effect (action) type '${action.type}' doesn't exist`);
        }
        if (def.allowedModes && !def.allowedModes.includes('sync')) {
          throw ValidationError(`Action type '${action.type}' is not allowed in syncActions (must support 'sync' mode) in transition ${transition.event}`);
        }
        validateAction(action, `transition ${transition.event} (syncActions)`);
        if (action.type === 'validateDraft') {
          hasValidateDraft = true;
        }
      }
    }
  }

  if (entityType === 'DraftWorkspace' && !hasValidateDraft) {
    errors.push({
      type: 'MISSING_VALIDATE_DRAFT_ACTION',
      message: 'DraftWorkspace workflow must contain at least one validateDraft action',
    });
  }

  // Validate exactly one root state (a state with no incoming transitions) and that it matches initialState
  if (initialState !== '*' && definedStates.size > 0) {
    const rootStates = [...definedStates].filter((s) => !statesWithIncomingTransition.has(s));
    if (rootStates.length > 1) {
      errors.push({
        type: 'MULTIPLE_ROOT_STATES',
        message: `Workflow must have exactly one root state (a state with no incoming transitions), but found: ${rootStates.join(', ')}`,
      });
    }
    if (rootStates.length === 1 && rootStates[0] !== initialState) {
      errors.push({
        type: 'ROOT_STATE_MISMATCH',
        message: `The root state '${rootStates[0]}' (no incoming transitions) must match the initialState '${initialState}'`,
      });
    }
  }

  const stateIdsArray = Array.from(stateIdsToCheck);
  if (stateIdsArray.length > 0) {
    const templates = await storeLoadByIds(context, user, stateIdsArray, ENTITY_TYPE_STATUS_TEMPLATE);
    // storeLoadByIds returns undefined entries for IDs not found — filter them out before mapping
    const foundIds = new Set(templates.filter((t) => t != null).map((template: any) => template.id));
    for (const stateId of stateIdsArray) {
      if (!foundIds.has(stateId)) {
        errors.push({
          type: 'STATE_NOT_FOUND',
          message: `Transition/Action state '${stateId}' doesn't exist in the workflow definition states nor in the status templates in DB`,
        });
      }
    }
  }

  if (existingWorkflowId) {
    const existingWorkflow = await storeLoadById<any>(context, user, existingWorkflowId, ENTITY_TYPE_WORKFLOW_DEFINITION);
    if (existingWorkflow) {
      let oldDefinitionData;
      try {
        const rawContent = existingWorkflow.draft_version?.content ?? existingWorkflow.published_version?.content;
        if (rawContent) {
          oldDefinitionData = typeof rawContent === 'string' ? JSON.parse(rawContent) : rawContent;
        } else {
          oldDefinitionData = null;
        }
      } catch (_) {
        oldDefinitionData = null;
      }

      const oldValidation = oldDefinitionData ? workflowDefinitionSchema.safeParse(oldDefinitionData) : null;
      if (oldValidation?.success) {
        const oldStates = extractAllStatesFromDefinition(oldValidation.data);
        const newStates = extractAllStatesFromDefinition(validationResult.data);
        const removedStates = [...oldStates].filter((s) => !newStates.has(s));
        if (removedStates.length > 0) {
          // Note: 'workflow_id' is a reserved special filter key (WORKFLOW_FILTER) in OpenCTI that maps to
          // entity workflow status (x_opencti_workflow_id). We cannot use it as a raw ES filter key.
          // Instead, we filter by currentState in ES and post-filter by workflow_id.
          const instancesInRemovedStates = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_WORKFLOW_INSTANCE], {
            filters: {
              mode: FilterMode.And,
              filters: [
                { key: ['currentState'], values: removedStates, operator: FilterOperator.Eq, mode: FilterMode.Or },
              ],
              filterGroups: [],
            },
          });
          const conflictingInstances = instancesInRemovedStates.filter((inst: any) => inst.workflow_id === existingWorkflowId);

          if (conflictingInstances.length > 0) {
            errors.push({
              type: 'STATE_IN_USE',
              message: `Cannot remove states ${removedStates.join(', ')} that are currently in use by workflow instances`,
              path: conflictingInstances.map((i: any) => ({ id: i.id, entity_type: ENTITY_TYPE_WORKFLOW_INSTANCE })),
            });
          }
        }
      }
    }
  }

  return errors;
};
