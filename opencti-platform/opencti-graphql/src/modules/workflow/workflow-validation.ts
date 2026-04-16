import { z } from 'zod';
import { ValidationError } from '../../config/errors';
import { ActionDefinitions } from './registry/workflow-actions';
import { storeLoadByIds, fullEntitiesList } from '../../database/middleware-loader';
import { ENTITY_TYPE_STATUS_TEMPLATE } from '../../schema/internalObject';
import type { AuthContext, AuthUser } from '../../types/user';
import { ENTITY_TYPE_WORKFLOW_DEFINITION } from './types/workflow-types';
import { isBasicObject } from '../../schema/stixCoreObject';
import { FilterMode, FilterOperator } from '../../generated/graphql';

const filterModeValues = Object.values(FilterMode) as [string, ...string[]];
const filterOperatorValues = Object.values(FilterOperator) as [string, ...string[]];

export const workflowActionConfigSchema = z.object({
  type: z.string().max(255),
  params: z.any().optional(),
  mode: z.enum(['sync', 'async']).optional(),
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
  filters: workflowFilterGroupSchema,
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
  actions: z.array(workflowActionConfigSchema).optional(),
  conditions: workflowConditionConfigSchema.optional(),
});

export const workflowDefinitionSchema = z.object({
  id: z.string().max(255).optional(),
  name: z.string().max(255).optional(),
  initialState: z.string().max(255),
  states: z.array(workflowSerializedStateSchema).optional(),
  transitions: z.array(workflowSerializedTransitionSchema),
});

const validateAction = (action: z.infer<typeof workflowActionConfigSchema>, source: string) => {
  const definition = ActionDefinitions[action.type];
  if (!definition) {
    throw ValidationError(`Side effect (action) type '${action.type}' doesn't exist`);
  }
  if (action.mode && definition.allowedModes && !definition.allowedModes.includes(action.mode)) {
    throw ValidationError(`Incompatible action mode '${action.mode}' for '${action.type}' in ${source}`);
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
) => {
  let parsed;
  try {
    parsed = JSON.parse(definitionStr);
  } catch (_error) {
    throw ValidationError('Invalid workflow definition JSON');
  }

  const validationResult = workflowDefinitionSchema.safeParse(parsed);
  if (!validationResult.success) {
    throw ValidationError('Workflow definition schema validation failed', { errors: validationResult.error.issues });
  }

  const { id, initialState, states = [], transitions } = validationResult.data;

  if (!isBasicObject(entityType) && !['DraftWorkspace'].includes(entityType)) {
    throw ValidationError(`Entity type '${entityType}' doesn't exist`);
  }

  if (id) {
    const existingWorkflows = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_WORKFLOW_DEFINITION]);
    const conflict = existingWorkflows.find((workflow) =>
      workflow.id !== existingWorkflowId
      && (workflow.id === id || workflow.name === id || (typeof workflow.workflow_content === 'string' && workflow.workflow_content.includes(`"id":"${id}"`))),
    );
    if (conflict) {
      throw ValidationError('Workflow id already exists');
    }
  }

  const definedStates = new Set<string>();
  states.forEach((state) => {
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

  const events = new Set<string>();
  let hasValidateDraft = false;

  for (const transition of transitions) {
    if (transition.from === null || transition.to === null) {
      throw ValidationError(`Transition ${transition.event} should be linked to at least one status`);
    }
    if (events.has(transition.event)) {
      throw ValidationError(`Transition '${transition.event}' referenced in multiple transitions`);
    }
    events.add(transition.event);

    const fromStates = Array.isArray(transition.from) ? transition.from : [transition.from];
    for (const fromState of fromStates) {
      if (fromState !== '*' && !definedStates.has(fromState)) {
        stateIdsToCheck.add(fromState);
      }
    }
    if (transition.to !== '*' && !definedStates.has(transition.to)) {
      stateIdsToCheck.add(transition.to);
    }

    if (transition.conditions) {
      // Validate filters recursively
      const validateFilterGroup = (group: any): void => {
        if (!group.filters || !Array.isArray(group.filters)) {
          return;
        }
        group.filters.forEach((filter: any) => {
          if (!filter.key) {
            throw ValidationError('Filter key is required');
          }
          if (!filter.values || !Array.isArray(filter.values)) {
            throw ValidationError('Filter values must be an array');
          }
          if (filter.operator && !filterOperatorValues.includes(filter.operator)) {
            throw ValidationError(`Invalid filter operator '${filter.operator}'`);
          }
          if (filter.mode && !filterModeValues.includes(filter.mode)) {
            throw ValidationError(`Invalid filter mode '${filter.mode}'`);
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

    if (transition.actions) {
      for (const action of transition.actions) {
        validateAction(action, `transition ${transition.event}`);
        if (action.type === 'validateDraft') {
          hasValidateDraft = true;
        }
      }
    }
  }

  if (entityType === 'DraftWorkspace' && !hasValidateDraft) {
    throw ValidationError('DraftWorkspace workflow must contain at least one validateDraft action');
  }

  const stateIdsArray = Array.from(stateIdsToCheck);
  if (stateIdsArray.length > 0) {
    const templates = await storeLoadByIds(context, user, stateIdsArray, ENTITY_TYPE_STATUS_TEMPLATE);
    const foundIds = new Set(templates.map((template: any) => template.id));
    for (const stateId of stateIdsArray) {
      if (!foundIds.has(stateId)) {
        throw ValidationError(`Transition/Action state '${stateId}' doesn't exist in the workflow definition states nor in the status templates in DB`);
      }
    }
  }

  return validationResult.data;
};
