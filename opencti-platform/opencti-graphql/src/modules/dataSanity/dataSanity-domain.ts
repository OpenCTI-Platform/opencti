import type { AuthContext, AuthUser } from '../../types/user';
import { fullEntitiesList } from '../../database/middleware-loader';
import { createEntity, updateAttribute } from '../../database/middleware';
import { ENTITY_TYPE_DATA_SANITY_EXECUTION } from './dataSanity-types';
import type { BasicStoreEntityDataSanity } from './dataSanity-types';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { utcDate } from '../../utils/format';
import { type SanityOperation, sanityOperationList, type SanityOperationRunOutput } from './dataSanity-operations';

/**
 * Find a DataSanity entity by operation_name.
 */
export const findDataSanityByOperationName = async (context: AuthContext, user: AuthUser, operationName: string): Promise<BasicStoreEntityDataSanity | undefined> => {
  const results = await fullEntitiesList<BasicStoreEntityDataSanity>(
    context,
    user,
    [ENTITY_TYPE_DATA_SANITY_EXECUTION],
    {
      filters: {
        mode: FilterMode.And,
        filters: [{ key: ['operation_name'], values: [operationName], operator: FilterOperator.Eq, mode: FilterMode.Or }],
        filterGroups: [],
      },
    },
  );
  return results.length > 0 ? results[0] : undefined;
};

/**
 * Check if a sanity operation has already been executed (stored in ElasticSearch).
 */
export const hasOperationBeenExecuted = async (context: AuthContext, user: AuthUser, operationName: string): Promise<boolean> => {
  const entity = await findDataSanityByOperationName(context, user, operationName);
  return entity !== undefined && !entity.force_run;
};

/**
 * Mark a sanity operation as currently running.
 * Creates the entity if it doesn't exist yet.
 */
export const markOperationAsRunning = async (context: AuthContext, user: AuthUser, operationName: string): Promise<void> => {
  const existing = await findDataSanityByOperationName(context, user, operationName);
  if (existing) {
    await updateAttribute(context, user, existing.internal_id, ENTITY_TYPE_DATA_SANITY_EXECUTION, [
      { key: 'is_running', value: [true] },
    ]);
  } else {
    await createEntity(context, user, {
      operation_name: operationName,
      last_run_date: utcDate().toISOString(),
      last_execution_time: 0,
      last_run_success: false,
      last_run_message: '',
      force_run: false,
      is_running: true,
    }, ENTITY_TYPE_DATA_SANITY_EXECUTION);
  }
};

/**
 * Mark a sanity operation as executed by creating or updating a DataSanity entity.
 * Resets force_run and is_running to false after execution.
 * @param context
 * @param user
 * @param operationName
 * @param executionTimeMs - duration of the operation execution in milliseconds
 * @param success - whether the operation succeeded
 * @param runMessage - human-readable message (error on failure, empty or brief on success)
 * @param output - the SanityOperationRunOutput to store (only on success)
 */
export const markOperationAsExecuted = async (
  context: AuthContext, user: AuthUser, operationName: string,
  executionTimeMs: number, success: boolean, runMessage: string,
  output?: SanityOperationRunOutput,
): Promise<void> => {
  const existing = await findDataSanityByOperationName(context, user, operationName);
  const lastRunOutput = success && output ? JSON.stringify(output) : '';
  if (existing) {
    await updateAttribute(context, user, existing.internal_id, ENTITY_TYPE_DATA_SANITY_EXECUTION, [
      { key: 'last_run_date', value: [utcDate().toISOString()] },
      { key: 'last_execution_time', value: [executionTimeMs] },
      { key: 'last_run_success', value: [success] },
      { key: 'last_run_message', value: [runMessage] },
      { key: 'last_run_output', value: [lastRunOutput] },
      { key: 'force_run', value: [false] },
      { key: 'is_running', value: [false] },
    ]);
  } else {
    await createEntity(context, user, {
      operation_name: operationName,
      last_run_date: utcDate().toISOString(),
      last_execution_time: executionTimeMs,
      last_run_success: success,
      last_run_message: runMessage,
      last_run_output: lastRunOutput,
      force_run: false,
      is_running: false,
    }, ENTITY_TYPE_DATA_SANITY_EXECUTION);
  }
};

/**
 * Find all DataSanity entities with force_run set to true.
 */
export const findForceRunOperations = async (context: AuthContext, user: AuthUser): Promise<BasicStoreEntityDataSanity[]> => {
  return fullEntitiesList<BasicStoreEntityDataSanity>(
    context,
    user,
    [ENTITY_TYPE_DATA_SANITY_EXECUTION],
    {
      filters: {
        mode: FilterMode.And,
        filters: [{ key: ['force_run'], values: ['true'], operator: FilterOperator.Eq, mode: FilterMode.Or }],
        filterGroups: [],
      },
    },
  );
};

/**
 * Set force_run to true for a given operation_name.
 * Creates the entity if it doesn't exist yet.
 */
export const setForceRun = async (context: AuthContext, user: AuthUser, operationName: string): Promise<string> => {
  const existing = await findDataSanityByOperationName(context, user, operationName);
  if (existing) {
    await updateAttribute(context, user, existing.internal_id, ENTITY_TYPE_DATA_SANITY_EXECUTION, [
      { key: 'force_run', value: [true] },
    ]);
    return existing.internal_id;
  }
  const created = await createEntity(context, user, {
    operation_name: operationName,
    last_run_date: utcDate().toISOString(),
    last_execution_time: 0,
    last_run_success: false,
    last_run_message: '',
    force_run: true,
  }, ENTITY_TYPE_DATA_SANITY_EXECUTION);
  return created.internal_id;

/**
 * List all DataSanityExecution entities (operations that have been executed).
 */
export const findAllDataSanityExecutions = async (context: AuthContext, user: AuthUser): Promise<BasicStoreEntityDataSanity[]> => {
  return fullEntitiesList<BasicStoreEntityDataSanity>(
    context,
    user,
    [ENTITY_TYPE_DATA_SANITY_EXECUTION],
    {},
  );
};

export const listAllSanityOperations = async (context: AuthContext, user: AuthUser) => {
  const executions = await findAllDataSanityExecutions(context, user);
  return sanityOperationList().map((operation: SanityOperation) => {
    const execution = executions.find((e) => e.operation_name === operation.identifier);
    return {
      identifier: operation.identifier,
      display_name: operation.display_name,
      execution_type: operation.execution_type,
      description: operation.description,
      eligible_entity_types: operation.eligibleEntityTypes,
      is_running: execution?.is_running ?? false,
      force_run: execution?.force_run ?? false,
      last_run_date: execution?.last_run_date ?? null,
      last_execution_time: execution?.last_execution_time ?? null,
      last_run_success: execution?.last_run_success ?? null,
      last_run_message: execution?.last_run_message ?? null,
      last_run_output: execution?.last_run_output ?? null,
    };
  });
};

/**
 * Execute the dry run of a sanity operation synchronously and return the output
 * formatted for GraphQL response.
 * @param context
 * @param operationName - the name of the sanity operation to dry run
 */
export const executeDryRun = async (context: AuthContext, operationName: string) => {
  const operation = sanityOperationList().find((op: SanityOperation) => op.identifier === operationName);
  if (!operation) {
    throw new Error(`Unknown sanity operation: ${operationName}`);
  }
  const output = await operation.dryRun(context);
  return {
    estimated_impact: Object.entries(output.impact.detail).map(([key, count]) => ({ key, count })),
  };
};
