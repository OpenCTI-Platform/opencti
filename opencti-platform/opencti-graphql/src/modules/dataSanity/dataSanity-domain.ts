import type { AuthContext, AuthUser } from '../../types/user';
import { fullEntitiesList } from '../../database/middleware-loader';
import { createEntity, updateAttribute } from '../../database/middleware';
import { ENTITY_TYPE_DATA_SANITY_EXECUTION, type SanityOperation } from './dataSanity-types';
import type { BasicStoreEntityDataSanity } from './dataSanity-types';
import { SYSTEM_USER } from '../../utils/access';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { utcDate } from '../../utils/format';
import { sanityOperationList } from './dataSanity-configuration';

/**
 * Find a DataSanity entity by operation_name.
 */
export const findDataSanityByOperationName = async (context: AuthContext, operationName: string): Promise<BasicStoreEntityDataSanity | undefined> => {
  const results = await fullEntitiesList<BasicStoreEntityDataSanity>(
    context,
    SYSTEM_USER,
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
export const hasOperationBeenExecuted = async (context: AuthContext, operationName: string): Promise<boolean> => {
  const entity = await findDataSanityByOperationName(context, operationName);
  return entity !== undefined && !entity.force_run;
};

/**
 * Mark a sanity operation as executed by creating or updating a DataSanity entity.
 * Resets force_run to false after execution.
 * @param context
 * @param user
 * @param operationName
 * @param executionTimeMs - duration of the operation execution in milliseconds
 * @param failureMessage - error message if the operation failed, empty string if success
 */
export const markOperationAsExecuted = async (context: AuthContext, user: AuthUser, operationName: string, executionTimeMs: number, failureMessage = ''): Promise<void> => {
  const existing = await findDataSanityByOperationName(context, operationName);
  if (existing) {
    await updateAttribute(context, user, existing.internal_id, ENTITY_TYPE_DATA_SANITY_EXECUTION, [
      { key: 'last_run_date', value: [utcDate().toISOString()] },
      { key: 'last_execution_time', value: [executionTimeMs] },
      { key: 'last_failure_message', value: [failureMessage] },
      { key: 'force_run', value: [false] },
    ]);
  } else {
    const input = {
      operation_name: operationName,
      last_run_date: utcDate().toISOString(),
      last_execution_time: executionTimeMs,
      last_failure_message: failureMessage,
      force_run: false,
    };
    await createEntity(context, user, input, ENTITY_TYPE_DATA_SANITY_EXECUTION);
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
  const existing = await findDataSanityByOperationName(context, operationName);
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
    last_failure_message: '',
    force_run: true,
  }, ENTITY_TYPE_DATA_SANITY_EXECUTION);
  return created.id;
};

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

export const listAllSanityOperations = async (_context: AuthContext) => {
  return sanityOperationList().map((operation: SanityOperation) => ({
    name: operation.name,
    execution_type: operation.execution_type,
  }));
};

/**
 * Ensure all on_demand operations have a corresponding DataSanity entity in ElasticSearch.
 * This allows users to later set force_run=true on them via the mutation.
 */
export const registerOnDemandOperations = async (context: AuthContext, user: AuthUser): Promise<void> => {
  const onDemandOperations = sanityOperationList().filter((op: SanityOperation) => op.execution_type === 'on_demand');
  for (const operation of onDemandOperations) {
    const existing = await findDataSanityByOperationName(context, operation.name);
    if (!existing) {
      await createEntity(context, user, {
        operation_name: operation.name,
        last_run_date: utcDate().toISOString(),
        last_execution_time: 0,
        last_failure_message: '',
        force_run: false,
      }, ENTITY_TYPE_DATA_SANITY_EXECUTION);
    }
  }
};
