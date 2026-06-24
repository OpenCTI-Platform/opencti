import type { AuthContext, AuthUser } from '../../types/user';
import { fullEntitiesList } from '../../database/middleware-loader';
import { createEntity, updateAttribute } from '../../database/middleware';
import { ENTITY_TYPE_DATA_SANITY } from './dataSanity-types';
import type { BasicStoreEntityDataSanity } from './dataSanity-types';
import { SYSTEM_USER } from '../../utils/access';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { utcDate } from '../../utils/format';
import { sanityFixList } from '../../manager/dataSanityManager/dataSanityManager-configuration';

/**
 * Find a DataSanity entity by fix_name.
 */
export const findDataSanityByFixName = async (context: AuthContext, fixName: string): Promise<BasicStoreEntityDataSanity | undefined> => {
  const results = await fullEntitiesList<BasicStoreEntityDataSanity>(
    context,
    SYSTEM_USER,
    [ENTITY_TYPE_DATA_SANITY],
    {
      filters: {
        mode: FilterMode.And,
        filters: [{ key: ['fix_name'], values: [fixName], operator: FilterOperator.Eq, mode: FilterMode.Or }],
        filterGroups: [],
      },
    },
  );
  return results.length > 0 ? results[0] : undefined;
};

/**
 * Check if a sanity fix has already been executed (stored in ElasticSearch).
 */
export const hasFixBeenExecuted = async (context: AuthContext, fixName: string): Promise<boolean> => {
  const entity = await findDataSanityByFixName(context, fixName);
  return entity !== undefined && !entity.force_run;
};

/**
 * Mark a sanity fix as executed by creating or updating a DataSanity entity.
 * Resets force_run to false after execution.
 * @param context
 * @param user
 * @param fixName
 * @param executionTimeMs - duration of the fix execution in milliseconds
 * @param failureMessage - error message if the fix failed, empty string if success
 */
export const markFixAsExecuted = async (context: AuthContext, user: AuthUser, fixName: string, executionTimeMs: number, failureMessage = ''): Promise<void> => {
  const existing = await findDataSanityByFixName(context, fixName);
  if (existing) {
    await updateAttribute(context, user, existing.internal_id, ENTITY_TYPE_DATA_SANITY, [
      { key: 'last_run_date', value: [utcDate().toISOString()] },
      { key: 'last_execution_time', value: [executionTimeMs] },
      { key: 'last_failure_message', value: [failureMessage] },
      { key: 'force_run', value: [false] },
    ]);
  } else {
    const input = {
      fix_name: fixName,
      last_run_date: utcDate().toISOString(),
      last_execution_time: executionTimeMs,
      last_failure_message: failureMessage,
      force_run: false,
    };
    console.log('***** input:', { input });
    await createEntity(context, user, input, ENTITY_TYPE_DATA_SANITY);
  }
};

/**
 * Find all DataSanity entities with force_run set to true.
 */
export const findForceRunFixes = async (context: AuthContext, user: AuthUser): Promise<BasicStoreEntityDataSanity[]> => {
  return fullEntitiesList<BasicStoreEntityDataSanity>(
    context,
    user,
    [ENTITY_TYPE_DATA_SANITY],
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
 * Set force_run to true for a given fix_name.
 * Creates the entity if it doesn't exist yet.
 */
export const setForceRun = async (context: AuthContext, user: AuthUser, fixName: string): Promise<string> => {
  const existing = await findDataSanityByFixName(context, fixName);
  if (existing) {
    await updateAttribute(context, user, existing.internal_id, ENTITY_TYPE_DATA_SANITY, [
      { key: 'force_run', value: [true] },
    ]);
    return existing.internal_id;
  }
  const created = await createEntity(context, user, {
    fix_name: fixName,
    last_run_date: utcDate().toISOString(),
    last_execution_time: 0,
    last_failure_message: '',
    force_run: true,
  }, ENTITY_TYPE_DATA_SANITY);
  return created.id;
};

export const listAllSanityFixes = async (_context: AuthContext) => {
  return sanityFixList().map((fix) => ({
    name: fix.name,
    execution_type: fix.execution_type,
  }));
};

/**
 * Ensure all on_demand fixes have a corresponding DataSanity entity in ElasticSearch.
 * This allows users to later set force_run=true on them via the mutation.
 */
export const registerOnDemandFixes = async (context: AuthContext, user: AuthUser): Promise<void> => {
  const onDemandFixes = sanityFixList().filter((fix) => fix.execution_type === 'on_demand');
  for (const fix of onDemandFixes) {
    const existing = await findDataSanityByFixName(context, fix.name);
    if (!existing) {
      await createEntity(context, user, {
        fix_name: fix.name,
        last_run_date: utcDate().toISOString(),
        last_execution_time: 0,
        last_failure_message: '',
        force_run: false,
      }, ENTITY_TYPE_DATA_SANITY);
    }
  }
};
