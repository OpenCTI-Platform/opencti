import conf, { logApp } from '../../config/conf';
import { DatabaseError } from '../../config/errors';
import { elRawSearch } from '../../database/engine';
import { getEntitiesMapFromCache } from '../../database/cache';
import { READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { SYSTEM_USER } from '../../utils/access';
import { now, utcDate } from '../../utils/format';
import type { AuthContext } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import { ENTITY_TYPE_USER_VISIT } from './timeMachine-types';
import { deleteUserVisits, deleteVisitsBefore } from './timeMachine-store';

const VISIT_RETENTION_DAYS: number = conf.get('time_machine:visit_retention_days') || 365;
// The retention manager runs every few seconds, the last visit markers only need an hourly purge
const VISIT_RETENTION_INTERVAL_MS = 60 * 60 * 1000;
const USERS_PAGE_SIZE = 1000;

let lastVisitRetention = 0;

// Users having last visit markers, paginated with a composite aggregation so no user is left out
const listUsersWithVisits = async (context: AuthContext): Promise<string[]> => {
  const userIds: string[] = [];
  let afterKey: Record<string, string> | null = null;
  do {
    const body: any = {
      size: 0,
      query: { bool: { must: [{ terms: { 'entity_type.keyword': [ENTITY_TYPE_USER_VISIT] } }] } },
      aggs: {
        users: {
          composite: {
            size: USERS_PAGE_SIZE,
            sources: [{ user_id: { terms: { field: 'user_id.keyword' } } }],
            ...(afterKey ? { after: afterKey } : {}),
          },
        },
      },
    };
    const data = await elRawSearch(context, SYSTEM_USER, ENTITY_TYPE_USER_VISIT, { index: READ_INDEX_INTERNAL_OBJECTS, body }).catch((err: unknown) => {
      throw DatabaseError('Last visit markers aggregation fail', { cause: err });
    });
    const buckets: Array<{ key: { user_id: string } }> = data.aggregations?.users?.buckets ?? [];
    buckets.forEach((bucket) => userIds.push(bucket.key.user_id));
    afterKey = buckets.length > 0 ? (data.aggregations?.users?.after_key ?? null) : null;
  } while (afterKey);
  return userIds;
};

export const purgeVisitsOfDeletedUsers = async (context: AuthContext): Promise<number> => {
  const users = await getEntitiesMapFromCache<BasicStoreEntity>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const userIds = await listUsersWithVisits(context);
  let deleted = 0;
  for (let index = 0; index < userIds.length; index += 1) {
    if (!users.has(userIds[index])) {
      deleted += await deleteUserVisits(userIds[index]);
    }
  }
  return deleted;
};

/**
 * Last visit markers expire after the visit retention and disappear with their user.
 * Run by the retention manager, whether knowledge snapshots are enabled or not.
 */
export const applyVisitRetention = async (context: AuthContext, currentDate: string): Promise<number> => {
  const expired = await deleteVisitsBefore(utcDate(currentDate).subtract(VISIT_RETENTION_DAYS, 'days').toISOString());
  const orphans = await purgeVisitsOfDeletedUsers(context);
  return expired + orphans;
};

export const applyVisitRetentionIfDue = async (context: AuthContext): Promise<void> => {
  const currentTime = Date.now();
  if (currentTime - lastVisitRetention < VISIT_RETENTION_INTERVAL_MS) {
    return;
  }
  lastVisitRetention = currentTime;
  try {
    const deleted = await applyVisitRetention(context, now());
    logApp.debug('[TIME MACHINE] Last visit markers retention done', { deleted });
  } catch (err) {
    logApp.error('[TIME MACHINE] Last visit markers retention failed', { cause: err });
  }
};
