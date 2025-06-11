import { logMigration } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_HISTORY } from '../database/utils';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { getEntitiesMapFromCache } from '../database/cache';
import { ENTITY_TYPE_USER } from '../schema/internalObject';

const message = '[MIGRATION] remove multiple authors from entities that have multiple rel_created-by.internal_id';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');

  const userGroupIdsMap = {};
  const allUsers = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_USER);
  allUsers.forEach((u) => { userGroupIdsMap[u.internal_id] = u.groups?.map((g) => g.internal_id) ?? []; });

  const activityUpdateQuery = {
    script: {
      params: { userGroupIdsMap },
      source: 'if (params.userGroupIdsMap.containsKey(ctx._source.user_id)) { ctx._source.group_ids = params.userGroupIdsMap[ctx._source.user_id]; }',
    },
    query: {
      range: {
        created_at: {
          gte: '2025-04-08T00:00:00',
          lte: '2025-06-13T00:00:00'
        }
      }
    }
  };
  await elUpdateByQueryForMigration(
    '[MIGRATION] Missing group_ids in activity fix',
    READ_INDEX_HISTORY,
    activityUpdateQuery
  );

  logMigration.info(`${message} > done`);
  next();
};
