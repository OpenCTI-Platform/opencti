// import { logMigration } from '../config/conf';
// import { elUpdateByQueryForMigration } from '../database/engine';
// import { READ_INDEX_HISTORY } from '../database/utils';
// import { executionContext, SYSTEM_USER } from '../utils/access';
// import { getEntitiesMapFromCache } from '../database/cache';
// import { ENTITY_TYPE_USER } from '../schema/internalObject';

// const message = '[MIGRATION] adding missing group_ids in activity due to regression bug in 6.6';

export const up = async (next) => {
  // ----- Explanations ----------
  // This migration has been removed
  // because it might be too heavy for large platforms
  // Prefer using a cleanup script that can be run while the platform is running.
  // -----------------------------

  // logMigration.info(`${message} > started`);
  // const context = executionContext('migration');
  //
  // const userGroupIdsMap = {};
  // const allUsers = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_USER);
  // allUsers.forEach((u) => { userGroupIdsMap[u.internal_id] = u.groups?.map((g) => g.internal_id) ?? []; });
  //
  // // Since bug was introduced with 6.6 release, we filter history from the data of 6.6 release: 8th of April 2025
  // const activityUpdateQuery = {
  //   script: {
  //     params: { userGroupIdsMap },
  //     source: 'if (params.userGroupIdsMap.containsKey(ctx._source.user_id)) { ctx._source.group_ids = params.userGroupIdsMap[ctx._source.user_id]; }',
  //   },
  //   query: {
  //     bool: {
  //       must_not: [{
  //         exists: {
  //           field: 'group_ids'
  //         }
  //       }],
  //       must: [{
  //         range: {
  //           created_at: {
  //             gte: '2025-04-08T00:00:00'
  //           }
  //         }
  //       }]
  //     },
  //   }
  // };
  // await elUpdateByQueryForMigration(
  //   '[MIGRATION] Missing group_ids in activity fix',
  //   READ_INDEX_HISTORY,
  //   activityUpdateQuery
  // );
  //
  // logMigration.info(`${message} > done`);
  next();
};
