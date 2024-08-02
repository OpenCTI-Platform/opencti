import { READ_DATA_INDICES } from '../database/utils';
import { logApp } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';

const message = '[MIGRATION] Remove authorized members in Public dashboards';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  // const publicDashboards = await listAllEntities(
  //   context,
  //   context.user,
  //   [ENTITY_TYPE_PUBLIC_DASHBOARD],
  // );
  //
  // for (let index = 0; index < publicDashboards.length; index += 1) {
  //   const publicDashboard = publicDashboards[index];
  //   const patch = { authorized_members: undefined };
  //   await patchAttribute(context, SYSTEM_USER, publicDashboard.id, ENTITY_TYPE_PUBLIC_DASHBOARD, patch);
  // }

  const updateQuery = {
    script: {
      params: { fieldToRemove: 'authorized_members' },
      source: 'ctx._source.remove(params.fieldToRemove)',
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'PublicDashboard' } } },
        ],
      },
    },
  };
  await elUpdateByQueryForMigration(
    message,
    READ_DATA_INDICES,
    updateQuery
  );

  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
