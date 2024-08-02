import { ENTITY_TYPE_PUBLIC_DASHBOARD } from '../modules/publicDashboard/publicDashboard-types';
import { logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { listAllEntities } from '../database/middleware-loader';
import { patchAttribute } from '../database/middleware';

const message = '[MIGRATION] Remove authorized members in Public dashboards';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration', SYSTEM_USER);

  const publicDashboards = await listAllEntities(
    context,
    context.user,
    [ENTITY_TYPE_PUBLIC_DASHBOARD],
  );

  for (let index = 0; index < publicDashboards.length; index += 1) {
    const publicDashboard = publicDashboards[index];
    const patch = { authorized_members: undefined };
    await patchAttribute(context, SYSTEM_USER, publicDashboard.id, ENTITY_TYPE_PUBLIC_DASHBOARD, patch);
  }
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
