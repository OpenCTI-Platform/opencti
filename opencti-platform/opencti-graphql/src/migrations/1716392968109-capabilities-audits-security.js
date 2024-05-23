import * as R from 'ramda';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { addCapability } from '../domain/grant';
import { listAllEntities } from '../database/middleware-loader';
import { roleCapabilities } from '../domain/user';
import { ENTITY_TYPE_ROLE } from '../schema/internalObject';
import { createRelation } from '../database/middleware';
import { logApp } from '../config/conf';

export const up = async (next) => {
  const context = executionContext('migration');
  logApp.info('[MIGRATION] Add SECURITY_ACTIVITY capability to platform and to users with SETTINGS capability');

  const securityActivityCapability = await addCapability(
    context,
    SYSTEM_USER,
    {
      name: 'SETTINGS_SECURITYACTIVITY',
      description: 'Security Activity',
      attribute_order: 3500
    }
  );
  const roles = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_ROLE], {});
  // eslint-disable-next-line no-plusplus
  for (let i = 0; i < roles.length; i++) {
    const getRoleCapabilities = await roleCapabilities(context, SYSTEM_USER, roles[i].id);
    const hasSettings = getRoleCapabilities.some((role) => {
      return role.name.startsWith('SETTINGS');
    });
    if (hasSettings) {
      const input = {
        fromId: roles[i].id,
        toId: securityActivityCapability.id,
        relationship_type: 'has-capability',
      };
      const finalInput = R.assoc('fromId', roles[i].id, input);
      await createRelation(context, SYSTEM_USER, finalInput);
    }
  }
  next();
};

export const down = async (next) => {
  next();
};
