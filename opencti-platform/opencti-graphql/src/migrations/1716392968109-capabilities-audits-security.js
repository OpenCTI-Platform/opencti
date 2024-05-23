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
  const securityActivityCapability = await addCapability(context, SYSTEM_USER, {
    name: 'SETTINGS_SECURITYACTIVITY',
    description: 'Security Activity',
    attribute_order: 3500
  });
  const roles = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_ROLE], {});
  for (let i = 0; i < roles.length; i += 1) {
    const role = roles[i].id;
    const getRoleCapabilities = await roleCapabilities(context, SYSTEM_USER, role);
    const hasSettings = getRoleCapabilities.some((capability) => {
      return capability.name.startsWith('SETTINGS');
    });
    if (hasSettings) {
      const input = { fromId: role, toId: securityActivityCapability.id, relationship_type: 'has-capability' };
      await createRelation(context, SYSTEM_USER, input);
    }
  }
  next();
};

export const down = async (next) => {
  next();
};
