import { executionContext, SYSTEM_USER } from '../utils/access';
import { fullEntitiesList } from '../database/middleware-loader';
import { createRelation } from '../database/middleware';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_ROLE } from '../schema/internalObject';
import { logApp } from '../config/conf';
import { API_ACCESS_CAPABILITIES, createCapabilities } from '../database/data-initialization';
import { generateStandardId } from '../schema/identifier';

const message = '[MIGRATION] Add APIACCESS capability and grant to all roles';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');

  // 1. Create Capability
  await createCapabilities(context, [API_ACCESS_CAPABILITIES]);

  // 2. Grant to ALL existing Roles
  const roles = await fullEntitiesList(context, SYSTEM_USER, [ENTITY_TYPE_ROLE], {});
  for (let i = 0; i < roles.length; i += 1) {
    const roleId = roles[i].id;
    // Relation to token
    const tokenCapabilityId = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: 'APIACCESS_USETOKEN' });
    const inputToken = { fromId: roleId, toId: tokenCapabilityId, relationship_type: 'has-capability' };
    await createRelation(context, SYSTEM_USER, inputToken);
    // Relation to basic auth
    const basicCapabilityId = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: 'APIACCESS_USEBASICAUTH' });
    const inputBasic = { fromId: roleId, toId: basicCapabilityId, relationship_type: 'has-capability' };
    await createRelation(context, SYSTEM_USER, inputBasic);
  }

  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
