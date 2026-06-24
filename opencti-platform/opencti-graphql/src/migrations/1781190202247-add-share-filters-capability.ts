import { logMigration } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { fullEntitiesList } from '../database/middleware-loader';
import { createRelation } from '../database/middleware';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_ROLE } from '../schema/internalObject';
import { roleCapabilities } from '../domain/user';
import { generateStandardId } from '../schema/identifier';
import { createCapabilities, SHARE_FILTERS_CAPABILITY } from '../database/data-initialization';
import type { BasicCapabilityEntity } from '../types/store';

const message = '[MIGRATION] Add KNOWLEDGE_KNSHAREFILTERS capability and grant to roles with KNOWLEDGE';

export const up = async (next: (error?: Error) => void) => {
  logMigration.info(`${message} > started`);

  const context = executionContext('migration');

  // 1. Create Capability
  await createCapabilities(context, [SHARE_FILTERS_CAPABILITY], 'KNOWLEDGE_');

  // 2. Grant to every existing role that already has the KNOWLEDGE capability
  const roles = await fullEntitiesList(context, SYSTEM_USER, [ENTITY_TYPE_ROLE], {});
  const capabilityId = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: 'KNOWLEDGE_KNSHAREFILTERS' });
  const createRelationPromises = roles.map(async (role) => {
    const roleId = role.id;
    const capabilities = await roleCapabilities(context, SYSTEM_USER, roleId) as BasicCapabilityEntity[];
    const hasKnowledgeCapability = capabilities.some((capability) => capability.name === 'KNOWLEDGE');
    if (hasKnowledgeCapability) {
      const input = { fromId: roleId, toId: capabilityId, relationship_type: 'has-capability' };
      return createRelation(context, SYSTEM_USER, input);
    }
    return undefined;
  });
  await Promise.all(createRelationPromises);

  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
