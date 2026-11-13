import { logMigration } from '../config/conf';
import { executionContext, KNOWLEDGE_KNHUNT, KNOWLEDGE_KNUPDATE, SYSTEM_USER } from '../utils/access';
import { addCapability } from '../domain/grant';
import { roleCapabilities } from '../modules/user/user-domain';
import { elList } from '../database/engine';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_ROLE } from '../schema/internalObject';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { createRelation } from '../database/middleware';
import { storeLoadById } from '../database/middleware-loader';
import { generateStandardId } from '../schema/identifier';

const message = '[MIGRATION] add the capability to launch hunts on security platforms';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  const capabilityId = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: KNOWLEDGE_KNHUNT });
  const existing = await storeLoadById(context, SYSTEM_USER, capabilityId, ENTITY_TYPE_CAPABILITY);
  const huntCapability = existing ?? await addCapability(context, SYSTEM_USER, {
    name: KNOWLEDGE_KNHUNT,
    description: 'Launch hunts on security platforms',
    attribute_order: 850,
  });
  // ------ Every role that creates and updates the knowledge keeps hunting as before; an administrator removes it per role
  let processed = 0;
  let granted = 0;
  const callback = async (roles) => {
    for (let i = 0; i < roles.length; i += 1) {
      const roleId = roles[i].id;
      const capabilities = await roleCapabilities(context, SYSTEM_USER, roleId);
      const updatesKnowledge = capabilities.some((capability) => capability.name.startsWith(KNOWLEDGE_KNUPDATE));
      const huntsAlready = capabilities.some((capability) => capability.name === KNOWLEDGE_KNHUNT);
      if (updatesKnowledge && !huntsAlready) {
        const input = { fromId: roleId, toId: huntCapability.id, relationship_type: 'has-capability' };
        await createRelation(context, SYSTEM_USER, input);
        granted += 1;
      }
      processed += 1;
    }
    logMigration.info(`${message} > ${processed} roles processed, ${granted} granted`);
  };
  const opts = { types: [ENTITY_TYPE_ROLE], callback };
  await elList(context, SYSTEM_USER, READ_INDEX_INTERNAL_OBJECTS, opts);
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
