import { logMigration } from '../config/conf';
import { executionContext, SETTINGS_SETCUSTOMFIELDS, SETTINGS_SETCUSTOMIZATION, SYSTEM_USER } from '../utils/access';
import { fullEntitiesList } from '../database/middleware-loader';
import { createRelation } from '../database/middleware';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_ROLE } from '../schema/internalObject';
import { RELATION_HAS_CAPABILITY } from '../schema/internalRelationship';
import { roleCapabilities } from '../modules/user/user-domain';
import { generateStandardId } from '../schema/identifier';
import { createCapabilities } from '../database/data-initialization';
import { CUSTOM_FIELDS_CAPABILITY } from '../schema/capabilities';
import type { BasicCapabilityEntity } from '../types/store';

const message = '[MIGRATION] Add SETTINGS_SETCUSTOMFIELDS capability and grant it to roles with Manage customization';

export const up = async (next: (error?: Error) => void) => {
  logMigration.info(`${message} > started`);

  const context = executionContext('migration');

  // 1. Create the capability
  await createCapabilities(context, [CUSTOM_FIELDS_CAPABILITY], 'SETTINGS_');

  // 2. Roles that can already manage the customization keep managing the custom fields: grant them the capability.
  // Manage customization is not a draft capability: only the main scope is concerned.
  const roles = await fullEntitiesList(context, SYSTEM_USER, [ENTITY_TYPE_ROLE], {});
  const capabilityId = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: SETTINGS_SETCUSTOMFIELDS });
  let granted = 0;
  for (const role of roles) {
    const capabilities = await roleCapabilities(context, SYSTEM_USER, role.id) as BasicCapabilityEntity[];
    // Matched by inclusion, as the capabilities are at runtime
    const canCustomize = capabilities.some((capability) => capability.name.includes(SETTINGS_SETCUSTOMIZATION));
    const alreadyGranted = capabilities.some((capability) => capability.name === SETTINGS_SETCUSTOMFIELDS);
    if (canCustomize && !alreadyGranted) {
      await createRelation(context, SYSTEM_USER, { fromId: role.id, toId: capabilityId, relationship_type: RELATION_HAS_CAPABILITY });
      granted += 1;
    }
  }

  logMigration.info(`${message} > done (${granted} grants on ${roles.length} roles)`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
