import { logMigration } from '../config/conf';
import { executionContext, KNOWLEDGE_KNFORMINTAKE, KNOWLEDGE_KNUPDATE, SYSTEM_USER } from '../utils/access';
import { fullEntitiesList } from '../database/middleware-loader';
import { createRelation } from '../database/middleware';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_ROLE } from '../schema/internalObject';
import { RELATION_HAS_CAPABILITY, RELATION_HAS_CAPABILITY_IN_DRAFT } from '../schema/internalRelationship';
import { roleCapabilities } from '../modules/user/user-domain';
import { generateStandardId } from '../schema/identifier';
import { createCapabilities, FORM_INTAKE_CAPABILITY } from '../database/data-initialization';
import type { BasicCapabilityEntity } from '../types/store';

const message = '[MIGRATION] Add KNOWLEDGE_KNFORMINTAKE capability and grant it to roles with Create / Update knowledge';

export const up = async (next: (error?: Error) => void) => {
  logMigration.info(`${message} > started`);

  const context = executionContext('migration');

  // 1. Create the capability
  await createCapabilities(context, [FORM_INTAKE_CAPABILITY], 'KNOWLEDGE_');

  // 2. Roles that can already create / update knowledge keep submitting forms: grant the form capability
  // in each scope (main, draft) where they hold Create / Update knowledge. Import is not required.
  const roles = await fullEntitiesList(context, SYSTEM_USER, [ENTITY_TYPE_ROLE], {});
  const capabilityId = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: KNOWLEDGE_KNFORMINTAKE });
  let granted = 0;
  for (const role of roles) {
    for (const relationshipType of [RELATION_HAS_CAPABILITY, RELATION_HAS_CAPABILITY_IN_DRAFT]) {
      const capabilities = await roleCapabilities(context, SYSTEM_USER, role.id, relationshipType) as BasicCapabilityEntity[];
      // Matched by inclusion, as the capabilities are at runtime: a child of KNUPDATE (KNDELETE, ...) implies it
      const canUpdate = capabilities.some((capability) => capability.name.includes(KNOWLEDGE_KNUPDATE));
      const alreadyGranted = capabilities.some((capability) => capability.name === KNOWLEDGE_KNFORMINTAKE);
      if (canUpdate && !alreadyGranted) {
        await createRelation(context, SYSTEM_USER, { fromId: role.id, toId: capabilityId, relationship_type: relationshipType });
        granted += 1;
      }
    }
  }

  logMigration.info(`${message} > done (${granted} grants on ${roles.length} roles)`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
