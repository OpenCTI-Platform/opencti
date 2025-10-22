import { logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { elLoadById, elReplace } from '../database/engine';
import { addCapability } from '../domain/grant';
import { fullEntitiesList } from '../database/middleware-loader';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_ROLE } from '../schema/internalObject';
import { roleCapabilities } from '../domain/user';
import { createRelation } from '../database/middleware';
import { generateStandardId } from '../schema/identifier';

const message = '[MIGRATION] Split "Delete / Merge knowledge" capability in two separated capabilities';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');
  // Rename Delete knowledge capability
  const deleteCapaStandardId = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: 'KNOWLEDGE_KNUPDATE_KNDELETE' });
  const deleteCapability = await elLoadById(context, SYSTEM_USER, deleteCapaStandardId);
  if (deleteCapability) {
    const deleteCapabilityPatch = { description: 'Delete knowledge' };
    await elReplace(deleteCapability._index, deleteCapability.internal_id, { doc: deleteCapabilityPatch });
  }
  // Add Merge knowledge capability
  const mergeKnowledgeCapa = await addCapability(
    context,
    SYSTEM_USER,
    { name: 'KNOWLEDGE_KNUPDATE_KNMERGE', description: 'Merge knowledge', attribute_order: 305 }
  );
  // Add merge knowledge capability to roles having former delete/merge capability
  const roles = await fullEntitiesList(context, SYSTEM_USER, [ENTITY_TYPE_ROLE]);
  for (let i = 0; i < roles.length; i += 1) {
    const role = roles[i].id;
    const getRoleCapabilities = await roleCapabilities(context, SYSTEM_USER, role);
    const hasDeleteMergeCapa = getRoleCapabilities.some((capability) => capability.name === 'KNOWLEDGE_KNUPDATE_KNDELETE');
    if (hasDeleteMergeCapa) {
      await createRelation(context, SYSTEM_USER, { fromId: role, toId: mergeKnowledgeCapa.id, relationship_type: 'has-capability' });
    }
  }

  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
