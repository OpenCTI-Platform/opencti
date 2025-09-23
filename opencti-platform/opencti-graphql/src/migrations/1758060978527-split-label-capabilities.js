import { logMigration } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { addCapability } from '../domain/grant';
import { fullEntitiesList } from '../database/middleware-loader';
import { ENTITY_TYPE_ROLE } from '../schema/internalObject';
import { roleCapabilities } from '../domain/user';
import { createRelation } from '../database/middleware';
import { elLoadById, elReplace } from '../database/engine';

const message = '[MIGRATION] Change set settings Capability';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  // ------ Update description of Manage labels & Attributes
  const taxonomiesCapability = await elLoadById(context, SYSTEM_USER, 'capability--0f78ff7d-7197-568f-ac8c-5d7842c07f0f');
  const taxonomiesCapabilityPatch = { description: 'Manage labels' };
  await elReplace(taxonomiesCapability._index, taxonomiesCapability.internal_id, { doc: taxonomiesCapabilityPatch });
  // Add capability
  const setVocab = await addCapability(context, SYSTEM_USER, { name: 'SETTINGS_SETVOCABULARIES', description: 'Manage vocabularies', attribute_order: 3410 });
  const setCaseTemplate = await addCapability(context, SYSTEM_USER, { name: 'SETTINGS_SETCASETEMPLATES', description: 'Manage case templates', attribute_order: 3420 });
  const setStatusTemplate = await addCapability(context, SYSTEM_USER, { name: 'SETTINGS_SETSTATUSTEMPLATES', description: 'Manage status templates', attribute_order: 3430 });
  const setKillChainPhase = await addCapability(context, SYSTEM_USER, { name: 'SETTINGS_SETKILLCHAINPHASES', description: 'Manage kill chain phases', attribute_order: 3440 });
  // Check existing roles that have SETTINGS_SETLABELS
  const roles = await fullEntitiesList(context, SYSTEM_USER, [ENTITY_TYPE_ROLE]);
  for (let i = 0; i < roles.length; i += 1) {
    const role = roles[i].id;
    const getRoleCapabilities = await roleCapabilities(context, SYSTEM_USER, role);
    const hasSetLabels = getRoleCapabilities.some((capability) => capability.name === 'SETTINGS_SETLABELS');
    if (hasSetLabels) {
      await createRelation(context, SYSTEM_USER, { fromId: role, toId: setVocab.id, relationship_type: 'has-capability' });
      await createRelation(context, SYSTEM_USER, { fromId: role, toId: setCaseTemplate.id, relationship_type: 'has-capability' });
      await createRelation(context, SYSTEM_USER, { fromId: role, toId: setStatusTemplate.id, relationship_type: 'has-capability' });
      await createRelation(context, SYSTEM_USER, { fromId: role, toId: setKillChainPhase.id, relationship_type: 'has-capability' });
    }
  }
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
