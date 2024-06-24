import { logApp } from '../config/conf';
import { elList, elLoadById, elReplace } from '../database/engine';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { addCapability } from '../domain/grant';
import { createRelation } from '../database/middleware';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { ENTITY_TYPE_ROLE } from '../schema/internalObject';
import { roleCapabilities } from '../domain/user';

const message = '[MIGRATION] update settings capabilities';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');

  // ------ Create Access Administration Parameters
  const parametersCapability = await addCapability(context, SYSTEM_USER, {
    name: 'SETTINGS_SETPARAMETERS',
    attribute_order: 3100,
    description: 'Access administration parameters'
  });
  // ------ Create Manage customization
  const customizationCapability = await addCapability(context, SYSTEM_USER, {
    name: 'SETTINGS_SETCUSTOMIZATION',
    attribute_order: 3350,
    description: 'Manage customization'
  });
  // ------ Create Access to file indexing
  const fileIndexingCapability = await addCapability(context, SYSTEM_USER, {
    name: 'SETTINGS_FILEINDEXING',
    attribute_order: 3600,
    description: 'Access to file indexing'
  });
  // ------ Create Access to support
  const supportCapability = await addCapability(context, SYSTEM_USER, {
    name: 'SETTINGS_SUPPORT',
    attribute_order: 3700,
    description: 'Access to support'
  });

  // ------ Update roles
  const callback = async (roles) => {
    for (let i = 0; i < roles.length; i += 1) {
      const roleId = roles[i].id;
      const capabilities = await roleCapabilities(context, SYSTEM_USER, roleId);
      const hasAdminCapability = capabilities.some((capability) => capability.name.startsWith('SETTINGS'));
      if (hasAdminCapability) {
        // Select 'Access Administration Parameters'
        const parametersInput = { fromId: roleId, toId: parametersCapability.id, relationship_type: 'has-capability' };
        await createRelation(context, SYSTEM_USER, parametersInput);
        // Select 'Manage customization'
        const customizationInput = { fromId: roleId, toId: customizationCapability.id, relationship_type: 'has-capability' };
        await createRelation(context, SYSTEM_USER, customizationInput);
        // Select 'Access to file indexing'
        const fileIndexingInput = { fromId: roleId, toId: fileIndexingCapability.id, relationship_type: 'has-capability' };
        await createRelation(context, SYSTEM_USER, fileIndexingInput);
        // Select 'Access to support'
        const supportInput = { fromId: roleId, toId: supportCapability.id, relationship_type: 'has-capability' };
        await createRelation(context, SYSTEM_USER, supportInput);
      }
    }
  };
  const opts = { types: [ENTITY_TYPE_ROLE], callback };
  await elList(context, SYSTEM_USER, READ_INDEX_INTERNAL_OBJECTS, opts);

  // ------ Update description of Access Administration
  const adminCapability = await elLoadById(context, SYSTEM_USER, 'capability--bb5ec6d0-0ffb-5b04-8fcf-c0d4447209a6');
  const adminCapabilityPatch = { description: 'Access to admin functionalities' };
  await elReplace(adminCapability._index, adminCapability.internal_id, { doc: adminCapabilityPatch });
  // ------ Update description of Manage labels & Attributes
  const taxonomiesCapability = await elLoadById(context, SYSTEM_USER, 'capability--0f78ff7d-7197-568f-ac8c-5d7842c07f0f');
  const taxonomiesCapabilityPatch = { description: 'Manage taxonomies' };
  await elReplace(taxonomiesCapability._index, taxonomiesCapability.internal_id, { doc: taxonomiesCapabilityPatch });
  // ------ Update description of Access security activity
  const activityCapability = await elLoadById(context, SYSTEM_USER, 'capability--3d467062-f044-50da-902c-627cfa739444');
  const activityCapabilityPatch = { description: 'Access security activity' };
  await elReplace(activityCapability._index, activityCapability.internal_id, { doc: activityCapabilityPatch });

  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
