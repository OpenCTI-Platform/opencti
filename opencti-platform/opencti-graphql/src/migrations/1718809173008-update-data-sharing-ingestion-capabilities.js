import { logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { elList, elLoadById, elReplace } from '../database/engine';
import { roleCapabilities } from '../domain/user';
import { addCapability } from '../domain/grant';
import { createRelation } from '../database/middleware';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_ROLE } from '../schema/internalObject';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { generateStandardId } from '../schema/identifier';

const message = '[MIGRATION] Split data sharing & ingestion into 2 capabilities';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');

  // ------ Create Access ingestion
  const accessIngestionCapability = await addCapability(context, SYSTEM_USER, {
    name: 'INGESTION',
    attribute_order: 2600,
    description: 'Access ingestion'
  });
  // ------ Create Manage ingestion
  const manageIngestionCapability = await addCapability(context, SYSTEM_USER, {
    name: 'INGESTION_SETINGESTIONS',
    description: 'Manage ingestion',
    attribute_order: 2610
  });

  // ------ Update roles
  const callback = async (roles) => {
    for (let i = 0; i < roles.length; i += 1) {
      const roleId = roles[i].id;
      const capabilities = await roleCapabilities(context, SYSTEM_USER, roleId);
      // Select 'Access ingestion' if 'Access Data sharing & ingestion' or 'Access administration' is selected
      const hasAccessDataSharingCapability = capabilities.some((capability) => capability.name.startsWith('SETTINGS') || capability.name === 'TAXIIAPI');
      if (hasAccessDataSharingCapability) {
        const input = { fromId: roleId, toId: accessIngestionCapability.id, relationship_type: 'has-capability' };
        await createRelation(context, SYSTEM_USER, input);
      }
      // Select 'Manage ingestion' if 'Manage Data sharing & ingestion' or 'Access administration' is selected
      const hasManageDataSharingCapability = capabilities.some((capability) => capability.name.startsWith('SETTINGS') || capability.name === 'TAXIIAPI_SETCOLLECTIONS');
      if (hasManageDataSharingCapability) {
        const input = { fromId: roleId, toId: manageIngestionCapability.id, relationship_type: 'has-capability' };
        await createRelation(context, SYSTEM_USER, input);
      }
    }
  };
  const opts = { types: [ENTITY_TYPE_ROLE], callback };
  await elList(context, SYSTEM_USER, READ_INDEX_INTERNAL_OBJECTS, opts);

  // ------ Update Attribute_order and name of Manage CSV mappers
  const CSVCapability = await elLoadById(context, SYSTEM_USER, 'capability--5407e8a4-0ff9-5253-89b1-c01a92ad9453');
  if (CSVCapability) {
    const CSVCapabilityPatch = {
      name: 'CSVMAPPERS',
      attribute_order: 2700,
      standard_id: generateStandardId(ENTITY_TYPE_CAPABILITY, { name: 'CSVMAPPERS' }),
    };
    await elReplace(CSVCapability._index, CSVCapability.internal_id, { doc: CSVCapabilityPatch });
  }

  // ------ Update description of Access data sharing & ingestion => Access data sharing
  const accessDataCapability = await elLoadById(context, SYSTEM_USER, 'capability--d258afde-7a8a-5917-8b4b-83119d3f8e52');
  const accessDataCapabilityPatch = { description: 'Access data sharing' };
  await elReplace(accessDataCapability._index, accessDataCapability.internal_id, { doc: accessDataCapabilityPatch });

  // ------ Update description of Manage data sharing & ingestion => Manage data sharing
  const manageDataCapability = await elLoadById(context, SYSTEM_USER, 'capability--24f9401c-8a77-59d5-8a8f-4ea21a1a733b');
  const manageDataCapabilityPatch = { description: 'Manage data sharing' };
  await elReplace(manageDataCapability._index, manageDataCapability.internal_id, { doc: manageDataCapabilityPatch });

  // ------ Update name + description + attribute_order of BYPASSREFERENCE
  const byPassRefCapability = await elLoadById(context, SYSTEM_USER, 'capability--7ad2a72e-8dcd-569c-8d3f-469dce6fa6b0');
  if (byPassRefCapability) {
    const byPassRefCapabilityPatch = {
      name: 'KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE',
      description: 'Bypass enforced reference',
      attribute_order: 320,
      standard_id: generateStandardId(ENTITY_TYPE_CAPABILITY, { name: 'KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE' }),
    };
    await elReplace(byPassRefCapability._index, byPassRefCapability.internal_id, { doc: byPassRefCapabilityPatch });
  }

  // ------ Update attribute_order of Connector API usage
  const connectorAPICapability = await elLoadById(context, SYSTEM_USER, 'capability--3b45a9ef-b336-5539-be9a-58e3509648e9');
  const connectorAPICapabilityPatch = { attribute_order: 2300 };
  await elReplace(connectorAPICapability._index, connectorAPICapability.internal_id, { doc: connectorAPICapabilityPatch });

  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
