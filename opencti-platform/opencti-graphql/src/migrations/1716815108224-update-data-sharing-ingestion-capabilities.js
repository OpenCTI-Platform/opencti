import { logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { createCapabilities } from '../database/data-initialization';
import { elLoadById, elReplace } from '../database/engine';
import { findRoles, roleCapabilities } from '../domain/user';
import { addCapability } from '../domain/grant';
import { createRelation } from '../database/middleware';
import { listAllEntities } from '../database/middleware-loader';
import { ENTITY_TYPE_ROLE } from '../schema/internalObject';

const message = '[MIGRATION] Split data sharing & ingestion into 2 capabilities';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');

  // ------ Create Access ingestion
  const accessIngestionCapability= await addCapability(context, SYSTEM_USER, {
    name: 'INGESTION',
    attribute_order: 2600,
    description: 'Access ingestion'
  });
  // ------ Create Manage ingestion
  const manageIngestionCapability= await addCapability(context, SYSTEM_USER, {
    name: 'INGESTION_SETINGESTIONS',
    description: 'Manage ingestion',
    attribute_order: 2610
  });

  // ------ Update roles
  const roles = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_ROLE], {});
  for (const role of roles) {
    const capabilities = await roleCapabilities(context, SYSTEM_USER, role.id);
    // Select 'Access ingestion' if 'Access Data sharing & ingestion' is selected
    const hasAccessDataSharingCapability = capabilities.some((capability) => capability.name === 'TAXIIAPI');
    if (hasAccessDataSharingCapability) {
      const input = { fromId: role.id, toId: accessIngestionCapability.id, relationship_type: 'has-capability' };
      await createRelation(context, SYSTEM_USER, input);
    }
    // Select 'Manage ingestion' if 'Manage Data sharing & ingestion' is selected
    const hasManageDataSharingCapability = capabilities.some((capability) => capability.name === 'TAXIIAPI_SETCOLLECTIONS');
    if (hasManageDataSharingCapability) {
      const input = { fromId: role.id, toId: manageIngestionCapability.id, relationship_type: 'has-capability' };
      await createRelation(context, SYSTEM_USER, input);
    }
  }

  // ------ Update Attribute_order and name of Manage CSV mappers
  const CSVCapability = await elLoadById(context, SYSTEM_USER, 'capability--5407e8a4-0ff9-5253-89b1-c01a92ad9453');
  const CSVCapabilityPatch = { name: 'INGESTION_SETCSVMAPPERS', attribute_order: 2620 };
  await elReplace(CSVCapability._index, CSVCapability.internal_id, { doc: CSVCapabilityPatch });

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
  const byPassRefCapabilityPatch = { name: 'KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE', description: 'Bypass enforced reference', attribute_order: 320 };
  await elReplace(byPassRefCapability._index, byPassRefCapability.internal_id, { doc: byPassRefCapabilityPatch });

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
