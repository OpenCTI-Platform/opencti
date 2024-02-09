import { executionContext, SYSTEM_USER, TAXIIAPI_SETCOLLECTIONS } from '../utils/access';
import { elReplace } from '../database/engine';
import { listAllEntities } from '../database/middleware-loader';
import { ENTITY_TYPE_CAPABILITY } from '../schema/internalObject';

export const up = async (next) => {
  const context = executionContext('migration');
  // ------ Access data sharing & ingestion
  const capabilities = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_CAPABILITY]);
  const accessTaxii = capabilities.find((capa) => capa.name === 'TAXIIAPI');
  const accessPatch = { description: 'Access data sharing & ingestions' };
  await elReplace(accessTaxii._index, accessTaxii.internal_id, { doc: accessPatch });
  // ------ Manage data sharing & ingestion
  const manageTaxii = capabilities.find((capa) => capa.name === TAXIIAPI_SETCOLLECTIONS);
  const managePatch = { description: 'Manage data sharing & ingestions' };
  await elReplace(manageTaxii._index, manageTaxii.internal_id, { doc: managePatch });
  next();
};

export const down = async (next) => {
  next();
};
