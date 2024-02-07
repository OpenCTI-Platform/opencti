import { executionContext, SYSTEM_USER } from '../utils/access';
import { elLoadById, elReplace } from '../database/engine';

export const up = async (next) => {
  const context = executionContext('migration');
  // ------ Access data sharing & ingestion
  const accessTaxii = await elLoadById(context, SYSTEM_USER, 'capability--d258afde-7a8a-5917-8b4b-83119d3f8e52');
  const accessPatch = { description: 'Access data sharing & ingestion' };
  await elReplace(accessTaxii._index, accessTaxii.internal_id, { doc: accessPatch });
  // ------ Manage data sharing & ingestion
  const manageTaxii = await elLoadById(context, SYSTEM_USER, 'capability--24f9401c-8a77-59d5-8a8f-4ea21a1a733b');
  const managePatch = { description: 'Manage data sharing & ingestion' };
  await elReplace(manageTaxii._index, manageTaxii.internal_id, { doc: managePatch });
  next();
};

export const down = async (next) => {
  next();
};
