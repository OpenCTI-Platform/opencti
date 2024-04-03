import { executionContext, SYSTEM_USER } from '../utils/access';
import { addCapability } from '../domain/grant';
import { elLoadById, elReplace } from '../database/engine';

export const up = async (next) => {
  const context = executionContext('migration');
  // ------ Add Manage Public Dashboards capability
  await addCapability(context, SYSTEM_USER, {
    name: 'EXPLORE_EXUPDATE_PUBLISH',
    description: 'Manage Public Dashboards',
    attribute_order: 1300
  });
  // ------ Access exploration renaming
  const accessCapability = await elLoadById(context, SYSTEM_USER, 'capability--c2f6d8be-29c7-5e7f-ab17-dfa14a349025');
  const accessCapabilityPatch = { description: 'Access Dashboards and investigations' };
  await elReplace(accessCapability._index, accessCapability.internal_id, { doc: accessCapabilityPatch });
  // ------ Create / Update exploration renaming
  const updateCapability = await elLoadById(context, SYSTEM_USER, 'capability--722e8727-5e8a-5b5e-8c1e-3b71b8415170');
  const updateCapabilityPatch = { description: 'Create / Update Dashboards and investigations' };
  await elReplace(updateCapability._index, updateCapability.internal_id, { doc: updateCapabilityPatch });
  // ------ Delete exploration renaming
  const deleteCapability = await elLoadById(context, SYSTEM_USER, 'capability--287d57a8-5e9a-573f-8f22-ea321f5cbc90');
  const deleteCapabilityPatch = { description: 'Delete Dashboards and investigations' };
  await elReplace(deleteCapability._index, deleteCapability.internal_id, { doc: deleteCapabilityPatch });
  next();
};

export const down = async (next) => {
  next();
};
