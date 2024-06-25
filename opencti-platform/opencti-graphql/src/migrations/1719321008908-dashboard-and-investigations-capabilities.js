import { logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { addCapability } from '../domain/grant';
import { createRelation } from '../database/middleware';
import { roleCapabilities } from '../domain/user';
import { ENTITY_TYPE_ROLE } from '../schema/internalObject';
import { elList, elLoadById, elReplace } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';

const message = '[MIGRATION] Split dashboard & investigations into 2 capabilities';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');

  // ------ Create 'Access investigations'
  const accessInvestigationsCapability = await addCapability(context, SYSTEM_USER, {
    name: 'INVESTIGATION',
    description: 'Access investigations',
    attribute_order: 1400
  });
  // ------ Create 'Create / Update investigations'
  const createUpdateInvestigationsCapability = await addCapability(context, SYSTEM_USER, {
    name: 'INVESTIGATION_INUPDATE',
    description: 'Create / Update investigations',
    attribute_order: 1410
  });
  // ------ Create 'Delete investigations'
  const deleteInvestigationsCapability = await addCapability(context, SYSTEM_USER, {
    name: 'INVESTIGATION_INUPDATE_INDELETE',
    description: 'Delete investigations',
    attribute_order: 1420
  });

  // ------ Update roles
  const callback = async (roles) => {
    for (let i = 0; i < roles.length; i += 1) {
      const roleId = roles[i].id;
      const capabilities = await roleCapabilities(context, SYSTEM_USER, roleId);
      // Select 'Access investigations' if 'Access dashboard & investigations' is selected
      const hasAccessDashboardCapability = capabilities.some((capability) => capability.name === 'EXPLORE');
      if (hasAccessDashboardCapability) {
        const input = { fromId: roleId, toId: accessInvestigationsCapability.id, relationship_type: 'has-capability' };
        await createRelation(context, SYSTEM_USER, input);
      }
      // Select 'Create / Update investigations' if 'Create / Update dashboard & investigations' is selected
      const hasCreateUpdateDashboardCapability = capabilities.some((capability) => capability.name === 'EXPLORE_EXUPDATE');
      if (hasCreateUpdateDashboardCapability) {
        const input = { fromId: roleId, toId: createUpdateInvestigationsCapability.id, relationship_type: 'has-capability' };
        await createRelation(context, SYSTEM_USER, input);
      }
      // Select 'Delete investigations' if 'Delete dashboard & investigations' is selected
      const hasDeleteDashboardCapability = capabilities.some((capability) => capability.name === 'EXPLORE_EXUPDATE_EXDELETE');
      if (hasDeleteDashboardCapability) {
        const input = { fromId: roleId, toId: deleteInvestigationsCapability.id, relationship_type: 'has-capability' };
        await createRelation(context, SYSTEM_USER, input);
      }
    }
  };
  const opts = { types: [ENTITY_TYPE_ROLE], callback };
  await elList(context, SYSTEM_USER, READ_INDEX_INTERNAL_OBJECTS, opts);

  // ------ Update description of Access dashboard & investigation => Access dashboard
  const accessDashboardCapability = await elLoadById(context, SYSTEM_USER, 'capability--c2f6d8be-29c7-5e7f-ab17-dfa14a349025');
  const accessDashboardCapabilityPatch = { description: 'Access dashboards' };
  await elReplace(accessDashboardCapability._index, accessDashboardCapability.internal_id, { doc: accessDashboardCapabilityPatch });

  // ------ Update description of Create / Update dashboard & investigation => Create / Update dashboard
  const createUpdateDashboardCapability = await elLoadById(context, SYSTEM_USER, 'capability--722e8727-5e8a-5b5e-8c1e-3b71b8415170');
  const createUpdateDashboardCapabilityPatch = { description: 'Create / Update dashboards' };
  await elReplace(createUpdateDashboardCapability._index, createUpdateDashboardCapability.internal_id, { doc: createUpdateDashboardCapabilityPatch });

  // ------ Update description of Delete dashboard & investigation => Delete dashboard
  const deleteDashboardCapability = await elLoadById(context, SYSTEM_USER, 'capability--287d57a8-5e9a-573f-8f22-ea321f5cbc90');
  const deleteDashboardCapabilityPatch = { description: 'Delete dashboards' };
  await elReplace(deleteDashboardCapability._index, deleteDashboardCapability.internal_id, { doc: deleteDashboardCapabilityPatch });

  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
