import { logApp } from '../config/conf';
import { AUTOMATION, AUTOMATION_AUTMANAGE, executionContext, SYSTEM_USER } from '../utils/access';
import { addCapability } from '../domain/grant';
import { createRelation } from '../database/middleware';
import { ENTITY_TYPE_ROLE } from '../schema/internalObject';
import { roleCapabilities } from '../domain/user';
import { fullEntitiesList } from '../database/middleware-loader';

const message = '[MIGRATION] create playbook capability';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');

  // ------ Create Automation capabilities
  const useAutomationCapability = await addCapability(context, SYSTEM_USER, {
    name: AUTOMATION,
    attribute_order: 2800,
    description: 'Use Playbooks'
  });
  const manageAutomationCapability = await addCapability(context, SYSTEM_USER, {
    name: AUTOMATION_AUTMANAGE,
    attribute_order: 2850,
    description: 'Manage Playbooks'
  });

  // ------ Add capabilities to Roles
  const roles = await fullEntitiesList(context, SYSTEM_USER, [ENTITY_TYPE_ROLE]);
  for (let i = 0; i < roles.length; i += 1) {
    const roleId = roles[i].id;
    const capabilities = await roleCapabilities(context, SYSTEM_USER, roleId);
    const hasAdminCapability = capabilities.some((capability) => capability.name === 'SETTINGS_SETACCESSES');
    const hasEnrichmentCapability = capabilities.some((capability) => capability.name === 'KNOWLEDGE_KNENRICHMENT');
    if (hasAdminCapability) {
      const parametersInput = { fromId: roleId, toId: manageAutomationCapability.id, relationship_type: 'has-capability' };
      await createRelation(context, SYSTEM_USER, parametersInput);
    }
    if (hasEnrichmentCapability) {
      const parametersInput = { fromId: roleId, toId: useAutomationCapability.id, relationship_type: 'has-capability' };
      await createRelation(context, SYSTEM_USER, parametersInput);
    }
  }

  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
