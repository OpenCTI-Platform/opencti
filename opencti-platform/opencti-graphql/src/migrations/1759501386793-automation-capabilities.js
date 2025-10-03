import { logApp } from '../config/conf';
import { elList } from '../database/engine';
import { AUTOMATION, AUTOMATION_AUTOMATIONMANAGE, executionContext, SYSTEM_USER } from '../utils/access';
import { addCapability } from '../domain/grant';
import { createRelation } from '../database/middleware';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { ENTITY_TYPE_ROLE } from '../schema/internalObject';
import { roleCapabilities } from '../domain/user';

const message = '[MIGRATION] create playbook capability';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');

  // ------ Create Automation capabilities
  const UseAutomationCapability = await addCapability(context, SYSTEM_USER, {
    name: AUTOMATION,
    attribute_order: 2800,
    description: 'Use Playbooks'
  });
  const manageAutomationCapability = await addCapability(context, SYSTEM_USER, {
    name: AUTOMATION_AUTOMATIONMANAGE,
    attribute_order: 2850,
    description: 'Manage Playbooks'
  });

  // ------ Add PLAYBOOK to all Roles that have
  const callback = async (roles) => {
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
        const parametersInput = { fromId: roleId, toId: UseAutomationCapability.id, relationship_type: 'has-capability' };
        await createRelation(context, SYSTEM_USER, parametersInput);
      }
    }
  };
  const opts = { types: [ENTITY_TYPE_ROLE], callback };
  await elList(context, SYSTEM_USER, READ_INDEX_INTERNAL_OBJECTS, opts);

  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
