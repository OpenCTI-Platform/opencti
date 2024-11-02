import { executionContext, SYSTEM_USER } from '../utils/access';
import { addCapability } from '../domain/grant';
import { roleCapabilities } from '../domain/user';
import { elList } from '../database/engine';
import { ENTITY_TYPE_ROLE } from '../schema/internalObject';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { createRelation } from '../database/middleware';

export const up = async (next) => {
  const context = executionContext('migration');
  const frontendExportCapability = await addCapability(context, SYSTEM_USER, {
    name: 'KNOWLEDGE_KNFRONTENDEXPORT',
    description: 'Can use web interface export functions (PDF, PNG, etc.)',
    attribute_order: 160
  });
  // ------ Update roles to avoid any breaking change in the current behavior (all knowledge access = export in frontend)
  const callback = async (roles) => {
    for (let i = 0; i < roles.length; i += 1) {
      const roleId = roles[i].id;
      const capabilities = await roleCapabilities(context, SYSTEM_USER, roleId);
      // Select 'Access ingestion' if 'Access Data sharing & ingestion' or 'Access administration' is selected
      const hasKnowledgeAccessCapability = capabilities.some((capability) => capability.name === 'KNOWLEDGE');
      if (hasKnowledgeAccessCapability) {
        const input = { fromId: roleId, toId: frontendExportCapability.id, relationship_type: 'has-capability' };
        await createRelation(context, SYSTEM_USER, input);
      }
    }
  };
  const opts = { types: [ENTITY_TYPE_ROLE], callback };
  await elList(context, SYSTEM_USER, READ_INDEX_INTERNAL_OBJECTS, opts);
  next();
};

export const down = async (next) => {
  next();
};
