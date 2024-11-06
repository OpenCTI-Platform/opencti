import { assoc, dissoc, pipe, uniq } from 'ramda';
import nconf from 'nconf';
import { createEntity, createRelation } from '../database/middleware';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_GROUP, ENTITY_TYPE_ROLE } from '../schema/internalObject';
import { RELATION_HAS_CAPABILITY } from '../schema/internalRelationship';
import { generateStandardId } from '../schema/identifier';
import { publishUserAction } from '../listener/UserActionListener';

export const addCapability = async (context, user, capability) => {
  return createEntity(context, user, capability, ENTITY_TYPE_CAPABILITY);
};

export const addRole = async (context, user, role) => {
  const capabilities = uniq(role.capabilities ?? []);
  const roleToCreate = pipe(
    assoc('description', role.description ? role.description : ''),
    dissoc('capabilities'),
  )(role);

  const completeRoleToCreate = {
    ...roleToCreate,
    can_manage_sensitive_config: role.can_manage_sensitive_config ?? false, // default when undefined is false
  };

  const { element, isCreation } = await createEntity(context, user, completeRoleToCreate, ENTITY_TYPE_ROLE, { complete: true });
  for (let index = 0; index < capabilities.length; index += 1) {
    const capability = capabilities[index];
    const generateToId = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: capability });
    await createRelation(context, user, { fromId: element.id, toId: generateToId, relationship_type: RELATION_HAS_CAPABILITY });
  }
  if (isCreation) {
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'administration',
      message: `creates role \`${role.name}\``,
      context_data: { id: element.id, entity_type: ENTITY_TYPE_ROLE, input: role }
    });
  }
  return element;
};

export const addGroup = async (context, user, group) => {
  // with SSO use-case in mind, we need to set a default confidence level if not provided (even if mandatory in GQL API)
  const group_confidence_level = group.group_confidence_level ?? {
    max_confidence: nconf.get('app:group_confidence_level:max_confidence_default') ?? 100,
    overrides: [],
  };

  const groupWithDefaultValues = {
    ...group,
    group_confidence_level,
    default_assignation: group.default_assignation ?? false,
    no_creators: group.no_creators ?? false,
    restrict_delete: group.restrict_delete ?? false,
    auto_new_marking: group.auto_new_marking ?? false
  };
  const { element, isCreation } = await createEntity(context, user, groupWithDefaultValues, ENTITY_TYPE_GROUP, { complete: true });
  if (isCreation) {
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'administration',
      message: `creates group \`${group.name}\``,
      context_data: { id: element.id, entity_type: ENTITY_TYPE_GROUP, input: group }
    });
  }
  return element;
};
