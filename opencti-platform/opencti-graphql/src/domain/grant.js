import { assoc, dissoc, pipe } from 'ramda';
import { createEntity, createRelation } from '../database/middleware';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_GROUP, ENTITY_TYPE_ROLE } from '../schema/internalObject';
import { RELATION_HAS_CAPABILITY } from '../schema/internalRelationship';
import { generateStandardId } from '../schema/identifier';
import { publishUserAction } from '../listener/UserActionListener';

export const addCapability = async (context, user, capability) => {
  return createEntity(context, user, capability, ENTITY_TYPE_CAPABILITY);
};

export const addRole = async (context, user, role) => {
  const capabilities = role.capabilities ?? [];
  const roleToCreate = pipe(
    assoc('description', role.description ? role.description : ''),
    dissoc('capabilities'),
  )(role);
  const roleEntity = await createEntity(context, user, roleToCreate, ENTITY_TYPE_ROLE);
  const relationPromises = capabilities.map(async (capabilityName) => {
    const generateToId = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: capabilityName });
    return createRelation(context, user, { fromId: roleEntity.id, toId: generateToId, relationship_type: RELATION_HAS_CAPABILITY });
  });
  await Promise.all(relationPromises);
  await publishUserAction({
    user,
    event_type: 'admin',
    status: 'success',
    message: `creates role \`${role.name}\``,
    context_data: { entity_type: ENTITY_TYPE_ROLE, operation: 'create', input: role }
  });
  return roleEntity;
};

export const addGroup = async (context, user, group) => {
  const groupWithDefaultValues = {
    ...group,
    default_assignation: group.default_assignation ?? false,
    auto_new_marking: group.auto_new_marking ?? false
  };
  const groupEntity = await createEntity(context, user, groupWithDefaultValues, ENTITY_TYPE_GROUP);
  await publishUserAction({
    user,
    event_type: 'admin',
    status: 'success',
    message: `creates group \`${group.name}\``,
    context_data: { entity_type: ENTITY_TYPE_GROUP, operation: 'create', input: group }
  });
  return groupEntity;
};
