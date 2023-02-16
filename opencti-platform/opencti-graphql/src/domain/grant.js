import { assoc, dissoc, pipe } from 'ramda';
import { createEntity, createRelation } from '../database/middleware';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_GROUP, ENTITY_TYPE_ROLE } from '../schema/internalObject';
import { RELATION_HAS_CAPABILITY } from '../schema/internalRelationship';
import { generateStandardId } from '../schema/identifier';
import { logAudit } from '../config/conf';
import { GROUP_CREATION, ROLE_CREATION } from '../config/audit';

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
    return createRelation(context, user, {
      fromId: roleEntity.id,
      toId: generateToId,
      relationship_type: RELATION_HAS_CAPABILITY,
    });
  });
  await Promise.all(relationPromises);
  // Audit log
  logAudit.info(user, ROLE_CREATION, { role });
  return roleEntity;
};

export const addGroup = async (context, user, group) => {
  const groupEntity = await createEntity(context, user, group, ENTITY_TYPE_GROUP);
  // Audit log
  logAudit.info(user, GROUP_CREATION, { group });
  return groupEntity;
};
