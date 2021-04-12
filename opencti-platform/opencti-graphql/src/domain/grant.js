import { assoc, dissoc, map, propOr, pipe } from 'ramda';
import { createEntity, createRelation, deleteElementById } from '../database/middleware';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_ROLE } from '../schema/internalObject';
import { RELATION_HAS_CAPABILITY } from '../schema/internalRelationship';
import { generateStandardId } from '../schema/identifier';
import { logAudit } from '../config/conf';
import { ROLE_CREATION } from '../config/audit';

export const addCapability = async (user, capability) => {
  return createEntity(user, capability, ENTITY_TYPE_CAPABILITY);
};

export const addRole = async (user, role) => {
  const capabilities = propOr([], 'capabilities', role);
  const roleToCreate = pipe(
    assoc('description', role.description ? role.description : ''),
    assoc('default_assignation', role.default_assignation ? role.default_assignation : false),
    dissoc('capabilities')
  )(role);
  const roleEntity = await createEntity(user, roleToCreate, ENTITY_TYPE_ROLE);
  const relationPromises = map(async (capabilityName) => {
    const generateToId = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: capabilityName });
    return createRelation(user, {
      fromId: roleEntity.id,
      toId: generateToId,
      relationship_type: RELATION_HAS_CAPABILITY,
    });
  }, capabilities);
  await Promise.all(relationPromises);
  // Audit log
  logAudit.info(user, ROLE_CREATION, { role });
  return roleEntity;
};

export const roleDelete = (user, roleId) => deleteElementById(user, roleId, ENTITY_TYPE_ROLE);
