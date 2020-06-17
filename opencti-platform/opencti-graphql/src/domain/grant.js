import { assoc, dissoc, map, propOr, pipe } from 'ramda';
import { createEntity, createRelation, deleteEntityById } from '../database/grakn';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_ROLE, generateInternalId } from '../utils/idGenerator';

export const addCapability = async (user, capability) => {
  return createEntity(user, capability, ENTITY_TYPE_CAPABILITY, { noLog: true });
};

export const addRole = async (user, role) => {
  const capabilities = propOr([], 'capabilities', role);
  const roleToCreate = pipe(
    assoc('description', role.description ? role.description : ''),
    assoc('default_assignation', role.default_assignation ? role.default_assignation : false),
    dissoc('capabilities')
  )(role);
  const roleEntity = await createEntity(user, roleToCreate, ENTITY_TYPE_ROLE, { noLog: true });
  const relationPromises = map(
    (capabilityName) =>
      createRelation(
        user,
        {
          fromId: roleEntity.id,
          fromType: ENTITY_TYPE_ROLE,
          fromRole: 'position',
          toId: generateInternalId(ENTITY_TYPE_CAPABILITY, { name: capabilityName }),
          toType: ENTITY_TYPE_CAPABILITY,
          toRole: 'capability',
          through: 'role_capability',
        },
        { noLog: true }
      ),
    capabilities
  );
  await Promise.all(relationPromises);
  return roleEntity;
};
export const roleDelete = (user, roleId) => deleteEntityById(user, roleId, ENTITY_TYPE_ROLE, { noLog: true });
