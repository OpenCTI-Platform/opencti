import { assoc, dissoc, map, propOr, pipe } from 'ramda';
import { v5 as uuidv5 } from 'uuid';
import { createEntity, createRelation, deleteEntityById } from '../database/grakn';
import { TYPE_OPENCTI_INTERNAL } from '../database/utils';

export const addCapability = async (user, capability) => {
  const capabilityToCreate = assoc('internal_id_key', uuidv5(capability.name, uuidv5.DNS), capability);
  return createEntity(user, capabilityToCreate, 'Capability', { modelType: TYPE_OPENCTI_INTERNAL, noLog: true });
};

export const addRole = async (user, role) => {
  const capabilities = propOr([], 'capabilities', role);
  const roleToCreate = pipe(
    assoc('internal_id_key', uuidv5(role.name, uuidv5.DNS)),
    assoc('description', role.description ? role.description : ''),
    assoc('default_assignation', role.default_assignation ? role.default_assignation : false),
    dissoc('capabilities')
  )(role);
  const roleEntity = await createEntity(user, roleToCreate, 'Role', { modelType: TYPE_OPENCTI_INTERNAL, noLog: true });
  const relationPromises = map(
    (capabilityName) =>
      createRelation(
        user,
        roleEntity.id,
        {
          fromType: 'Role',
          fromRole: 'position',
          toId: uuidv5(capabilityName, uuidv5.DNS),
          toType: 'Capability',
          toRole: 'capability',
          through: 'role_capability',
        },
        { indexable: false, noLog: true }
      ),
    capabilities
  );
  await Promise.all(relationPromises);
  return roleEntity;
};
export const roleDelete = (user, roleId) => deleteEntityById(user, roleId, 'Role', { noLog: true });
