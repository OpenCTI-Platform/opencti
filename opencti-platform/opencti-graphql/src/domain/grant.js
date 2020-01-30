import { assoc, dissoc, map, pipe } from 'ramda';
import uuidv5 from 'uuid/v5';
import { createEntity, createRelation, deleteEntityById, TYPE_OPENCTI_INTERNAL } from '../database/grakn';

export const addCapability = async capability => {
  const capabilityToCreate = assoc('internal_id_key', uuidv5(capability.name, uuidv5.DNS), capability);
  return createEntity(capabilityToCreate, 'Capability', { modelType: TYPE_OPENCTI_INTERNAL });
};

export const addRole = async role => {
  const { capabilities } = role;
  const roleToCreate = pipe(
    assoc('internal_id_key', uuidv5(role.name, uuidv5.DNS)),
    assoc('editable', role.editable ? role.editable : true),
    dissoc('capabilities')
  )(role);
  const roleEntity = await createEntity(roleToCreate, 'Role', { modelType: TYPE_OPENCTI_INTERNAL });
  const relationPromises = map(
    capabilityId =>
      createRelation(roleEntity.id, {
        toId: capabilityId,
        fromRole: 'position',
        toRole: 'capability',
        through: 'role_capability'
      }),
    capabilities
  );
  await Promise.all(relationPromises);
  return roleEntity;
};
export const roleDelete = roleId => deleteEntityById(roleId);
