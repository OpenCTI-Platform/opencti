import { createEntity, deleteElementById, listEntities, loadById, updateAttribute } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { ENTITY_TYPE_WORKSPACE } from '../schema/internalObject';

export const findById = (workspaceId) => {
  return loadById(workspaceId, ENTITY_TYPE_WORKSPACE);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_WORKSPACE], args);
};

export const addWorkspace = async (user, workspace) => {
  const created = await createEntity(user, workspace, ENTITY_TYPE_WORKSPACE);
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].ADDED_TOPIC, created, user);
};

export const workspaceEditField = async (user, workspaceId, input) => {
  const workspace = await updateAttribute(user, workspaceId, ENTITY_TYPE_WORKSPACE, input);
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, workspace, user);
};

export const workspaceDelete = async (user, workspaceId) => {
  await deleteElementById(user, workspaceId, ENTITY_TYPE_WORKSPACE);
  return workspaceId;
};

// region context
export const workspaceCleanContext = async (user, workspaceId) => {
  await delEditContext(user, workspaceId);
  return loadById(workspaceId, ENTITY_TYPE_WORKSPACE).then((userToReturn) =>
    notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, userToReturn, user)
  );
};

export const workspaceEditContext = async (user, workspaceId, input) => {
  await setEditContext(user, workspaceId, input);
  return loadById(workspaceId, ENTITY_TYPE_WORKSPACE).then((workspaceToReturn) =>
    notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, workspaceToReturn, user)
  );
};
// endregion
