import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  deleteEntityById,
  executeWrite,
  listEntities,
  loadEntityById,
  updateAttribute,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { ENTITY_TYPE_MARKING } from '../utils/idGenerator';

export const findById = (markingDefinitionId) => {
  return loadEntityById(markingDefinitionId, ENTITY_TYPE_MARKING);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_MARKING], ['definition_type', 'definition'], args);
};

export const addMarkingDefinition = async (user, markingDefinition) => {
  const created = await createEntity(user, markingDefinition, ENTITY_TYPE_MARKING);
  return notify(BUS_TOPICS.MarkingDefinition.ADDED_TOPIC, created, user);
};

export const markingDefinitionDelete = (user, markingDefinitionId) =>
  deleteEntityById(user, markingDefinitionId, ENTITY_TYPE_MARKING);

export const markingDefinitionEditField = (user, markingDefinitionId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, markingDefinitionId, ENTITY_TYPE_MARKING, input, wTx);
  }).then(async () => {
    const markingDefinition = await loadEntityById(markingDefinitionId, ENTITY_TYPE_MARKING);
    return notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, markingDefinition, user);
  });
};

export const markingDefinitionCleanContext = (user, markingDefinitionId) => {
  delEditContext(user, markingDefinitionId);
  return loadEntityById(markingDefinitionId, ENTITY_TYPE_MARKING).then((markingDefinition) =>
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, markingDefinition, user)
  );
};
export const markingDefinitionEditContext = (user, markingDefinitionId, input) => {
  setEditContext(user, markingDefinitionId, input);
  return loadEntityById(markingDefinitionId, ENTITY_TYPE_MARKING).then((markingDefinition) =>
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, markingDefinition, user)
  );
};
