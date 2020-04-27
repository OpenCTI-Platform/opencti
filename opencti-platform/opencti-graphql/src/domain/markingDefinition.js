import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  deleteEntityById,
  executeWrite,
  listEntities,
  loadEntityById,
  loadEntityByStixId,
  TYPE_STIX_DOMAIN,
  updateAttribute,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findById = (markingDefinitionId) => {
  if (markingDefinitionId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(markingDefinitionId, 'Marking-Definition');
  }
  return loadEntityById(markingDefinitionId, 'Marking-Definition');
};

export const findAll = (args) => {
  return listEntities(['Marking-Definition'], ['definition_type', 'definition'], args);
};

export const addMarkingDefinition = async (user, markingDefinition) => {
  const created = await createEntity(user, markingDefinition, 'Marking-Definition', { modelType: TYPE_STIX_DOMAIN });
  return notify(BUS_TOPICS.MarkingDefinition.ADDED_TOPIC, created, user);
};

export const markingDefinitionDelete = (user, markingDefinitionId) =>
  deleteEntityById(user, markingDefinitionId, 'Marking-Definition');

export const markingDefinitionEditField = (user, markingDefinitionId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, markingDefinitionId, 'Marking-Definition', input, wTx);
  }).then(async () => {
    const markingDefinition = await loadEntityById(markingDefinitionId, 'Marking-Definition');
    return notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, markingDefinition, user);
  });
};

export const markingDefinitionCleanContext = (user, markingDefinitionId) => {
  delEditContext(user, markingDefinitionId);
  return loadEntityById(markingDefinitionId, 'Marking-Definition').then((markingDefinition) =>
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, markingDefinition, user)
  );
};
export const markingDefinitionEditContext = (user, markingDefinitionId, input) => {
  setEditContext(user, markingDefinitionId, input);
  return loadEntityById(markingDefinitionId, 'Marking-Definition').then((markingDefinition) =>
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, markingDefinition, user)
  );
};
