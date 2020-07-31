import { assoc } from 'ramda';
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
import { ENTITY_TYPE_MARKING_DEFINITION } from '../utils/idGenerator';

export const findById = (markingDefinitionId) => {
  return loadEntityById(markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_MARKING_DEFINITION], ['definition_type', 'definition'], args);
};

export const addMarkingDefinition = async (user, markingDefinition) => {
  const created = await createEntity(
    user,
    assoc(
      'x_opencti_color',
      markingDefinition.x_opencti_color ? markingDefinition.x_opencti_color : '#ffffff',
      markingDefinition
    ),
    ENTITY_TYPE_MARKING_DEFINITION
  );
  return notify(BUS_TOPICS[ENTITY_TYPE_MARKING_DEFINITION].ADDED_TOPIC, created, user);
};

export const markingDefinitionDelete = (user, markingDefinitionId) =>
  deleteEntityById(user, markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION);

export const markingDefinitionEditField = (user, markingDefinitionId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION, input, wTx);
  }).then(async () => {
    const markingDefinition = await loadEntityById(markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION);
    return notify(BUS_TOPICS[ENTITY_TYPE_MARKING_DEFINITION].EDIT_TOPIC, markingDefinition, user);
  });
};

export const markingDefinitionCleanContext = async (user, markingDefinitionId) => {
  await delEditContext(user, markingDefinitionId);
  return loadEntityById(markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION).then((markingDefinition) =>
    notify(BUS_TOPICS[ENTITY_TYPE_MARKING_DEFINITION].EDIT_TOPIC, markingDefinition, user)
  );
};

export const markingDefinitionEditContext = async (user, markingDefinitionId, input) => {
  await setEditContext(user, markingDefinitionId, input);
  return loadEntityById(markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION).then((markingDefinition) =>
    notify(BUS_TOPICS[ENTITY_TYPE_MARKING_DEFINITION].EDIT_TOPIC, markingDefinition, user)
  );
};
