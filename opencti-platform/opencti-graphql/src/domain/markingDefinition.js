import { assoc } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { createEntity, deleteElementById, listEntities, loadById, updateAttribute } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';

export const findById = (markingDefinitionId) => {
  return loadById(markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_MARKING_DEFINITION], args);
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
  deleteElementById(user, markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION);

export const markingDefinitionEditField = async (user, markingDefinitionId, input) => {
  const markingDefinition = await updateAttribute(user, markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION, input);
  return notify(BUS_TOPICS[ENTITY_TYPE_MARKING_DEFINITION].EDIT_TOPIC, markingDefinition, user);
};

export const markingDefinitionCleanContext = async (user, markingDefinitionId) => {
  await delEditContext(user, markingDefinitionId);
  return loadById(markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION).then((markingDefinition) =>
    notify(BUS_TOPICS[ENTITY_TYPE_MARKING_DEFINITION].EDIT_TOPIC, markingDefinition, user)
  );
};

export const markingDefinitionEditContext = async (user, markingDefinitionId, input) => {
  await setEditContext(user, markingDefinitionId, input);
  return loadById(markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION).then((markingDefinition) =>
    notify(BUS_TOPICS[ENTITY_TYPE_MARKING_DEFINITION].EDIT_TOPIC, markingDefinition, user)
  );
};
