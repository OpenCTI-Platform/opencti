import { assoc } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  createRelation,
  deleteEntityById,
  deleteRelationById,
  executeWrite,
  listEntities,
  loadEntityById,
  TYPE_STIX_DOMAIN,
  updateAttribute
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findById = markingDefinitionId => {
  return loadEntityById(markingDefinitionId);
};

export const findAll = args => {
  const typedArgs = assoc('types', ['Marking-Definition'], args);
  return listEntities(['definition_type', 'definition'], typedArgs);
};

export const addMarkingDefinition = async (user, markingDefinition) => {
  const created = await createEntity(markingDefinition, 'Marking-Definition', { modelType: TYPE_STIX_DOMAIN });
  return notify(BUS_TOPICS.MarkingDefinition.ADDED_TOPIC, created, user);
};

export const markingDefinitionDelete = markingDefinitionId => deleteEntityById(markingDefinitionId);
export const markingDefinitionAddRelation = (user, markingDefinitionId, input) => {
  return createRelation(markingDefinitionId, input).then(relationData => {
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const markingDefinitionDeleteRelation = (user, markingDefinitionId, relationId) => {
  return deleteRelationById(markingDefinitionId, relationId).then(relationData => {
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const markingDefinitionEditField = (user, markingDefinitionId, input) => {
  return executeWrite(wTx => {
    return updateAttribute(markingDefinitionId, input, wTx);
  }).then(async () => {
    const markingDefinition = await loadEntityById(markingDefinitionId);
    return notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, markingDefinition, user);
  });
};

export const markingDefinitionCleanContext = (user, markingDefinitionId) => {
  delEditContext(user, markingDefinitionId);
  return loadEntityById(markingDefinitionId).then(markingDefinition =>
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, markingDefinition, user)
  );
};
export const markingDefinitionEditContext = (user, markingDefinitionId, input) => {
  setEditContext(user, markingDefinitionId, input);
  return loadEntityById(markingDefinitionId).then(markingDefinition =>
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, markingDefinition, user)
  );
};
