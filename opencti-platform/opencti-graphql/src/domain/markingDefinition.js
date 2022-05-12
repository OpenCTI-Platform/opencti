import * as R from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { createEntity, deleteElementById, storeLoadById, updateAttribute } from '../database/middleware';
import { listEntities } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { ENTITY_TYPE_GROUP } from '../schema/internalObject';
import { SYSTEM_USER } from '../utils/access';
import { groupAddRelation } from './group';
import { RELATION_ACCESSES_TO } from '../schema/internalRelationship';

export const findById = (user, markingDefinitionId) => {
  return storeLoadById(user, markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION);
};

export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_MARKING_DEFINITION], args);
};

export const addMarkingDefinition = async (user, markingDefinition) => {
  const markingColor = markingDefinition.x_opencti_color ? markingDefinition.x_opencti_color : '#ffffff';
  const markingToCreate = R.assoc('x_opencti_color', markingColor, markingDefinition);
  const created = await createEntity(user, markingToCreate, ENTITY_TYPE_MARKING_DEFINITION);
  const filters = [{ key: 'auto_new_marking', values: [true] }];
  // Bypass current right to read group
  const groups = await listEntities(SYSTEM_USER, [ENTITY_TYPE_GROUP], { filters, connectionFormat: false });
  if (groups && groups.length > 0) {
    await Promise.all(
      groups.map((group) => {
        return groupAddRelation(SYSTEM_USER, group.id, {
          relationship_type: RELATION_ACCESSES_TO,
          toId: created.id,
        });
      })
    );
  }
  return notify(BUS_TOPICS[ENTITY_TYPE_MARKING_DEFINITION].ADDED_TOPIC, created, user);
};

export const markingDefinitionDelete = (user, markingDefinitionId) => {
  return deleteElementById(user, markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION);
};

export const markingDefinitionEditField = async (user, markingDefinitionId, input, opts = {}) => {
  const { element } = await updateAttribute(user, markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION, input, opts);
  return notify(BUS_TOPICS[ENTITY_TYPE_MARKING_DEFINITION].EDIT_TOPIC, element, user);
};

export const markingDefinitionCleanContext = async (user, markingDefinitionId) => {
  await delEditContext(user, markingDefinitionId);
  return storeLoadById(user, markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION).then((markingDefinition) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_MARKING_DEFINITION].EDIT_TOPIC, markingDefinition, user);
  });
};

export const markingDefinitionEditContext = async (user, markingDefinitionId, input) => {
  await setEditContext(user, markingDefinitionId, input);
  return storeLoadById(user, markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION).then((markingDefinition) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_MARKING_DEFINITION].EDIT_TOPIC, markingDefinition, user);
  });
};
