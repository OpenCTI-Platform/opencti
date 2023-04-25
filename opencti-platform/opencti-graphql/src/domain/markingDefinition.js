import * as R from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { createEntity, deleteElementById, updateAttribute } from '../database/middleware';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { ENTITY_TYPE_GROUP } from '../schema/internalObject';
import { SYSTEM_USER } from '../utils/access';
import { groupAddRelation } from './group';
import { RELATION_ACCESSES_TO } from '../schema/internalRelationship';
import { publishUserAction } from '../listener/UserActionListener';

export const findById = (context, user, markingDefinitionId) => {
  return storeLoadById(context, user, markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION);
};

export const findAll = (context, user, args) => {
  // Force looking with prefix wildcard for markings
  return listEntities(context, user, [ENTITY_TYPE_MARKING_DEFINITION], { ...args, useWildcardPrefix: true });
};

export const addMarkingDefinition = async (context, user, markingDefinition) => {
  const markingColor = markingDefinition.x_opencti_color ? markingDefinition.x_opencti_color : '#ffffff';
  const markingToCreate = R.assoc('x_opencti_color', markingColor, markingDefinition);
  const created = await createEntity(context, user, markingToCreate, ENTITY_TYPE_MARKING_DEFINITION);
  const filters = [{ key: 'auto_new_marking', values: [true] }];
  // Bypass current right to read group
  const groups = await listEntities(context, SYSTEM_USER, [ENTITY_TYPE_GROUP], { filters, connectionFormat: false });
  if (groups && groups.length > 0) {
    await Promise.all(
      groups.map((group) => {
        return groupAddRelation(context, SYSTEM_USER, group.id, {
          relationship_type: RELATION_ACCESSES_TO,
          toId: created.id,
        });
      })
    );
  }
  await publishUserAction({
    user,
    event_type: 'admin',
    status: 'success',
    message: `creates marking \`${created.name}\``,
    context_data: { type: 'marking', operation: 'create', input: markingToCreate }
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_MARKING_DEFINITION].ADDED_TOPIC, created, user);
};

export const markingDefinitionDelete = async (context, user, markingDefinitionId) => {
  const deleted = await deleteElementById(context, user, markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION);
  await publishUserAction({
    user,
    event_type: 'admin',
    status: 'success',
    message: `deletes marking \`${deleted.name}\``,
    context_data: { type: 'marking', operation: 'delete', input: { id: markingDefinitionId } }
  });
  return markingDefinitionId;
};

export const markingDefinitionEditField = async (context, user, markingDefinitionId, input, opts = {}) => {
  const { element } = await updateAttribute(context, user, markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION, input, opts);
  await publishUserAction({
    user,
    event_type: 'admin',
    status: 'success',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for marking \`${element.name}\``,
    context_data: { type: 'marking', operation: 'update', input }
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_MARKING_DEFINITION].EDIT_TOPIC, element, user);
};

export const markingDefinitionCleanContext = async (context, user, markingDefinitionId) => {
  await delEditContext(user, markingDefinitionId);
  return storeLoadById(context, user, markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION).then((markingDefinition) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_MARKING_DEFINITION].EDIT_TOPIC, markingDefinition, user);
  });
};

export const markingDefinitionEditContext = async (context, user, markingDefinitionId, input) => {
  await setEditContext(user, markingDefinitionId, input);
  return storeLoadById(context, user, markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION).then((markingDefinition) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_MARKING_DEFINITION].EDIT_TOPIC, markingDefinition, user);
  });
};
