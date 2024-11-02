import * as R from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { createEntity, deleteElementById, updateAttribute } from '../database/middleware';
import { listAllEntities, listEntities, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { ENTITY_TYPE_GROUP } from '../schema/internalObject';
import { SYSTEM_USER } from '../utils/access';
import { RELATION_ACCESSES_TO } from '../schema/internalRelationship';
import { groupAddRelation, groupEditField } from './group';

export const findById = (context, user, markingDefinitionId) => {
  return storeLoadById(context, user, markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION);
};

export const findAll = (context, user, args) => {
  // Force looking with prefix wildcard for markings
  return listEntities(context, user, [ENTITY_TYPE_MARKING_DEFINITION], { ...args, useWildcardPrefix: true });
};

// add the given marking definitions in the allowed markings of the user groups
export const addAllowedMarkingDefinition = async (context, user, markingDefinition) => {
  const markingColor = markingDefinition.x_opencti_color ? markingDefinition.x_opencti_color : '#ffffff';
  const markingToCreate = R.assoc('x_opencti_color', markingColor, markingDefinition);
  const result = await createEntity(context, user, markingToCreate, ENTITY_TYPE_MARKING_DEFINITION, { complete: true });
  const { element } = result;
  if (result.isCreation) {
    const filters = {
      mode: 'and',
      filters: [{ key: 'auto_new_marking', values: [true] }],
      filterGroups: [],
    };
    // Bypass current right to read group
    const groups = await listEntities(context, SYSTEM_USER, [ENTITY_TYPE_GROUP], { filters, connectionFormat: false });
    if (groups && groups.length > 0) {
      await Promise.all(
        groups.map((group) => {
          return groupAddRelation(context, SYSTEM_USER, group.id, {
            relationship_type: RELATION_ACCESSES_TO,
            toId: element.id,
          });
        })
      );
    }
  }
  return notify(BUS_TOPICS[ENTITY_TYPE_MARKING_DEFINITION].ADDED_TOPIC, element, user);
};

export const markingDefinitionDelete = async (context, user, markingDefinitionId) => {
  // remove the marking from the groups max shareable markings config if needed
  const groupsWithMarkingInShareableMarkings = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_GROUP], {
    filters: {
      mode: 'and',
      filters: [{ key: 'max_shareable_markings.value', values: [markingDefinitionId], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    }
  });
  if (groupsWithMarkingInShareableMarkings.length > 0) {
    const markingDefinition = await findById(context, user, markingDefinitionId);
    const editShareableMarkingsPromises = [];
    groupsWithMarkingInShareableMarkings.forEach((group) => {
      const type = markingDefinition.definition_type;
      const value = (group.max_shareable_markings ?? []).filter(({ type: t, value: v }) => t !== type && v !== 'none');
      editShareableMarkingsPromises.push(groupEditField(context, user, group.id, [{ key: 'max_shareable_markings', value }]));
    });
    await Promise.all(editShareableMarkingsPromises);
  }
  // delete the marking
  await deleteElementById(context, user, markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION);
  return markingDefinitionId;
};

export const markingDefinitionEditField = async (context, user, markingDefinitionId, input, opts = {}) => {
  const { element } = await updateAttribute(context, user, markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION, input, opts);
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
