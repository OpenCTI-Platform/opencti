import * as R from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { createEntity, deleteElementById, updateAttribute } from '../database/middleware';
import { internalFindByIds, listAllEntities, listAllRelations, listEntities, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_USER } from '../schema/internalObject';
import { SYSTEM_USER } from '../utils/access';
import { RELATION_ACCESSES_TO, RELATION_MEMBER_OF } from '../schema/internalRelationship';
import { groupAddRelation, groupEditField, groupMaxShareableMarkings } from './group';
import { getEntitiesListFromCache } from '../database/cache';
import { READ_RELATIONSHIPS_INDICES } from '../database/utils';

export const findById = (context, user, markingDefinitionId) => {
  return storeLoadById(context, user, markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION);
};

export const findAll = (context, user, args) => {
  // Force looking with prefix wildcard for markings
  return listEntities(context, user, [ENTITY_TYPE_MARKING_DEFINITION], { ...args, useWildcardPrefix: true });
};

const notifyMembersOfNewMarking = async (context, user, newMarking) => {
  const allMarkings = await getEntitiesListFromCache(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  const userGroupedMarkings = R.groupBy((m) => m.definition_type, allMarkings);
  const otherExistingTypeMarkingIds = (userGroupedMarkings[newMarking.definition_type] ?? []).map((m) => m.internal_id);
  const groupIds = new Set();
  const groupUsers = new Map();
  const relations = await listAllRelations(context, SYSTEM_USER, [RELATION_ACCESSES_TO, RELATION_MEMBER_OF], { indices: READ_RELATIONSHIPS_INDICES });
  for (let index = 0; index < relations.length; index += 1) {
    // group <- RELATION_ACCESSES_TO -> marking
    const { fromId, entity_type, toId } = relations[index];
    if (entity_type === RELATION_ACCESSES_TO && otherExistingTypeMarkingIds.includes(toId)) {
      groupIds.add(fromId);
    }
    // user <- RELATION_MEMBER_OF -> group
    if (entity_type === RELATION_MEMBER_OF) {
      if (groupUsers.has(toId)) {
        const users = groupUsers.get(toId);
        users.push(fromId);
        groupUsers.set(toId, users);
      } else {
        groupUsers.set(toId, [fromId]);
      }
    }
  }
  const groups = Array.from(groupIds);
  if (groups.length > 0) {
    const userIds = groups.map((groupId) => (groupUsers.get(groupId) ?? [])).flat();
    const users = await internalFindByIds(context, SYSTEM_USER, userIds);
    await notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, users, user);
  }
};

const updateGroupsAfterAddingMarking = async (context, markingCreated) => {
  // marking creation --> update the markings of the groups with auto_new_marking = true
  const filters = {
    mode: 'and',
    filters: [{ key: 'auto_new_marking', values: [true] }],
    filterGroups: [],
  };
  const groupsWithAutoNewMarking = await listEntities(context, SYSTEM_USER, [ENTITY_TYPE_GROUP], { filters, connectionFormat: false });
  if (groupsWithAutoNewMarking && groupsWithAutoNewMarking.length > 0) {
    const markingId = markingCreated.id;
    const markingType = markingCreated.definition_type;
    // add marking in allowed markings
    await Promise.all(groupsWithAutoNewMarking.map((group) => {
      return groupAddRelation(context, SYSTEM_USER, group.id, { relationship_type: RELATION_ACCESSES_TO, toId: markingId });
    }));
    // add marking in max shareable markings
    const completeGroupsWithAutoNewMarking = await Promise.all(groupsWithAutoNewMarking.map(async (g) => ({
      ...g,
      max_shareable_marking: await groupMaxShareableMarkings(context, g),
    })));
    const groupsWithShareableMarkingToUpdate = completeGroupsWithAutoNewMarking.filter((g) => {
      const shareableMarkingOfTypeWithGreaterOrder = (g.max_shareable_marking ?? [])
        .find((m) => m.definition_type === markingType && m.x_opencti_order > markingCreated.x_opencti_order);
      // we need to update the group max shareable markings if it has no shareable marking of the same definition type with a greater order
      return shareableMarkingOfTypeWithGreaterOrder === undefined;
    });
    await Promise.all(groupsWithShareableMarkingToUpdate.map((group) => {
      const finalMarkings = [
        ...(group.max_shareable_markings ?? []).filter(({ type: t }) => t !== markingType),
        ...[{ type: markingType, value: markingId }],
      ];
      return groupEditField(context, SYSTEM_USER, group.id, [{
        key: 'max_shareable_markings',
        value: finalMarkings,
      }]);
    }));
  }
};

export const addAllowedMarkingDefinition = async (context, user, markingDefinition) => {
  const markingColor = markingDefinition.x_opencti_color ? markingDefinition.x_opencti_color : '#ffffff';
  const markingToCreate = {
    ...markingDefinition,
    x_opencti_color: markingColor,
  };
  // Force context out of draft to force creation in live index
  const contextOutOfDraft = { ...context, draft_context: '' };
  const { element, isCreation } = await createEntity(contextOutOfDraft, user, markingToCreate, ENTITY_TYPE_MARKING_DEFINITION, { complete: true });
  if (isCreation) {
    // marking creation --> update the markings of the groups with auto_new_marking = true
    await updateGroupsAfterAddingMarking(contextOutOfDraft, element);
    // users of group impacted must be refreshed
    await notifyMembersOfNewMarking(contextOutOfDraft, user, element);
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
  const element = await deleteElementById(context, user, markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION);
  // users of group impacted must be refreshed
  await notifyMembersOfNewMarking(context, user, element);
  return markingDefinitionId;
};

export const markingDefinitionEditField = async (context, user, markingDefinitionId, input, opts = {}) => {
  const { element } = await updateAttribute(context, user, markingDefinitionId, ENTITY_TYPE_MARKING_DEFINITION, input, opts);
  // users of group impacted must be refreshed
  await notifyMembersOfNewMarking(context, user, element);
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
