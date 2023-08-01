import {
  batchListThroughGetFrom,
  batchListThroughGetTo,
  createRelation,
  deleteElementById,
  deleteRelationsByFromAndTo,
  listThroughGetFrom,
  patchAttribute,
  updateAttribute,
} from '../database/middleware';
import { internalFindByIds, listEntities, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_ROLE, ENTITY_TYPE_USER } from '../schema/internalObject';
import {
  isInternalRelationship,
  RELATION_ACCESSES_TO,
  RELATION_HAS_ROLE,
  RELATION_MEMBER_OF
} from '../schema/internalRelationship';
import { FunctionalError } from '../config/errors';
import { ABSTRACT_INTERNAL_RELATIONSHIP } from '../schema/general';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { findSessionsForUsers, markSessionForRefresh } from '../database/session';
import { ENTITY_TYPE_WORKSPACE } from '../modules/workspace/workspace-types';
import { getEntitiesMapFromCache } from '../database/cache';
import { SYSTEM_USER } from '../utils/access';
import { publishUserAction } from '../listener/UserActionListener';
import { extractEntityRepresentativeName } from '../database/entity-representative';
import { cleanMarkings } from './markingDefinition';

export const GROUP_DEFAULT = 'Default';

const groupSessionRefresh = async (context, user, groupId) => {
  const members = await listThroughGetFrom(context, user, [groupId], RELATION_MEMBER_OF, ENTITY_TYPE_USER);
  const sessions = await findSessionsForUsers(members.map((e) => e.internal_id));
  await Promise.all(sessions.map((s) => markSessionForRefresh(s.id)));
};

export const findById = (context, user, groupId) => {
  return storeLoadById(context, user, groupId, ENTITY_TYPE_GROUP);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_GROUP], args);
};

export const batchMembers = async (context, user, groupIds, opts = {}) => {
  return batchListThroughGetFrom(context, user, groupIds, RELATION_MEMBER_OF, ENTITY_TYPE_USER, opts);
};

export const batchMarkingDefinitions = async (context, user, groupIds) => {
  const opts = { paginate: false };
  return batchListThroughGetTo(context, user, groupIds, RELATION_ACCESSES_TO, ENTITY_TYPE_MARKING_DEFINITION, opts);
};

export const defaultMarkingDefinitions = async (context, group) => {
  const defaultMarking = group.default_marking ?? [];
  const markingsMap = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  return defaultMarking.map((entry) => {
    return {
      entity_type: entry.entity_type,
      values: entry.values?.map((d) => markingsMap.get(d)),
    };
  });
};

export const mergeDefaultMarking = async (context, defaultMarkings) => {
  const results = [];
  defaultMarkings.filter((d) => !!d.entity_type)
    .forEach((d) => {
      const existing = results.find((r) => r.entity_type === d.entity_type);
      if (existing) {
        existing.values = [...(d.values ?? []), ...existing.values];
      } else {
        results.push(d);
      }
    });

  return results;
};

export const defaultMarkingDefinitionsFromGroups = async (context, groupIds) => {
  const markingsMap = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  // Retrieve default marking by groups
  return internalFindByIds(context, SYSTEM_USER, groupIds)
    .then((groups) => groups.map((group) => {
      const defaultMarking = group.default_marking ?? [];
      return defaultMarking.map((entry) => {
        return {
          entity_type: entry.entity_type,
          values: entry.values?.map((d) => markingsMap.get(d)),
        };
      });
    }).flat())
    // Merge default marking by group
    .then((defaultMarkings) => mergeDefaultMarking(context, defaultMarkings))
    // Clean default marking by entity type
    .then((defaultMarkings) => {
      return Promise.all(defaultMarkings.map(async (d) => {
        return {
          entity_type: d.entity_type,
          values: await cleanMarkings(context, d.values),
        };
      }));
    });
};

export const batchRoles = async (context, user, groupIds) => {
  const opts = { paginate: false };
  return batchListThroughGetTo(context, user, groupIds, RELATION_HAS_ROLE, ENTITY_TYPE_ROLE, opts);
};

export const groupDelete = async (context, user, groupId) => {
  const group = await deleteElementById(context, user, groupId, ENTITY_TYPE_GROUP);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes group \`${group.name}\``,
    context_data: { id: groupId, entity_type: ENTITY_TYPE_GROUP, input: group }
  });
  return groupId;
};

export const groupEditField = async (context, user, groupId, input) => {
  const { element } = await updateAttribute(context, user, groupId, ENTITY_TYPE_GROUP, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for group \`${element.name}\``,
    context_data: { id: groupId, entity_type: ENTITY_TYPE_GROUP, input }
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_GROUP].EDIT_TOPIC, element, user);
};

// -- RELATIONS --

export const groupAddRelation = async (context, user, groupId, input) => {
  const group = await storeLoadById(context, user, groupId, ENTITY_TYPE_GROUP);
  if (!group) {
    throw FunctionalError('Cannot add the relation, Group cannot be found.');
  }
  if (!isInternalRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be added through this method.`);
  }
  let finalInput;
  if (input.fromId) {
    finalInput = { ...input, toId: groupId };
  } else if (input.toId) {
    finalInput = { ...input, fromId: groupId };
  }
  const createdRelation = await createRelation(context, user, finalInput);
  const created = input.fromId ? createdRelation.from : createdRelation.to;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `adds ${created.entity_type} \`${extractEntityRepresentativeName(created)}\` for group \`${group.name}\``,
    context_data: { id: groupId, entity_type: ENTITY_TYPE_GROUP, input }
  });
  await groupSessionRefresh(context, user, groupId);
  return notify(BUS_TOPICS[ENTITY_TYPE_GROUP].EDIT_TOPIC, createdRelation, user);
};

export const groupDeleteRelation = async (context, user, groupId, fromId, toId, relationshipType) => {
  const group = await storeLoadById(context, user, groupId, ENTITY_TYPE_GROUP);
  if (!group) {
    throw FunctionalError('Cannot delete the relation, Group cannot be found.');
  }
  if (!isInternalRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be deleted through this method.`);
  }
  let target;
  if (fromId) {
    const deleted = await deleteRelationsByFromAndTo(context, user, fromId, groupId, relationshipType, ABSTRACT_INTERNAL_RELATIONSHIP);
    target = deleted.from;
  } else if (toId) {
    const deleted = await deleteRelationsByFromAndTo(context, user, groupId, toId, relationshipType, ABSTRACT_INTERNAL_RELATIONSHIP);
    target = deleted.to;
  }
  const input = { fromId, toId, relationship_type: relationshipType };
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `removes ${target.entity_type} \`${extractEntityRepresentativeName(target)}\` for group \`${group.name}\``,
    context_data: { id: groupId, entity_type: ENTITY_TYPE_GROUP, input }
  });
  await groupSessionRefresh(context, user, groupId);
  return notify(BUS_TOPICS[ENTITY_TYPE_GROUP].EDIT_TOPIC, group, user);
};

// -- DEFAULT MARKING --
export const groupEditDefaultMarking = async (context, user, groupId, defaultMarking) => {
  const values = (await cleanMarkings(context, defaultMarking.values)).map((m) => m.id);

  const group = await storeLoadById(context, user, groupId, ENTITY_TYPE_GROUP);
  const existingDefaultMarking = group.default_marking ?? [];
  const existing = existingDefaultMarking.find((r) => r.entity_type === defaultMarking.entity_type);
  if (existing) {
    existing.values = values;
  } else {
    existingDefaultMarking.push({ entity_type: defaultMarking.entity_type, values });
  }
  const patch = { default_marking: existingDefaultMarking };
  const { element } = await patchAttribute(context, user, groupId, ENTITY_TYPE_GROUP, patch);
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, element, user);
};

// -- CONTEXT --

export const groupCleanContext = async (context, user, groupId) => {
  await delEditContext(user, groupId);
  return storeLoadById(context, user, groupId, ENTITY_TYPE_GROUP).then((group) => notify(BUS_TOPICS.Group.EDIT_TOPIC, group, user));
};

export const groupEditContext = async (context, user, groupId, input) => {
  await setEditContext(user, groupId, input);
  return storeLoadById(context, user, groupId, ENTITY_TYPE_GROUP).then((group) => notify(BUS_TOPICS.Group.EDIT_TOPIC, group, user));
};
