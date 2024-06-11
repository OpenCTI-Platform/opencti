import * as R from 'ramda';
import { createRelation, deleteElementById, deleteRelationsByFromAndTo, patchAttribute, updateAttribute } from '../database/middleware';
import {
  internalFindByIds,
  listAllFromEntitiesThroughRelations,
  listAllToEntitiesThroughRelations,
  listEntities,
  listEntitiesThroughRelationsPaginated,
  storeLoadById
} from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_ROLE, ENTITY_TYPE_USER } from '../schema/internalObject';
import { isInternalRelationship, RELATION_ACCESSES_TO, RELATION_HAS_ROLE, RELATION_MEMBER_OF } from '../schema/internalRelationship';
import { FunctionalError } from '../config/errors';
import { ABSTRACT_INTERNAL_RELATIONSHIP } from '../schema/general';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { findSessionsForUsers, markSessionForRefresh } from '../database/session';
import { ENTITY_TYPE_WORKSPACE } from '../modules/workspace/workspace-types';
import { getEntitiesMapFromCache } from '../database/cache';
import { isUserHasCapability, SETTINGS_SET_ACCESSES, SYSTEM_USER } from '../utils/access';
import { publishUserAction } from '../listener/UserActionListener';
import { extractEntityRepresentativeName } from '../database/entity-representative';
import { cleanMarkings } from '../utils/markingDefinition-utils';

export const GROUP_DEFAULT = 'Default';

const groupSessionRefresh = async (context, user, groupId) => {
  const members = await listAllFromEntitiesThroughRelations(context, user, groupId, RELATION_MEMBER_OF, ENTITY_TYPE_USER);
  const sessions = await findSessionsForUsers(members.map((e) => e.internal_id));
  await Promise.all(sessions.map((s) => markSessionForRefresh(s.id)));
};

export const findById = (context, user, groupId) => {
  return storeLoadById(context, user, groupId, ENTITY_TYPE_GROUP);
};

export const findAll = async (context, user, args) => {
  if (!isUserHasCapability(user, SETTINGS_SET_ACCESSES)) {
    const groupsIds = R.uniq((user.administrated_organizations ?? []).map((orga) => (orga.grantable_groups ?? [])).flat());
    return listEntities(context, user, [ENTITY_TYPE_GROUP], { ...args, ids: groupsIds });
  }
  return listEntities(context, user, [ENTITY_TYPE_GROUP], args);
};

export const groupAllowedMarkings = async (context, user, groupId) => {
  return listAllToEntitiesThroughRelations(context, user, groupId, RELATION_ACCESSES_TO, ENTITY_TYPE_MARKING_DEFINITION);
};

export const groupNotShareableMarkings = (group) => group.max_shareable_markings?.filter(({ value }) => value === 'none')
  .map(({ type }) => type) ?? [];

export const groupMaxShareableMarkings = async (context, user, group) => {
  const markings = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  return group.max_shareable_markings?.filter(({ value }) => value !== 'none')
    .map(({ value }) => markings.get(value)) ?? [];
};

export const defaultMarkingDefinitions = async (context, group) => {
  const defaultMarking = group.default_marking ?? [];
  return defaultMarking.map(async (entry) => {
    return {
      entity_type: entry.entity_type,
      values: await cleanMarkings(context, entry.values),
    };
  });
};

export const mergeDefaultMarking = async (defaultMarkings) => {
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
  return internalFindByIds(context, SYSTEM_USER, groupIds, { type: ENTITY_TYPE_GROUP })
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
    .then((defaultMarkings) => mergeDefaultMarking(defaultMarkings))
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

export const rolesPaginated = async (context, user, groupId, args) => {
  return listEntitiesThroughRelationsPaginated(context, user, groupId, RELATION_HAS_ROLE, ENTITY_TYPE_ROLE, false, args);
};

export const membersPaginated = async (context, user, groupId, args) => {
  return listEntitiesThroughRelationsPaginated(context, user, groupId, RELATION_MEMBER_OF, ENTITY_TYPE_USER, true, args);
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
  // on editing the group confidence level, all memebers might have changed their effective level
  if (input.find((i) => ['group_confidence_level', 'max_shareable_markings'].includes(i.key))) {
    await groupSessionRefresh(context, user, groupId);
  }
  return notify(BUS_TOPICS[ENTITY_TYPE_GROUP].EDIT_TOPIC, element, user);
};

// -- RELATIONS --

export const groupAddRelation = async (context, user, groupId, input) => {
  const group = await storeLoadById(context, user, groupId, ENTITY_TYPE_GROUP);
  if (!group) {
    throw FunctionalError('Cannot add the relation, Group cannot be found.');
  }
  if (!isInternalRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be added through this method, got ${input.relationship_type}.`);
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
