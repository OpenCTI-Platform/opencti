import * as R from 'ramda';
import { createRelation, deleteElementById, deleteRelationsByFromAndTo, patchAttribute, updateAttribute } from '../database/middleware';
import {
  fullEntitiesThroughRelationsFromList,
  fullEntitiesThroughRelationsToList,
  topEntitiesList,
  pageEntitiesConnection,
  pageRegardingEntitiesConnection,
  storeLoadById
} from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_ROLE, ENTITY_TYPE_USER } from '../schema/internalObject';
import { isInternalRelationship, RELATION_ACCESSES_TO, RELATION_HAS_ROLE, RELATION_MEMBER_OF } from '../schema/internalRelationship';
import { FunctionalError } from '../config/errors';
import { ABSTRACT_INTERNAL_RELATIONSHIP } from '../schema/general';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { getEntitiesMapFromCache } from '../database/cache';
import { isUserHasCapability, SETTINGS_SET_ACCESSES, SYSTEM_USER } from '../utils/access';
import { publishUserAction } from '../listener/UserActionListener';
import { extractEntityRepresentativeName } from '../database/entity-representative';
import { cleanMarkings } from '../utils/markingDefinition-utils';

export const GROUP_DEFAULT = 'Default';

const groupUsersCacheRefresh = async (context, user, groupId) => {
  const members = await fullEntitiesThroughRelationsFromList(context, user, groupId, RELATION_MEMBER_OF, ENTITY_TYPE_USER);
  await notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, members, user);
};

export const findById = (context, user, groupId) => {
  return storeLoadById(context, user, groupId, ENTITY_TYPE_GROUP);
};

export const findGroupPaginated = async (context, user, args) => {
  if (!isUserHasCapability(user, SETTINGS_SET_ACCESSES)) {
    const groupsIds = R.uniq((user.administrated_organizations ?? []).map((orga) => (orga.grantable_groups ?? [])).flat());
    return pageEntitiesConnection(context, user, [ENTITY_TYPE_GROUP], { ...args, ids: groupsIds });
  }
  return pageEntitiesConnection(context, user, [ENTITY_TYPE_GROUP], args);
};

export const findDefaultIngestionGroups = async (context, user) => {
  return topEntitiesList(context, user, [ENTITY_TYPE_GROUP], {
    filters: {
      mode: 'and',
      filters: [
        {
          key: ['auto_integration_assignation'],
          values: [
            'global',
          ],
        },
      ],
      filterGroups: [],
    }
  });
};

export const groupAllowedMarkings = async (context, user, groupId) => {
  return fullEntitiesThroughRelationsToList(context, user, groupId, RELATION_ACCESSES_TO, ENTITY_TYPE_MARKING_DEFINITION);
};

export const groupNotShareableMarkingTypes = (group) => group.max_shareable_markings?.filter(({ value }) => value === 'none')
  .map(({ type }) => type) ?? [];

export const groupMaxShareableMarkings = async (context, group) => {
  const groupMaxShareableMarkingsResult = [];
  if (group.max_shareable_markings) {
    const markings = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);

    for (let i = 0; i < group.max_shareable_markings.length; i += 1) {
      const currentGroupMaxMarkingId = group.max_shareable_markings[i].value;
      if (currentGroupMaxMarkingId !== 'none') {
        const markingDetails = markings.get(currentGroupMaxMarkingId);
        if (markingDetails) {
          groupMaxShareableMarkingsResult.push(markingDetails);
        }
      }
    }
  }
  return groupMaxShareableMarkingsResult;
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
  defaultMarkings.filter((d) => !!d.entity_type).forEach((d) => {
    const existing = results.find((r) => r.entity_type === d.entity_type);
    if (existing) {
      existing.values = [...(d.values ?? []), ...existing.values];
    } else {
      results.push(d);
    }
  });

  return results;
};

export const defaultMarkingDefinitionsFromGroups = async (context, userGroups) => {
  const markingsMap = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  // Retrieve default marking by groups
  const defaultMarkingsFlat = userGroups.map((group) => {
    const defaultMarking = group.default_marking ?? [];
    return defaultMarking.map((entry) => {
      return {
        entity_type: entry.entity_type,
        values: entry.values?.map((d) => markingsMap.get(d)),
      };
    });
  }).flat();
  // Merge default marking by group
  return mergeDefaultMarking(defaultMarkingsFlat)
    .then((defaultMarkings) => {
      // Clean default marking by entity type
      return Promise.all(defaultMarkings.map(async (d) => {
        return {
          entity_type: d.entity_type,
          values: await cleanMarkings(context, d.values),
        };
      }));
    });
};

export const rolesPaginated = async (context, user, groupId, args) => {
  return pageRegardingEntitiesConnection(context, user, groupId, RELATION_HAS_ROLE, ENTITY_TYPE_ROLE, false, args);
};

export const membersPaginated = async (context, user, groupId, args) => {
  return pageRegardingEntitiesConnection(context, user, groupId, RELATION_MEMBER_OF, ENTITY_TYPE_USER, true, args);
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
  return notify(BUS_TOPICS[ENTITY_TYPE_GROUP].DELETE_TOPIC, group, user).then(() => groupId);
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
  // on editing the group confidence level, all members might have changed their effective level
  if (input.find((i) => ['group_confidence_level', 'max_shareable_markings', 'restrict_delete'].includes(i.key))) {
    await groupUsersCacheRefresh(context, user, groupId);
  }
  return notify(BUS_TOPICS[ENTITY_TYPE_GROUP].EDIT_TOPIC, element, user);
};

// -- RELATIONS --

export const groupAddRelation = async (context, user, groupId, input) => {
  const group = await storeLoadById(context, user, groupId, ENTITY_TYPE_GROUP);
  if (!group) {
    throw FunctionalError('Cannot add the relation, Group cannot be found.', { groupId });
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
  if (input.relationship_type === RELATION_MEMBER_OF && created.entity_type === ENTITY_TYPE_USER) {
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'update',
      event_access: 'administration',
      message: `adds ${group.entity_type} \`${extractEntityRepresentativeName(group)}\` for user \`${created.user_email}\``,
      context_data: { id: created.id, entity_type: ENTITY_TYPE_USER, input: finalInput }
    });
    return notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, created, user).then(() => createdRelation);
  }
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `adds ${created.entity_type} \`${extractEntityRepresentativeName(created)}\` for group \`${group.name}\``,
    context_data: { id: groupId, entity_type: ENTITY_TYPE_GROUP, input }
  });
  await groupUsersCacheRefresh(context, user, groupId);
  return notify(BUS_TOPICS[ENTITY_TYPE_GROUP].EDIT_TOPIC, group, user).then(() => createdRelation);
};

export const groupDeleteRelation = async (context, user, groupId, fromId, toId, relationshipType) => {
  const group = await storeLoadById(context, user, groupId, ENTITY_TYPE_GROUP);
  if (!group) {
    throw FunctionalError('Cannot delete the relation, Group cannot be found.', { groupId });
  }
  if (!isInternalRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be deleted through this method, got ${input.relationship_type}.`);
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
  if (relationshipType === RELATION_MEMBER_OF && target.entity_type === ENTITY_TYPE_USER) {
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'update',
      event_access: 'administration',
      message: `removes ${group.entity_type} \`${extractEntityRepresentativeName(group)}\` for user \`${target.user_email}\``,
      context_data: { id: target.id, entity_type: ENTITY_TYPE_USER, input }
    });
    await notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, target, user);
  }
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `removes ${target.entity_type} \`${extractEntityRepresentativeName(target)}\` for group \`${group.name}\``,
    context_data: { id: groupId, entity_type: ENTITY_TYPE_GROUP, input }
  });
  await groupUsersCacheRefresh(context, user, groupId);
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
  await groupUsersCacheRefresh(context, user, groupId);
  return notify(BUS_TOPICS[ENTITY_TYPE_GROUP].EDIT_TOPIC, element, user);
};

// -- CONTEXT --

export const groupCleanContext = async (context, user, groupId) => {
  await delEditContext(user, groupId);
  return storeLoadById(context, user, groupId, ENTITY_TYPE_GROUP); // notify removed for performance issues with users cache
};

export const groupEditContext = async (context, user, groupId, input) => {
  await setEditContext(user, groupId, input);
  return storeLoadById(context, user, groupId, ENTITY_TYPE_GROUP); // notify removed for performance issues with users cache
};
