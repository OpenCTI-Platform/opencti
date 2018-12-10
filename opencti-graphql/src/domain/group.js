import { head } from 'ramda';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteByID,
  editInputTx,
  loadByID,
  notify,
  now,
  paginate,
  qk
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $m isa Group', args);

export const members = (groupId, args) =>
  paginate(
    `match $user isa User; 
    (member:$user, grouping:$group) isa membership; 
    $group id ${groupId}`,
    args
  );

export const permissions = (groupId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    (allow:$marking, allowed:$group) isa permission; 
    $group id ${groupId}`,
    args
  );

export const addGroup = async (user, group) => {
  const createGroup = qk(`insert $group isa Group 
    has name "${group.name}";
    $group has description "${group.description}";
    $group has created_at ${now()};
    $group has updated_at ${now()};
  `);
  return createGroup.then(result => {
    const { data } = result;
    return loadByID(head(data).group.id).then(created =>
      notify(BUS_TOPICS.Group.ADDED_TOPIC, created)
    );
  });
};

export const findById = groupId => loadByID(groupId);

export const groupDelete = groupId => deleteByID(groupId);

export const groupDeleteRelation = relationId => deleteByID(relationId);

export const groupAddRelation = (groupId, input) =>
  createRelation(groupId, input).then(group =>
    notify(BUS_TOPICS.Group.EDIT_TOPIC, group)
  );

export const groupCleanContext = (user, groupId) => {
  delEditContext(user, groupId);
  return loadByID(groupId).then(group =>
    notify(BUS_TOPICS.Group.EDIT_TOPIC, group)
  );
};

export const groupEditContext = (user, groupId, input) => {
  setEditContext(user, groupId, input);
  loadByID(groupId).then(group => notify(BUS_TOPICS.Group.EDIT_TOPIC, group));
};

export const groupEditField = (groupId, input) =>
  editInputTx(groupId, input).then(group =>
    notify(BUS_TOPICS.Group.EDIT_TOPIC, group)
  );
