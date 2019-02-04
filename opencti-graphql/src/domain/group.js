import { head } from 'ramda';
import {
  deleteByID,
  loadByID,
  dayFormat,
  monthFormat,
  yearFormat,
  notify,
  now,
  paginate,
  qk,
  prepareString
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $m isa Group', args);

export const findById = groupId => loadByID(groupId);

export const members = (groupId, args) =>
  paginate(
    `match $user isa User; 
    $rel((member:$user, grouping:$group) isa membership; 
    $group id ${groupId}`,
    args
  );

export const permissions = (groupId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(allow:$marking, allowed:$group) isa permission; 
    $group id ${groupId}`,
    args
  );

export const addGroup = async (user, group) => {
  const createGroup = qk(`insert $group isa Group 
    has type "group";
    $group has name "${prepareString(group.name)}";
    $group has description "${prepareString(group.description)}";
    $group has name_lowercase "${prepareString(group.name.toLowerCase())}";
    $group has description_lowercase "${
      group.description ? prepareString(group.description.toLowerCase()) : ''
    }";
    $group has created_at ${now()};
    $group has created_at_day "${dayFormat(now())}";
    $group has created_at_month "${monthFormat(now())}";
    $group has created_at_year "${yearFormat(now())}";    
    $group has updated_at ${now()};
  `);
  return createGroup.then(result => {
    const { data } = result;
    return loadByID(head(data).group.id).then(created =>
      notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
    );
  });
};

export const groupDelete = groupId => deleteByID(groupId);
