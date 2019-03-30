import { map } from 'ramda';
import uuid from 'uuid/v4';
import {
  deleteEntityById,
  getById,
  dayFormat,
  monthFormat,
  yearFormat,
  notify,
  now,
  paginate,
  takeWriteTx,
  prepareString
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $x isa Group', args);

export const findById = groupId => getById(groupId);

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
  const wTx = await takeWriteTx();
  const groupIterator = await wTx.query(`insert $group isa Group 
    has type "group";
    $group has stix_id "${
      group.stix_id ? prepareString(group.stix_id) : `group--${uuid()}`
    }";
    $group has name "${prepareString(group.name)}";
    $group has description "${prepareString(group.description)}";
    $group has created_at ${now()};
    $group has created_at_day "${dayFormat(now())}";
    $group has created_at_month "${monthFormat(now())}";
    $group has created_at_year "${yearFormat(now())}";    
    $group has updated_at ${now()};
  `);
  const createGroup = await groupIterator.next();
  const createdGroupId = await createGroup.map().get('group').id;

  if (group.createdByRef) {
    await wTx.query(`match $from id ${createdGroupId};
         $to id ${group.createdByRef};
         insert (so: $from, creator: $to)
         isa created_by_ref;`);
  }

  if (group.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdGroupId}; $to id ${markingDefinition}; insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      group.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await wTx.commit();

  return getById(createdGroupId).then(created =>
    notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
  );
};

export const groupDelete = groupId => deleteEntityById(groupId);
