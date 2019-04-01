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

export const findAll = args => paginate('match $g isa Group', args);

export const findById = groupId => getById(groupId);

export const members = (groupId, args) =>
  paginate(
    `match $user isa User; 
    $rel((member:$user, grouping:$g) isa membership; 
    $ id ${groupId}`,
    args
  );

export const permissions = (groupId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(allow:$marking, allowed:$g) isa permission; 
    $g id ${groupId}`,
    args
  );

export const addGroup = async (user, group) => {
  const wTx = await takeWriteTx();
  const groupIterator = await wTx.query(`insert $group isa Group,
    has entity_type "group",
    has stix_id "${
      group.stix_id ? prepareString(group.stix_id) : `group--${uuid()}`
    }",
    has name "${prepareString(group.name)}",
    has description "${prepareString(group.description)}",
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}",  
    has updated_at ${now()};
  `);
  const createGroup = await groupIterator.next();
  const createdGroupId = await createGroup.map().get('group').id;

  if (group.createdByRef) {
    await wTx.query(
      `match $from id ${createdGroupId};
      $to id ${group.createdByRef};
      insert (so: $from, creator: $to)
      isa created_by_ref;`
    );
  }

  if (group.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdGroupId}; 
        $to id ${markingDefinition};
        insert (so: $from, marking: $to) isa object_marking_refs;`
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
