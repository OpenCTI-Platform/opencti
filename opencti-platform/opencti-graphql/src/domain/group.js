import uuid from 'uuid/v4';
import {
  dayFormat,
  deleteEntityById,
  escapeString,
  executeWrite,
  graknNow,
  loadEntityById,
  monthFormat,
  paginate,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { addCreatedByRef, addMarkingDefs } from './stixEntity';
import { notify } from '../database/redis';

// region grakn fetch
export const findById = groupId => loadEntityById(groupId);
export const findAll = args => {
  return paginate(
    `match $g isa Group ${
      args.search
        ? `; $g has name $name;
   $g has description $description;
   { $name contains "${escapeString(args.search)}"; } or
   { $description contains "${escapeString(args.search)}"; }`
        : ''
    }`,
    args
  );
};
export const members = (groupId, args) => {
  return paginate(
    `match $user isa User; 
    $rel((member:$user, grouping:$g) isa membership; 
    $g has internal_id_key "${escapeString(groupId)}"`,
    args
  );
};
export const permissions = (groupId, args) => {
  return paginate(
    `match $marking isa Marking-Definition; 
    $rel(allow:$marking, allowed:$g) isa permission; 
    $g has internal_id_key "${escapeString(groupId)}"`,
    args
  );
};
// endregion

export const addGroup = async (user, group) => {
  const internalId = group.internal_id_key ? escapeString(group.internal_id_key) : uuid();
  await executeWrite(async wTx => {
    const groupIterator = await wTx.tx.query(`insert $group isa Group,
    has internal_id_key "${internalId}",
    has entity_type "group",
    has name "${escapeString(group.name)}",
    has description "${escapeString(group.description)}",
    has created_at ${graknNow()},
    has created_at_day "${dayFormat(graknNow())}",
    has created_at_month "${monthFormat(graknNow())}",
    has created_at_year "${yearFormat(graknNow())}",  
    has updated_at ${graknNow()};
  `);
    const createGroup = await groupIterator.next();
    return createGroup.map().get('group').id;
  });
  const created = await loadEntityById(internalId);
  await addCreatedByRef(internalId, group.createdByRef);
  await addMarkingDefs(internalId, group.markingDefinitions);
  notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};

export const groupDelete = groupId => deleteEntityById(groupId);
