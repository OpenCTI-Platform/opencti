import uuid from 'uuid/v4';
import {
  dayFormat,
  deleteEntityById,
  escapeString,
  executeWrite,
  loadEntityById,
  graknNow,
  monthFormat,
  paginate,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { linkCreatedByRef, linkMarkingDef } from './stixEntity';
import { notify } from '../database/redis';

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

export const findById = groupId => loadEntityById(groupId);

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

export const addGroup = async (user, group) => {
  const groupId = await executeWrite(async wTx => {
    const internalId = group.internal_id_key
      ? escapeString(group.internal_id_key)
      : uuid();
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
    const createdGroupId = await createGroup.map().get('group').id;

    // Create associated relations
    await linkCreatedByRef(wTx, createdGroupId, group.createdByRef);
    await linkMarkingDef(wTx, createdGroupId, group.markingDefinitions);
    return internalId;
  });
  return loadEntityById(groupId).then(created =>
    notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
  );
};

export const groupDelete = groupId => deleteEntityById(groupId);
