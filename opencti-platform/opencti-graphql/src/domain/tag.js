import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  escapeString,
  createRelation,
  deleteEntityById,
  deleteRelationById,
  updateAttribute,
  getById,
  dayFormat,
  monthFormat,
  yearFormat,
  notify,
  now,
  paginate,
  takeWriteTx,
  commitWriteTx
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args =>
  paginate(
    `match $t isa Tag ${
      args.search
        ? `; $t has tag_type $type;
   $t has value $value;
   { $type contains "${escapeString(args.search)}"; } or
   { $value contains "${escapeString(args.search)}"; }`
        : ''
    }`,
    args
  );

export const findByEntity = args =>
  paginate(
    `match $t isa Tag; 
    $rel(tagging:$t, so:$so) isa tagged; 
    $so has internal_id "${escapeString(args.objectId)}"`,
    args,
    false,
    null,
    false,
    false
  );

export const findByValue = args =>
  paginate(
    `match $t isa Tag; 
    $t has tag_type "${escapeString(args.tag_type)}"; 
    $t has value "${escapeString(args.value)}"`,
    args,
    false
  );

export const findById = tagId => getById(tagId);

export const addTag = async (user, tag) => {
  const wTx = await takeWriteTx();
  const internalId = tag.internal_id ? escapeString(tag.internal_id) : uuid();
  await wTx.tx.query(`insert $tag isa Tag,
    has internal_id "${internalId}",
    has tag_type "${escapeString(tag.tag_type)}",
    has value "${escapeString(tag.value)}",
    has color "${escapeString(tag.color)}",
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}",       
    has updated_at ${now()};
  `);
  await commitWriteTx(wTx);

  return getById(internalId).then(created =>
    notify(BUS_TOPICS.Tag.ADDED_TOPIC, created, user)
  );
};

export const tagDelete = tagId => deleteEntityById(tagId);

export const tagAddRelation = (user, tagId, input) =>
  createRelation(tagId, input).then(relationData => {
    notify(BUS_TOPICS.Tag.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const tagDeleteRelation = (user, tagId, relationId) =>
  deleteRelationById(tagId, relationId).then(relationData => {
    notify(BUS_TOPICS.Tag.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const tagCleanContext = (user, tagId) => {
  delEditContext(user, tagId);
  return getById(tagId).then(tag =>
    notify(BUS_TOPICS.Tag.EDIT_TOPIC, tag, user)
  );
};

export const tagEditContext = (user, tagId, input) => {
  setEditContext(user, tagId, input);
  return getById(tagId).then(tag =>
    notify(BUS_TOPICS.Tag.EDIT_TOPIC, tag, user)
  );
};

export const tagEditField = (user, tagId, input) =>
  updateAttribute(tagId, input).then(tag =>
    notify(BUS_TOPICS.Tag.EDIT_TOPIC, tag, user)
  );
