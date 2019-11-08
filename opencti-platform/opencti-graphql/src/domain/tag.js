import uuid from 'uuid/v4';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createRelation,
  dayFormat,
  deleteEntityById,
  deleteRelationById,
  escapeString,
  executeWrite,
  loadEntityById,
  graknNow,
  monthFormat,
  paginate,
  updateAttribute,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { elLoadById } from '../database/elasticSearch';

export const findById = tagId => elLoadById(tagId);

// region grakn fetch
export const findAll = args => {
  return paginate(
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
};
export const findByEntity = args => {
  return paginate(
    `match $t isa Tag; 
    $rel(tagging:$t, so:$so) isa tagged; 
    $so has internal_id_key "${escapeString(args.objectId)}"`,
    args,
    false,
    null,
    false,
    false
  );
};
export const findByValue = args => {
  return paginate(
    `match $t isa Tag; 
    $t has tag_type "${escapeString(args.tag_type)}"; 
    $t has value "${escapeString(args.value)}"`,
    args,
    false
  );
};
// endregion

export const addTag = async (user, tag) => {
  const internalId = tag.internal_id_key ? escapeString(tag.internal_id_key) : uuid();
  await executeWrite(async wTx => {
    const now = graknNow();
    await wTx.tx.query(`insert $tag isa Tag,
      has internal_id_key "${internalId}",
      has tag_type "${escapeString(tag.tag_type)}",
      has value "${escapeString(tag.value)}",
      has color "${escapeString(tag.color)}",
      has created_at ${now},
      has created_at_day "${dayFormat(now)}",
      has created_at_month "${monthFormat(now)}",
      has created_at_year "${yearFormat(now)}",       
      has updated_at ${now};`);
  });
  const created = await loadEntityById(internalId);
  return notify(BUS_TOPICS.Tag.ADDED_TOPIC, created, user);
};

export const tagDelete = tagId => deleteEntityById(tagId);
export const tagAddRelation = (user, tagId, input) => {
  return createRelation(tagId, input).then(relationData => {
    notify(BUS_TOPICS.Tag.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });
};
export const tagDeleteRelation = (user, tagId, relationId) => {
  return deleteRelationById(tagId, relationId).then(relationData => {
    notify(BUS_TOPICS.Tag.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });
};
export const tagEditField = (user, tagId, input) => {
  return executeWrite(wTx => {
    return updateAttribute(tagId, input, wTx);
  }).then(async () => {
    const tag = await elLoadById(tagId);
    return notify(BUS_TOPICS.Tag.EDIT_TOPIC, tag, user);
  });
};

export const tagCleanContext = (user, tagId) => {
  delEditContext(user, tagId);
  return loadEntityById(tagId).then(tag => notify(BUS_TOPICS.Tag.EDIT_TOPIC, tag, user));
};
export const tagEditContext = (user, tagId, input) => {
  setEditContext(user, tagId, input);
  return loadEntityById(tagId).then(tag => notify(BUS_TOPICS.Tag.EDIT_TOPIC, tag, user));
};
