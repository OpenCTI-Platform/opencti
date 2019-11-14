import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  createRelation,
  deleteEntityById,
  deleteRelationById,
  escapeString,
  executeWrite,
  loadEntityById,
  paginate,
  TYPE_OPENCTI_INTERNAL,
  updateAttribute
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findById = tagId => loadEntityById(tagId);

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
  const created = await createEntity(tag, 'Tag', TYPE_OPENCTI_INTERNAL);
  return notify(BUS_TOPICS.Tag.ADDED_TOPIC, created, user);
};

export const tagDelete = tagId => deleteEntityById(tagId);
export const tagAddRelation = (user, tagId, input) => {
  return createRelation(tagId, input).then(relationData => {
    notify(BUS_TOPICS.Tag.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const tagDeleteRelation = (user, tagId, relationId) => {
  return deleteRelationById(tagId, relationId).then(relationData => {
    notify(BUS_TOPICS.Tag.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const tagEditField = (user, tagId, input) => {
  return executeWrite(wTx => {
    return updateAttribute(tagId, input, wTx);
  }).then(async () => {
    const tag = await loadEntityById(tagId);
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
