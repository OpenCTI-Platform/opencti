import uuid from 'uuid/v4';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createRelation,
  dayFormat,
  deleteEntityById,
  deleteRelationById,
  escapeString,
  executeWrite,
  graknNow,
  loadEntityById,
  monthFormat,
  paginate,
  prepareDate,
  updateAttribute,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { addCreatedByRef } from './stixEntity';
import { elLoadById } from '../database/elasticSearch';

export const findById = markingDefinitionId => {
  return elLoadById(markingDefinitionId);
};

// region grakn fetch
export const findAll = args => {
  return paginate(
    `match $m isa Marking-Definition ${
      args.search
        ? `; $m has definition_type $type;
   $m has definition $definition;
   { $type contains "${escapeString(args.search)}"; } or
   { $definition contains "${escapeString(args.search)}"; }`
        : ''
    }`,
    args
  );
};
export const findByEntity = args => {
  return paginate(
    `match $m isa Marking-Definition; 
    $rel(marking:$m, so:$so) isa object_marking_refs; 
    $so has internal_id_key "${escapeString(args.objectId)}"`,
    args,
    false,
    null,
    false,
    false
  );
};
export const findByDefinition = args => {
  return paginate(
    `match $m isa Marking-Definition; 
    $m has definition_type "${escapeString(args.definition_type)}"; 
    $m has definition "${escapeString(args.definition)}"`,
    args,
    false
  );
};
export const findByStixId = args => {
  return paginate(
    `match $m isa Marking-Definition; 
    $m has stix_id_key "${escapeString(args.stix_id_key)}"`,
    args,
    false
  );
};
// endregion

export const addMarkingDefinition = async (user, markingDefinition) => {
  const internalId = markingDefinition.internal_id_key ? escapeString(markingDefinition.internal_id_key) : uuid();
  await executeWrite(async wTx => {
    const now = graknNow();
    const markingDefinitionIterator = await wTx.tx.query(`insert $markingDefinition isa Marking-Definition,
    has internal_id_key "${internalId}",
    has entity_type "marking-definition",
    has stix_id_key "${
      markingDefinition.stix_id_key ? escapeString(markingDefinition.stix_id_key) : `marking-definition--${uuid()}`
    }",
    has definition_type "${escapeString(markingDefinition.definition_type)}",
    has definition "${escapeString(markingDefinition.definition)}",
    has color "${escapeString(markingDefinition.color)}",
    has level ${markingDefinition.level},
    has created ${markingDefinition.created ? prepareDate(markingDefinition.created) : now},
    has modified ${markingDefinition.modified ? prepareDate(markingDefinition.modified) : now},
    has revoked false,
    has created_at ${now},
    has created_at_day "${dayFormat(now)}",
    has created_at_month "${monthFormat(now)}",
    has created_at_year "${yearFormat(now)}",       
    has updated_at ${now};
  `);
    const createMarkingDef = await markingDefinitionIterator.next();
    return createMarkingDef.map().get('markingDefinition').id;
  });
  const created = await loadEntityById(internalId);
  await addCreatedByRef(internalId, markingDefinition.createdByRef);
  return notify(BUS_TOPICS.MarkingDefinition.ADDED_TOPIC, created, user);
};

export const markingDefinitionDelete = markingDefinitionId => deleteEntityById(markingDefinitionId);
export const markingDefinitionAddRelation = (user, markingDefinitionId, input) => {
  return createRelation(markingDefinitionId, input).then(relationData => {
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });
};
export const markingDefinitionDeleteRelation = (user, markingDefinitionId, relationId) => {
  return deleteRelationById(markingDefinitionId, relationId).then(relationData => {
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });
};
export const markingDefinitionEditField = (user, markingDefinitionId, input) => {
  return executeWrite(wTx => {
    return updateAttribute(markingDefinitionId, input, wTx);
  }).then(async () => {
    const markingDefinition = await elLoadById(markingDefinitionId);
    return notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, markingDefinition, user);
  });
};

export const markingDefinitionCleanContext = (user, markingDefinitionId) => {
  delEditContext(user, markingDefinitionId);
  return loadEntityById(markingDefinitionId).then(markingDefinition =>
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, markingDefinition, user)
  );
};
export const markingDefinitionEditContext = (user, markingDefinitionId, input) => {
  setEditContext(user, markingDefinitionId, input);
  return loadEntityById(markingDefinitionId).then(markingDefinition =>
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, markingDefinition, user)
  );
};
