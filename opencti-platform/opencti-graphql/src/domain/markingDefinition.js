import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  escapeString,
  createRelation,
  deleteEntityById,
  deleteRelationById,
  updateAttribute,
  getById,
  prepareDate,
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
  paginate('match $m isa Marking-Definition', args);

export const findByEntity = args =>
  paginate(
    `match $m isa Marking-Definition; 
    $rel(marking:$m, so:$so) isa object_marking_refs; 
    $so has internal_id "${escapeString(args.objectId)}"`,
    args,
    false,
    null,
    false,
    false
  );

export const findByDefinition = args =>
  paginate(
    `match $m isa Marking-Definition; 
    $m has definition_type "${escapeString(args.definition_type)}"; 
    $m has definition "${escapeString(args.definition)}"`,
    args,
    false
  );

export const findByStixId = args =>
  paginate(
    `match $m isa Marking-Definition; 
    $m has stix_id "${escapeString(args.stix_id)}"`,
    args,
    false
  );

export const findById = markingDefinitionId => getById(markingDefinitionId);

export const addMarkingDefinition = async (user, markingDefinition) => {
  const wTx = await takeWriteTx();
  const internalId = markingDefinition.internal_id
    ? escapeString(markingDefinition.internal_id)
    : uuid();
  const markingDefinitionIterator = await wTx.tx
    .query(`insert $markingDefinition isa Marking-Definition,
    has internal_id "${internalId}",
    has entity_type "marking-definition",
    has stix_id "${
      markingDefinition.stix_id
        ? escapeString(markingDefinition.stix_id)
        : `marking-definition--${uuid()}`
    }",
    has definition_type "${escapeString(markingDefinition.definition_type)}",
    has definition "${escapeString(markingDefinition.definition)}",
    has color "${escapeString(markingDefinition.color)}",
    has level ${markingDefinition.level},
    has created ${
      markingDefinition.created ? prepareDate(markingDefinition.created) : now()
    },
    has modified ${
      markingDefinition.modified
        ? prepareDate(markingDefinition.modified)
        : now()
    },
    has revoked false,
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}",       
    has updated_at ${now()};
  `);
  const createMarkingDefinition = await markingDefinitionIterator.next();
  const createdMarkingDefinitionId = await createMarkingDefinition
    .map()
    .get('markingDefinition').id;

  if (markingDefinition.createdByRef) {
    await wTx.tx.query(
      `match $from id ${createdMarkingDefinitionId};
      $to has internal_id "${escapeString(markingDefinition.createdByRef)}";
      insert (so: $from, creator: $to)
      isa created_by_ref, has internal_id "${uuid()}";`
    );
  }

  await commitWriteTx(wTx);

  return getById(internalId).then(created =>
    notify(BUS_TOPICS.MarkingDefinition.ADDED_TOPIC, created, user)
  );
};

export const markingDefinitionDelete = markingDefinitionId =>
  deleteEntityById(markingDefinitionId);

export const markingDefinitionAddRelation = (
  user,
  markingDefinitionId,
  input
) =>
  createRelation(markingDefinitionId, input).then(relationData => {
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const markingDefinitionDeleteRelation = (
  user,
  markingDefinitionId,
  relationId
) =>
  deleteRelationById(markingDefinitionId, relationId).then(relationData => {
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const markingDefinitionCleanContext = (user, markingDefinitionId) => {
  delEditContext(user, markingDefinitionId);
  return getById(markingDefinitionId).then(markingDefinition =>
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, markingDefinition, user)
  );
};

export const markingDefinitionEditContext = (
  user,
  markingDefinitionId,
  input
) => {
  setEditContext(user, markingDefinitionId, input);
  return getById(markingDefinitionId).then(markingDefinition =>
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, markingDefinition, user)
  );
};

export const markingDefinitionEditField = (user, markingDefinitionId, input) =>
  updateAttribute(markingDefinitionId, input).then(markingDefinition =>
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, markingDefinition, user)
  );
