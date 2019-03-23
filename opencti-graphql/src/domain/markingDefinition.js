import { head, map } from 'ramda';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteEntityById,
  deleteRelationById,
  editInputTx,
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

export const findAll = args =>
  paginate('match $m isa Marking-Definition', args);
export const findById = markingDefinitionId => getById(markingDefinitionId);

export const addMarkingDefinition = async (user, markingDefinition) => {
  const wTx = await takeWriteTx();
  const markingDefinitionIterator = await wTx.query(`insert $markingDefinition isa Marking-Definition 
    has type "marking-definition";
    $markingDefinition has stix_id "${
      markingDefinition.stix_id
        ? prepareString(markingDefinition.stix_id)
        : `marking-definition--${uuid()}`
    }";
    $markingDefinition has definition_type "${prepareString(
      markingDefinition.definition_type
    )}";
    $markingDefinition has definition "${prepareString(
      markingDefinition.definition
    )}";
    $markingDefinition has color "${prepareString(markingDefinition.color)}";
    $markingDefinition has level ${markingDefinition.level};
    $markingDefinition has created ${now()};
    $markingDefinition has modified ${now()};
    $markingDefinition has revoked false;
    $markingDefinition has created_at ${now()};
    $markingDefinition has created_at_day "${dayFormat(now())}";
    $markingDefinition has created_at_month "${monthFormat(now())}";
    $markingDefinition has created_at_year "${yearFormat(now())}";       
    $markingDefinition has updated_at ${now()};
  `);
  const createMarkingDefinition = await markingDefinitionIterator.next();
  const createdMarkingDefinitionId = await createMarkingDefinition
    .map()
    .get('markingDefinition').id;

  if (markingDefinition.createdByRef) {
    await wTx.query(`match $from id ${createdMarkingDefinitionId};
         $to id ${markingDefinition.createdByRef};
         insert (so: $from, creator: $to)
         isa created_by_ref;`);
  }

  await wTx.commit();

  return getById(createdMarkingDefinitionId).then(created =>
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
  editInputTx(markingDefinitionId, input).then(markingDefinition =>
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, markingDefinition, user)
  );
