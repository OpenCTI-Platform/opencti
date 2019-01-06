import { head } from 'ramda';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteByID,
  deleteRelationByID,
  editInputTx,
  loadByID,
  notify,
  now,
  paginate,
  qk
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args =>
  paginate('match $m isa Marking-Definition', args);
export const findById = markingDefinitionId => loadByID(markingDefinitionId);

export const addMarkingDefinition = async (user, markingDefinition) => {
  const createMarkingDefinition = qk(`insert $markingDefinition isa Marking-Definition 
    has type "marking-definition";
    $markingDefinition has stix_id "marking-definition--${uuid()}";
    $markingDefinition has definition_type "${
      markingDefinition.definition_type
    }";
    $markingDefinition has definition "${markingDefinition.definition}";
    $markingDefinition has color "${markingDefinition.color}";
    $markingDefinition has level ${markingDefinition.level};
    $markingDefinition has created ${now()};
    $markingDefinition has modified ${now()};
    $markingDefinition has revoked false;
    $markingDefinition has created_at ${now()};
    $markingDefinition has updated_at ${now()};
  `);
  return createMarkingDefinition.then(result => {
    const { data } = result;
    return findById(head(data).markingDefinition.id).then(created =>
      notify(BUS_TOPICS.MarkingDefinition.ADDED_TOPIC, created)
    );
  });
};

export const markingDefinitionDelete = markingDefinitionId =>
  deleteByID(markingDefinitionId);

export const markingDefinitionDeleteRelation = relationId =>
  deleteRelationByID(relationId);

export const markingDefinitionAddRelation = (markingDefinitionId, input) =>
  createRelation(markingDefinitionId, input).then(markingDefinition =>
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, markingDefinition)
  );

export const markingDefinitionCleanContext = (user, markingDefinitionId) => {
  delEditContext(user, markingDefinitionId);
  return findById(markingDefinitionId).then(markingDefinition =>
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, markingDefinition)
  );
};

export const markingDefinitionEditContext = (
  user,
  markingDefinitionId,
  input
) => {
  setEditContext(user, markingDefinitionId, input);
  findById(markingDefinitionId).then(markingDefinition =>
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, markingDefinition)
  );
};

export const markingDefinitionEditField = (markingDefinitionId, input) =>
  editInputTx(markingDefinitionId, input).then(markingDefinition =>
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, markingDefinition)
  );
