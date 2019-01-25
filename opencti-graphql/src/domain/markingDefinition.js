import { head } from 'ramda';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteByID,
  deleteRelation,
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
    return loadByID(head(data).markingDefinition.id).then(created =>
      notify(BUS_TOPICS.MarkingDefinition.ADDED_TOPIC, created)
    );
  });
};

export const markingDefinitionDelete = markingDefinitionId =>
  deleteByID(markingDefinitionId);

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
  deleteRelation(markingDefinitionId, relationId).then(relationData => {
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const markingDefinitionCleanContext = (user, markingDefinitionId) => {
  delEditContext(user, markingDefinitionId);
  return loadByID(markingDefinitionId).then(markingDefinition =>
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, markingDefinition, user)
  );
};

export const markingDefinitionEditContext = (
  user,
  markingDefinitionId,
  input
) => {
  setEditContext(user, markingDefinitionId, input);
  return loadByID(markingDefinitionId).then(markingDefinition =>
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, markingDefinition, user)
  );
};

export const markingDefinitionEditField = (user, markingDefinitionId, input) =>
  editInputTx(markingDefinitionId, input).then(markingDefinition =>
    notify(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC, markingDefinition, user)
  );
