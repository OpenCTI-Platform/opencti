import { pipe, assoc } from 'ramda';
import {
  findAll as stixRelationFindAll,
  findById as findByIdStixRelation,
  stixRelationAddRelation,
  stixRelationCleanContext,
  stixRelationDelete,
  stixRelationDeleteRelation,
  stixRelationEditContext,
  stixRelationEditField,
} from './stixRelation';
import { createRelation } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';

export const findAll = (args) =>
  stixRelationFindAll(args.relationType ? args : assoc('relationType', 'stix_observable_relation', args));

export const findById = (id) => findByIdStixRelation(id);

// region mutations
export const addStixObservableRelation = async (user, input, reversedReturn = false) => {
  const finalInput = pipe(assoc('fromType', 'Stix-Observable'), assoc('toType', 'Stix-Observable'))(input);
  const created = await createRelation(finalInput.fromId, finalInput, {
    reversedReturn,
    isStixObservableRelation: true,
  });
  return notify(BUS_TOPICS.StixObservableRelation.ADDED_TOPIC, created, user);
};
export const stixObservableRelationDelete = async (stixObservableRelationId) =>
  stixRelationDelete(stixObservableRelationId);

export const stixObservableRelationCleanContext = (user, stixObservableRelationId) =>
  stixRelationCleanContext(user, stixObservableRelationId);

export const stixObservableRelationEditContext = (user, stixObservableRelationId, input) =>
  stixRelationEditContext(user, stixObservableRelationId, input);

export const stixObservableRelationEditField = (user, stixObservableRelationId, input) =>
  stixRelationEditField(user, stixObservableRelationId, input);

export const stixObservableRelationAddRelation = (user, stixObservableRelationId, input) =>
  stixRelationAddRelation(user, stixObservableRelationId, input);

export const stixObservableRelationDeleteRelation = (user, stixObservableRelationId, relationId) =>
  stixRelationDeleteRelation(user, stixObservableRelationId, relationId);
// endregion
