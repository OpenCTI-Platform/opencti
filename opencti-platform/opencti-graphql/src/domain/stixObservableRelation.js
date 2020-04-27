import { pipe, assoc } from 'ramda';
import { findAll as stixRelationFindAll, stixRelationCleanContext, stixRelationEditContext } from './stixRelation';
import {
  createRelation,
  deleteRelationById,
  executeWrite,
  getRelationInferredById,
  loadRelationById,
  loadRelationByStixId,
  updateAttribute,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';

export const findAll = (args) =>
  stixRelationFindAll(args.relationType ? args : assoc('relationType', 'stix_observable_relation', args));

export const findById = (stixObservableRelationId) => {
  if (stixObservableRelationId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadRelationByStixId(stixObservableRelationId, 'stix_observable_relation');
  }
  if (stixObservableRelationId.length !== 36) {
    return getRelationInferredById(stixObservableRelationId);
  }
  return loadRelationById(stixObservableRelationId, 'stix_observable_relation');
};

// region mutations
export const addStixObservableRelation = async (user, input, reversedReturn = false) => {
  const finalInput = pipe(assoc('fromType', 'Stix-Observable'), assoc('toType', 'Stix-Observable'))(input);
  const created = await createRelation(user, finalInput.fromId, finalInput, {
    reversedReturn,
    isStixObservableRelation: true,
    noLog: true,
  });
  return notify(BUS_TOPICS.StixObservableRelation.ADDED_TOPIC, created, user);
};
export const stixObservableRelationDelete = async (user, stixObservableRelationId) => {
  return deleteRelationById(user, stixObservableRelationId, 'stix_observable_relation', { noLog: true });
};

export const stixObservableRelationCleanContext = (user, stixObservableRelationId) =>
  stixRelationCleanContext(user, stixObservableRelationId);

export const stixObservableRelationEditContext = (user, stixObservableRelationId, input) =>
  stixRelationEditContext(user, stixObservableRelationId, input);

export const stixObservableRelationEditField = (user, stixObservableRelationId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, stixObservableRelationId, 'stix_observable_relation', input, wTx, { noLog: true });
  }).then(async () => {
    const stixObservableRelation = await loadRelationById(stixObservableRelationId, 'stix_observable_relation');
    return notify(BUS_TOPICS.StixObservableRelation.EDIT_TOPIC, stixObservableRelation, user);
  });
};
// endregion
