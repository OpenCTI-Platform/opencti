import { assoc, dissoc, propOr } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteRelationById,
  executeWrite,
  getRelationInferredById,
  internalLoadEntityById,
  listRelations,
  loadRelationById,
  updateAttribute,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { ForbiddenAccess } from '../config/errors';
import { elCount } from '../database/elasticSearch';
import { INDEX_STIX_RELATIONS } from '../database/utils';
import { isStixId, isStandardId, isStixRelation } from '../utils/idGenerator';

export const findAll = async (args) => {
  return listRelations(propOr('stix_relation', 'relationType', args), args);
};
export const findById = (stixRelationId) => {
  if (!isStixId(stixRelationId) && !isStandardId(stixRelationId)) {
    return getRelationInferredById(stixRelationId);
  }
  return loadRelationById(stixRelationId, 'stix_relation');
};

export const stixRelationsNumber = (args) => {
  let finalArgs;
  if (args.type && args.type !== 'stix_relation' && args.type !== 'stix_relation_embedded') {
    finalArgs = assoc('relationshipType', args.type, args);
  } else {
    finalArgs = args.type ? assoc('types', [args.type], args) : assoc('types', ['stix_relation'], args);
  }
  return {
    count: elCount(INDEX_STIX_RELATIONS, finalArgs),
    total: elCount(INDEX_STIX_RELATIONS, dissoc('endDate', finalArgs)),
  };
};

// region mutations
export const addStixRelation = async (user, stixRelation, reversedReturn = false) => {
  // We force the created by ref if not specified
  let input = stixRelation;
  if (!stixRelation.createdByRef) {
    input = assoc('createdByRef', user.id, stixRelation);
  }
  const created = await createRelation(user, input, { reversedReturn });
  return notify(BUS_TOPICS.StixRelation.ADDED_TOPIC, created, user);
};
export const stixRelationDelete = async (user, stixRelationId) => {
  return deleteRelationById(user, stixRelationId, 'stix_relation');
};
export const stixRelationEditField = (user, stixRelationId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, stixRelationId, 'stix_relation', input, wTx);
  }).then(async () => {
    const stixRelation = await loadRelationById(stixRelationId, 'stix_relation');
    return notify(BUS_TOPICS.StixRelation.EDIT_TOPIC, stixRelation, user);
  });
};
export const stixRelationAddRelation = async (user, stixRelationId, input) => {
  const data = await internalLoadEntityById(stixRelationId);
  if (!isStixRelation(data.type) || !input.through) {
    throw ForbiddenAccess();
  }
  const finalInput = assoc('fromId', stixRelationId, input);
  return createRelation(user, finalInput).then((relationData) => {
    notify(BUS_TOPICS.StixRelation.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const stixRelationDeleteRelation = async (user, stixRelationId, relationId) => {
  await deleteRelationById(user, relationId, 'stix_relation_embedded');
  const data = await loadRelationById(stixRelationId, 'stix_relation');
  return notify(BUS_TOPICS.StixRelation.EDIT_TOPIC, data, user);
};
// endregion

// region context
export const stixRelationCleanContext = (user, stixRelationId) => {
  delEditContext(user, stixRelationId);
  return loadRelationById(stixRelationId, 'stix_relation').then((stixRelation) =>
    notify(BUS_TOPICS.StixRelation.EDIT_TOPIC, stixRelation, user)
  );
};
export const stixRelationEditContext = (user, stixRelationId, input) => {
  setEditContext(user, stixRelationId, input);
  return loadRelationById(stixRelationId, 'stix_relation').then((stixRelation) =>
    notify(BUS_TOPICS.StixRelation.EDIT_TOPIC, stixRelation, user)
  );
};
// endregion
