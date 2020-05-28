import { assoc, dissoc, includes, propOr } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteRelationById,
  executeWrite,
  getRelationInferredById,
  listRelations,
  loadEntityById,
  loadRelationById,
  loadRelationByStixId,
  updateAttribute,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { ForbiddenAccess } from '../config/errors';
import { elCount } from '../database/elasticSearch';
import { INDEX_STIX_RELATIONS } from '../database/utils';

export const findAll = async (args) => {
  return listRelations(propOr('stix_relation', 'relationType', args), args);
};
export const findById = (stixRelationId) => {
  if (stixRelationId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadRelationByStixId(stixRelationId, 'stix_relation');
  }
  if (stixRelationId.length !== 36) {
    return getRelationInferredById(stixRelationId);
  }
  return loadRelationById(stixRelationId, 'stix_relation');
};

export const stixRelationsNumber = (args) => {
  const finalArgs = args.type ? assoc('types', [args.type], args) : args;
  return {
    count: elCount(INDEX_STIX_RELATIONS, finalArgs),
    total: elCount(INDEX_STIX_RELATIONS, dissoc('endDate', finalArgs)),
  };
};

// region mutations
export const addStixRelation = async (user, stixRelation, reversedReturn = false) => {
  if (!includes('stix_id_key', Object.keys(stixRelation)) && !stixRelation.relationship_type) {
    throw ForbiddenAccess();
  }
  // We force the created by ref if not specified
  let input = stixRelation;
  if (!stixRelation.createdByRef) {
    input = assoc('createdByRef', user.id, stixRelation);
  }
  const created = await createRelation(user, stixRelation.fromId, input, { reversedReturn });
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
  const data = await loadEntityById(stixRelationId, 'stix_relation');
  if (!data.parent_types.includes('stix_relation') || !input.through) {
    throw ForbiddenAccess();
  }
  return createRelation(user, stixRelationId, input).then((relationData) => {
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
