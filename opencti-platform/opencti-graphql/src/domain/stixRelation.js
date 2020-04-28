import { includes, propOr } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteRelationById,
  escape,
  escapeString,
  executeWrite,
  getRelationInferredById,
  getSingleValueNumber,
  listRelations,
  loadEntityById,
  loadRelationById,
  loadRelationByStixId,
  prepareDate,
  updateAttribute,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { ForbiddenAccess } from '../config/errors';

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

export const stixRelationsNumber = (args) => ({
  count: getSingleValueNumber(
    `match $x($y, $z) isa ${args.type ? escape(args.type) : 'stix_relation'};
    ${
      args.endDate
        ? `$x has created_at $date;
    $date < ${prepareDate(args.endDate)};`
        : ''
    }
    ${args.fromId ? `$y has internal_id_key "${escapeString(args.fromId)}";` : ''}
    get;
    count;`,
    args.inferred ? args.inferred : false
  ),
  total: getSingleValueNumber(
    `match $x($y, $z) isa ${args.type ? escape(args.type) : 'stix_relation'};
    ${args.fromId ? `$y has internal_id_key "${escapeString(args.fromId)}";` : ''}
    get;
    count;`,
    args.inferred ? args.inferred : false
  ),
});

// region mutations
export const addStixRelation = async (user, stixRelation, reversedReturn = false) => {
  if (!includes('stix_id_key', Object.keys(stixRelation)) && !stixRelation.relationship_type) {
    throw new ForbiddenAccess();
  }
  const created = await createRelation(user, stixRelation.fromId, stixRelation, { reversedReturn });
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
    throw new ForbiddenAccess();
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
