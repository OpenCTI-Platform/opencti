import { includes, propOr } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteRelationById,
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
  return listRelations(propOr('stix_sighting', 'relationType', args), args);
};
export const findById = (stixSightingId) => {
  if (stixSightingId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadRelationByStixId(stixSightingId, 'stix_sighting');
  }
  if (stixSightingId.length !== 36) {
    return getRelationInferredById(stixSightingId);
  }
  return loadRelationById(stixSightingId, 'stix_sighting');
};

export const stixSightingsNumber = (args) => ({
  count: getSingleValueNumber(
    `match $x($y, $z) isa stix_sighting; ${
      args.endDate ? `$x has created_at $date; $date < ${prepareDate(args.endDate)};` : ''
    } ${args.fromId ? `$y has internal_id_key "${escapeString(args.fromId)}";` : ''} get; count;`,
    args.inferred ? args.inferred : false
  ),
  total: getSingleValueNumber(
    `match $x($y, $z) isa stix_sighting; ${
      args.fromId ? `$y has internal_id_key "${escapeString(args.fromId)}";` : ''
    } get; count;`,
    args.inferred ? args.inferred : false
  ),
});

// region mutations
export const addstixSighting = async (user, stixSighting, reversedReturn = false) => {
  if (!includes('stix_id_key', Object.keys(stixSighting)) && !stixSighting.relationship_type) {
    throw new ForbiddenAccess();
  }
  const created = await createRelation(user, stixSighting.fromId, stixSighting, { reversedReturn });
  return notify(BUS_TOPICS.stixSighting.ADDED_TOPIC, created, user);
};
export const stixSightingDelete = async (user, stixSightingId) => {
  return deleteRelationById(user, stixSightingId, 'stix_sighting');
};
export const stixSightingEditField = (user, stixSightingId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, stixSightingId, 'stix_sighting', input, wTx);
  }).then(async () => {
    const stixSighting = await loadRelationById(stixSightingId, 'stix_sighting');
    return notify(BUS_TOPICS.stixSighting.EDIT_TOPIC, stixSighting, user);
  });
};
export const stixSightingAddRelation = async (user, stixSightingId, input) => {
  const data = await loadEntityById(stixSightingId, 'stix_sighting');
  if (!data.parent_types.includes('stix_sighting') || !input.through) {
    throw new ForbiddenAccess();
  }
  return createRelation(user, stixSightingId, input).then((relationData) => {
    notify(BUS_TOPICS.stixSighting.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const stixSightingDeleteRelation = async (user, stixSightingId, relationId) => {
  await deleteRelationById(user, relationId, 'stix_relation_embedded');
  const data = await loadRelationById(stixSightingId, 'stix_sighting');
  return notify(BUS_TOPICS.stixSighting.EDIT_TOPIC, data, user);
};
// endregion

// region context
export const stixSightingCleanContext = (user, stixSightingId) => {
  delEditContext(user, stixSightingId);
  return loadRelationById(stixSightingId, 'stix_sighting').then((stixSighting) =>
    notify(BUS_TOPICS.stixSighting.EDIT_TOPIC, stixSighting, user)
  );
};
export const stixSightingEditContext = (user, stixSightingId, input) => {
  setEditContext(user, stixSightingId, input);
  return loadRelationById(stixSightingId, 'stix_sighting').then((stixSighting) =>
    notify(BUS_TOPICS.stixSighting.EDIT_TOPIC, stixSighting, user)
  );
};
// endregion
