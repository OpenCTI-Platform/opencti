import { assoc } from 'ramda';
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
  prepareDate,
  updateAttribute,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { ForbiddenAccess } from '../config/errors';
import { isInternalId, isStixId, STIX_SIGHTING_RELATIONSHIP } from '../utils/idGenerator';

export const findAll = async (args) => {
  return listRelations(STIX_SIGHTING_RELATIONSHIP, args);
};
export const findById = (stixSightingId) => {
  if (!isStixId(stixSightingId) && !isInternalId(stixSightingId)) {
    return getRelationInferredById(stixSightingId);
  }
  return loadRelationById(stixSightingId, STIX_SIGHTING_RELATIONSHIP);
};

export const stixSightingsNumber = (args) => ({
  count: getSingleValueNumber(
    `match $x($y, $z) isa ${STIX_SIGHTING_RELATIONSHIP}; ${
      args.endDate ? `$x has created_at $date; $date < ${prepareDate(args.endDate)};` : ''
    } ${args.fromId ? `$y has internal_id "${escapeString(args.fromId)}";` : ''} get; count;`,
    args.inferred ? args.inferred : false
  ),
  total: getSingleValueNumber(
    `match $x($y, $z) isa ${STIX_SIGHTING_RELATIONSHIP}; ${
      args.fromId ? `$y has internal_id "${escapeString(args.fromId)}";` : ''
    } get; count;`,
    args.inferred ? args.inferred : false
  ),
});

// region mutations
export const addstixSighting = async (user, stixSighting, reversedReturn = false) => {
  const created = await createRelation(user, stixSighting, { reversedReturn });
  return notify(BUS_TOPICS.StixSighting.ADDED_TOPIC, created, user);
};
export const stixSightingDelete = async (user, stixSightingId) => {
  return deleteRelationById(user, stixSightingId, STIX_SIGHTING_RELATIONSHIP);
};
export const stixSightingEditField = (user, stixSightingId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, stixSightingId, STIX_SIGHTING_RELATIONSHIP, input, wTx);
  }).then(async () => {
    const stixSighting = await loadRelationById(stixSightingId, STIX_SIGHTING_RELATIONSHIP);
    return notify(BUS_TOPICS.StixSighting.EDIT_TOPIC, stixSighting, user);
  });
};
export const stixSightingAddRelation = async (user, stixSightingId, input) => {
  const data = await loadEntityById(stixSightingId, STIX_SIGHTING_RELATIONSHIP);
  if (data.type !== STIX_SIGHTING_RELATIONSHIP || !input.relationship_type) {
    throw ForbiddenAccess();
  }
  const finalInput = assoc('fromId', stixSightingId, input);
  return createRelation(user, finalInput).then((relationData) => {
    notify(BUS_TOPICS.StixSighting.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const stixSightingDeleteRelation = async (user, stixSightingId, relationId) => {
  await deleteRelationById(user, relationId, STIX_SIGHTING_RELATIONSHIP);
  const data = await loadRelationById(stixSightingId, STIX_SIGHTING_RELATIONSHIP);
  return notify(BUS_TOPICS.StixSighting.EDIT_TOPIC, data, user);
};
// endregion

// region context
export const stixSightingCleanContext = (user, stixSightingId) => {
  delEditContext(user, stixSightingId);
  return loadRelationById(stixSightingId, STIX_SIGHTING_RELATIONSHIP).then((stixSighting) =>
    notify(BUS_TOPICS.StixSighting.EDIT_TOPIC, stixSighting, user)
  );
};
export const stixSightingEditContext = (user, stixSightingId, input) => {
  setEditContext(user, stixSightingId, input);
  return loadRelationById(stixSightingId, STIX_SIGHTING_RELATIONSHIP).then((stixSighting) =>
    notify(BUS_TOPICS.StixSighting.EDIT_TOPIC, stixSighting, user)
  );
};
// endregion
