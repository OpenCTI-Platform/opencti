import { pipe, assoc } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteRelationById,
  escapeString,
  executeWrite,
  getRelationInferredById,
  getSingleValueNumber,
  internalLoadEntityById,
  listRelations, loadEntityById,
  loadRelationById,
  prepareDate,
  updateAttribute,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { ForbiddenAccess } from '../config/errors';
import {
  ABSTRACT_STIX_SIGHTING_RELATIONSHIP,
  isInternalId,
  isStixId,
  RELATION_SIGHTING_POSITIVE,
} from '../utils/idGenerator';

export const findAll = async (args) => {
  return listRelations(ABSTRACT_STIX_SIGHTING_RELATIONSHIP, args);
};
export const findById = (stixSightingId) => {
  if (!isStixId(stixSightingId) && !isInternalId(stixSightingId)) {
    return getRelationInferredById(stixSightingId);
  }
  return loadRelationById(stixSightingId, ABSTRACT_STIX_SIGHTING_RELATIONSHIP);
};

export const stixSightingsNumber = (args) => ({
  count: getSingleValueNumber(
    `match $x($y, $z) isa ${ABSTRACT_STIX_SIGHTING_RELATIONSHIP}; ${
      args.endDate ? `$x has created_at $date; $date < ${prepareDate(args.endDate)};` : ''
    } ${args.fromId ? `$y has internal_id_key "${escapeString(args.fromId)}";` : ''} get; count;`,
    args.inferred ? args.inferred : false
  ),
  total: getSingleValueNumber(
    `match $x($y, $z) isa ${ABSTRACT_STIX_SIGHTING_RELATIONSHIP}; ${
      args.fromId ? `$y has internal_id_key "${escapeString(args.fromId)}";` : ''
    } get; count;`,
    args.inferred ? args.inferred : false
  ),
});

// region mutations
export const addstixSighting = async (user, stixSighting, reversedReturn = false) => {
  // TODO @JRI @SAM Define when to use RELATION_SIGHTING_POSITIVE or NEGATIVE
  const finalStixSighting = pipe(
    assoc('relationship_type', RELATION_SIGHTING_POSITIVE),
    assoc('fromRole', 'so'),
    assoc('toId', stixSighting.toId ? stixSighting.toId : user.id),
    assoc('toRole', 'sighted_in')
  )(stixSighting);
  const created = await createRelation(user, finalStixSighting, {
    reversedReturn,
    isStixSighting: true,
  });
  return notify(BUS_TOPICS.StixSighting.ADDED_TOPIC, created, user);
};
export const stixSightingDelete = async (user, stixSightingId) => {
  return deleteRelationById(user, stixSightingId, RELATION_SIGHTING_POSITIVE);
};
export const stixSightingEditField = (user, stixSightingId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, stixSightingId, RELATION_SIGHTING_POSITIVE, input, wTx);
  }).then(async () => {
    const stixSighting = await loadRelationById(stixSightingId, RELATION_SIGHTING_POSITIVE);
    return notify(BUS_TOPICS.StixSighting.EDIT_TOPIC, stixSighting, user);
  });
};
export const stixSightingAddRelation = async (user, stixSightingId, input) => {
  const data = await loadEntityById(stixSightingId, RELATION_SIGHTING_POSITIVE);
  if (data.type !== ABSTRACT_STIX_SIGHTING_RELATIONSHIP || !input.through) {
    throw ForbiddenAccess();
  }
  const finalInput = assoc('fromId', stixSightingId, input);
  return createRelation(user, finalInput).then((relationData) => {
    notify(BUS_TOPICS.StixSighting.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const stixSightingDeleteRelation = async (user, stixSightingId, relationId) => {
  await deleteRelationById(user, relationId, ABSTRACT_STIX_SIGHTING_RELATIONSHIP);
  const data = await loadRelationById(stixSightingId, RELATION_SIGHTING_POSITIVE);
  return notify(BUS_TOPICS.StixSighting.EDIT_TOPIC, data, user);
};
// endregion

// region context
export const stixSightingCleanContext = (user, stixSightingId) => {
  delEditContext(user, stixSightingId);
  return loadRelationById(stixSightingId, RELATION_SIGHTING_POSITIVE).then((stixSighting) =>
    notify(BUS_TOPICS.StixSighting.EDIT_TOPIC, stixSighting, user)
  );
};
export const stixSightingEditContext = (user, stixSightingId, input) => {
  setEditContext(user, stixSightingId, input);
  return loadRelationById(stixSightingId, RELATION_SIGHTING_POSITIVE).then((stixSighting) =>
    notify(BUS_TOPICS.StixSighting.EDIT_TOPIC, stixSighting, user)
  );
};
// endregion
