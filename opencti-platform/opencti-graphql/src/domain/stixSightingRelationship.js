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
export const findById = (stixSightingRelationshipId) => {
  if (!isStixId(stixSightingRelationshipId) && !isInternalId(stixSightingRelationshipId)) {
    return getRelationInferredById(stixSightingRelationshipId);
  }
  return loadRelationById(stixSightingRelationshipId, STIX_SIGHTING_RELATIONSHIP);
};

export const stixSightingRelationshipsNumber = (args) => ({
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
export const addstixSightingRelationship = async (user, stixSightingRelationship, reversedReturn = false) => {
  const created = await createRelation(user, stixSightingRelationship, { reversedReturn });
  return notify(BUS_TOPICS.StixSightingRelationship.ADDED_TOPIC, created, user);
};
export const stixSightingRelationshipDelete = async (user, stixSightingRelationshipId) => {
  return deleteRelationById(user, stixSightingRelationshipId, STIX_SIGHTING_RELATIONSHIP);
};
export const stixSightingRelationshipEditField = (user, stixSightingRelationshipId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, stixSightingRelationshipId, STIX_SIGHTING_RELATIONSHIP, input, wTx);
  }).then(async () => {
    const stixSightingRelationship = await loadRelationById(stixSightingRelationshipId, STIX_SIGHTING_RELATIONSHIP);
    return notify(BUS_TOPICS.StixSightingRelationship.EDIT_TOPIC, stixSightingRelationship, user);
  });
};
export const stixSightingRelationshipAddRelation = async (user, stixSightingRelationshipId, input) => {
  const data = await loadEntityById(stixSightingRelationshipId, STIX_SIGHTING_RELATIONSHIP);
  if (data.type !== STIX_SIGHTING_RELATIONSHIP || !input.relationship_type) {
    throw ForbiddenAccess();
  }
  const finalInput = assoc('fromId', stixSightingRelationshipId, input);
  return createRelation(user, finalInput).then((relationData) => {
    notify(BUS_TOPICS.StixSightingRelationship.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const stixSightingRelationshipDeleteRelation = async (user, stixSightingRelationshipId, relationId) => {
  await deleteRelationById(user, relationId, STIX_SIGHTING_RELATIONSHIP);
  const data = await loadRelationById(stixSightingRelationshipId, STIX_SIGHTING_RELATIONSHIP);
  return notify(BUS_TOPICS.StixSightingRelationship.EDIT_TOPIC, data, user);
};
// endregion

// region context
export const stixSightingRelationshipCleanContext = (user, stixSightingRelationshipId) => {
  delEditContext(user, stixSightingRelationshipId);
  return loadRelationById(stixSightingRelationshipId, STIX_SIGHTING_RELATIONSHIP).then((stixSightingRelationship) =>
    notify(BUS_TOPICS.StixSightingRelationship.EDIT_TOPIC, stixSightingRelationship, user)
  );
};
export const stixSightingRelationshipEditContext = (user, stixSightingRelationshipId, input) => {
  setEditContext(user, stixSightingRelationshipId, input);
  return loadRelationById(stixSightingRelationshipId, STIX_SIGHTING_RELATIONSHIP).then((stixSightingRelationship) =>
    notify(BUS_TOPICS.StixSightingRelationship.EDIT_TOPIC, stixSightingRelationship, user)
  );
};
// endregion
