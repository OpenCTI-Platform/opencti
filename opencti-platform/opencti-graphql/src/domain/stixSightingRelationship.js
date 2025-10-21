import { assoc, dissoc, pipe } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { createRelation, deleteElementById, updateAttribute } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import { elCount } from '../database/engine';
import { READ_INDEX_STIX_SIGHTING_RELATIONSHIPS } from '../database/utils';
import { pageRelationsConnection, storeLoadById } from '../database/middleware-loader';
import { stixObjectOrRelationshipAddRefRelation, stixObjectOrRelationshipAddRefRelations, stixObjectOrRelationshipDeleteRefRelation } from './stixObjectOrStixRelationship';
import { FunctionalError } from '../config/errors';
import { elRemoveElementFromDraft } from '../database/draft-engine';

export const findStixSightingsPaginated = async (context, user, args) => {
  return pageRelationsConnection(context, user, STIX_SIGHTING_RELATIONSHIP, args);
};

export const findById = (context, user, stixSightingRelationshipId) => {
  return storeLoadById(context, user, stixSightingRelationshipId, STIX_SIGHTING_RELATIONSHIP);
};

export const stixSightingRelationshipsNumber = (context, user, args) => ({
  count: elCount(context, user, READ_INDEX_STIX_SIGHTING_RELATIONSHIPS, assoc('types', [STIX_SIGHTING_RELATIONSHIP], args)),
  total: elCount(
    context,
    user,
    READ_INDEX_STIX_SIGHTING_RELATIONSHIPS,
    pipe(assoc('types', [STIX_SIGHTING_RELATIONSHIP]), dissoc('endDate'))(args)
  ),
});

// region mutations
export const addStixSightingRelationship = async (context, user, stixSightingRelationship) => {
  const created = await createRelation(
    context,
    user,
    assoc('relationship_type', STIX_SIGHTING_RELATIONSHIP, stixSightingRelationship)
  );
  return notify(BUS_TOPICS[STIX_SIGHTING_RELATIONSHIP].ADDED_TOPIC, created, user);
};
export const stixSightingRelationshipDelete = async (context, user, stixSightingRelationshipId) => {
  await deleteElementById(context, user, stixSightingRelationshipId, STIX_SIGHTING_RELATIONSHIP);
  return stixSightingRelationshipId;
};
export const stixSightingRelationshipEditField = async (context, user, relationshipId, input, opts) => {
  const { element } = await updateAttribute(context, user, relationshipId, STIX_SIGHTING_RELATIONSHIP, input, opts);
  return notify(BUS_TOPICS[STIX_SIGHTING_RELATIONSHIP].EDIT_TOPIC, element, user);
};
// endregion

// region relation ref
export const stixSightingRelationshipAddRelation = async (context, user, stixSightingRelationshipId, input) => {
  return stixObjectOrRelationshipAddRefRelation(context, user, stixSightingRelationshipId, input, STIX_SIGHTING_RELATIONSHIP);
};
export const stixSightingRelationshipAddRelations = async (context, user, stixSightingRelationshipId, input, opts = {}) => {
  return stixObjectOrRelationshipAddRefRelations(context, user, stixSightingRelationshipId, input, STIX_SIGHTING_RELATIONSHIP, opts);
};
export const stixSightingRelationshipDeleteRelation = async (context, user, stixSightingRelationshipId, toId, relationshipType, opts = {}) => {
  return stixObjectOrRelationshipDeleteRefRelation(context, user, stixSightingRelationshipId, toId, relationshipType, STIX_SIGHTING_RELATIONSHIP, opts);
};
// endregion

// region context
export const stixSightingRelationshipCleanContext = async (context, user, stixSightingRelationshipId) => {
  await delEditContext(user, stixSightingRelationshipId);
  const stixSightingRelationship = await storeLoadById(context, user, stixSightingRelationshipId, STIX_SIGHTING_RELATIONSHIP);
  return await notify(BUS_TOPICS[STIX_SIGHTING_RELATIONSHIP].EDIT_TOPIC, stixSightingRelationship, user);
};
export const stixSightingRelationshipEditContext = async (context, user, stixSightingRelationshipId, input) => {
  await setEditContext(user, stixSightingRelationshipId, input);
  const stixSightingRelationship = await storeLoadById(context, user, stixSightingRelationshipId, STIX_SIGHTING_RELATIONSHIP);
  return await notify(BUS_TOPICS[STIX_SIGHTING_RELATIONSHIP].EDIT_TOPIC, stixSightingRelationship, user);
};
// endregion

export const stixSightingRelationshipRemoveFromDraft = async (context, user, stixCoreObjectId) => {
  const stixSighting = await storeLoadById(context, user, stixCoreObjectId, STIX_SIGHTING_RELATIONSHIP, { includeDeletedInDraft: true });
  if (!stixSighting) {
    throw FunctionalError('Cannot remove the object from draft, Stix-Sighting-Relationship cannot be found.', { id: stixCoreObjectId});
  }
  // TODO currently not locked, but might need to be
  await elRemoveElementFromDraft(context, user, stixSighting);
  return stixSighting.id;
};
