import { elLoadById } from '../database/engine';
import { READ_PLATFORM_INDICES } from '../database/utils';
import { storeLoadById } from '../database/middleware-loader';
import { ABSTRACT_STIX_META_RELATIONSHIP } from '../schema/general';
import { FunctionalError } from '../config/errors';
import { isStixMetaRelationship } from '../schema/stixMetaRelationship';
import { deleteRelationsByFromAndTo } from '../database/middleware';
import { notify } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';

// eslint-disable-next-line import/prefer-default-export
export const findById = async (context, user, id) => {
  return elLoadById(context, user, id, null, READ_PLATFORM_INDICES);
};

export const stixObjectOrRelationshipDeleteRelation = async (context, user, stixObjectOrRelationshipId, toId, relationshipType, type) => {
  const stixObjectOrRelationship = await storeLoadById(context, user, stixObjectOrRelationshipId, type);
  if (!stixObjectOrRelationship) {
    throw FunctionalError('Cannot delete the relation, Stix-Object or Stix-Relationship cannot be found.');
  }
  if (!isStixMetaRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(context, user, stixObjectOrRelationshipId, toId, relationshipType, ABSTRACT_STIX_META_RELATIONSHIP);
  return notify(BUS_TOPICS[type].EDIT_TOPIC, stixObjectOrRelationship, user);
};
