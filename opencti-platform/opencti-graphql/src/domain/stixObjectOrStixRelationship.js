import { elLoadById } from '../database/engine';
import { READ_PLATFORM_INDICES } from '../database/utils';
import { storeLoadById } from '../database/middleware-loader';
import { ABSTRACT_STIX_REF_RELATIONSHIP } from '../schema/general';
import { FunctionalError } from '../config/errors';
import { isStixRefRelationship } from '../schema/stixRefRelationship';
import { createRelation, createRelations, deleteRelationsByFromAndTo } from '../database/middleware';
import { notify } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';

export const findById = async (context, user, id) => {
  return elLoadById(context, user, id, { indices: READ_PLATFORM_INDICES });
};

export const stixObjectOrRelationshipAddRefRelation = async (context, user, stixObjectOrRelationshipId, input, type) => {
  const stixObjectOrRelationship = await storeLoadById(context, user, stixObjectOrRelationshipId, type);
  if (!stixObjectOrRelationship) {
    throw FunctionalError('Cannot add the relation, Stix-Object or Stix-Relationship cannot be found.');
  }
  const finalInput = { ...input, fromId: stixObjectOrRelationshipId };
  if (!isStixRefRelationship(finalInput.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_REF_RELATIONSHIP} can be added through this method.`);
  }
  return createRelation(context, user, finalInput).then((relationData) => {
    return notify(BUS_TOPICS[ABSTRACT_STIX_REF_RELATIONSHIP].ADDED_TOPIC, relationData, user);
  });
};
export const stixObjectOrRelationshipAddRelations = async (context, user, stixObjectOrRelationshipId, input, type) => {
  const stixObjectOrRelationship = await storeLoadById(context, user, stixObjectOrRelationshipId, type);
  if (!stixObjectOrRelationship) {
    throw FunctionalError('Cannot add the relation, Stix-Object or Stix-Relationship cannot be found.');
  }
  if (!isStixRefRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_REF_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = input.toIds.map(
    (n) => ({ fromId: stixObjectOrRelationshipId, toId: n, relationship_type: input.relationship_type })
  );
  await createRelations(context, user, finalInput);
  const entity = await storeLoadById(context, user, stixObjectOrRelationshipId, type);
  return notify(BUS_TOPICS[type].EDIT_TOPIC, entity, user);
};

export const stixObjectOrRelationshipDeleteRelation = async (context, user, stixObjectOrRelationshipId, toId, relationshipType, type) => {
  const stixObjectOrRelationship = await storeLoadById(context, user, stixObjectOrRelationshipId, type);
  if (!stixObjectOrRelationship) {
    throw FunctionalError('Cannot delete the relation, Stix-Object or Stix-Relationship cannot be found.');
  }
  if (!isStixRefRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_REF_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(context, user, stixObjectOrRelationshipId, toId, relationshipType, ABSTRACT_STIX_REF_RELATIONSHIP);
  return notify(BUS_TOPICS[type].EDIT_TOPIC, stixObjectOrRelationship, user);
};
