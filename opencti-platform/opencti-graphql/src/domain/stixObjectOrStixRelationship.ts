import { elLoadById } from '../database/engine';
import { READ_PLATFORM_INDICES, UPDATE_OPERATION_ADD } from '../database/utils';
import { storeLoadById } from '../database/middleware-loader';
import { ABSTRACT_STIX_REF_RELATIONSHIP } from '../schema/general';
import { FunctionalError } from '../config/errors';
import { isStixRefRelationship } from '../schema/stixRefRelationship';
import { createRelations, deleteRelationsByFromAndTo, patchAttribute } from '../database/middleware';
import { notify } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import type { AuthContext, AuthUser } from '../types/user';
import type { StixRefRelationshipAddInput, StixRefRelationshipsAddInput } from '../generated/graphql';
import type { BasicStoreObject } from '../types/store';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';

type BusTopicsKeyType = keyof typeof BUS_TOPICS;

export const findById = async <T extends BasicStoreObject> (context: AuthContext, user: AuthUser, id: string) : Promise<T> => {
  return await elLoadById(context, user, id, { indices: READ_PLATFORM_INDICES }) as unknown as T;
};

export const stixObjectOrRelationshipAddRefRelation = async (
  context: AuthContext,
  user: AuthUser,
  stixObjectOrRelationshipId: string,
  input: StixRefRelationshipAddInput,
  type: string
) => {
  const stixObjectOrRelationship = await storeLoadById(context, user, stixObjectOrRelationshipId, type);
  if (!stixObjectOrRelationship) {
    throw FunctionalError('Cannot add the relation, Stix-Object or Stix-Relationship cannot be found.');
  }
  const finalInput = { ...input, fromId: stixObjectOrRelationshipId };
  if (!isStixRefRelationship(finalInput.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_REF_RELATIONSHIP} can be added through this method.`);
  }
  // Create relation
  const fieldName = schemaRelationsRefDefinition.convertDatabaseNameToInputName(type, input.relationship_type);
  const patch = { [fieldName as string]: [input.toId] };
  const operations = { [fieldName as string]: UPDATE_OPERATION_ADD };
  const { element } = await patchAttribute(context, user, stixObjectOrRelationshipId, type, patch, { operations });
  const relation = { ...element, from: stixObjectOrRelationship, fromId: stixObjectOrRelationshipId };
  await notify(BUS_TOPICS[type as BusTopicsKeyType].EDIT_TOPIC, relation, user);
  return relation;
};
export const stixObjectOrRelationshipAddRefRelations = async (
  context: AuthContext,
  user: AuthUser,
  stixObjectOrRelationshipId: string,
  input: StixRefRelationshipsAddInput,
  type: string,
  opts = {}
) => {
  const stixObjectOrRelationship = await storeLoadById(context, user, stixObjectOrRelationshipId, type);
  if (!stixObjectOrRelationship) {
    throw FunctionalError('Cannot add the relation, Stix-Object or Stix-Relationship cannot be found.');
  }
  if (!isStixRefRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_REF_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = input.toIds?.map(
    (n) => ({ fromId: stixObjectOrRelationshipId, toId: n, relationship_type: input.relationship_type })
  ) ?? [];
  await createRelations(context, user, finalInput, opts);
  const entity = await storeLoadById(context, user, stixObjectOrRelationshipId, type);
  await notify(BUS_TOPICS[type as BusTopicsKeyType].EDIT_TOPIC, entity, user);
  return entity;
};

export const stixObjectOrRelationshipDeleteRefRelation = async (
  context: AuthContext,
  user: AuthUser,
  stixObjectOrRelationshipId: string,
  toId: string,
  relationshipType: string,
  type: string,
  opts = {}
): Promise<any> => { // TODO remove any when all resolvers in ts
  const stixObjectOrRelationship = await storeLoadById(context, user, stixObjectOrRelationshipId, type);
  if (!stixObjectOrRelationship) {
    throw FunctionalError('Cannot delete the relation, Stix-Object or Stix-Relationship cannot be found.');
  }
  if (!isStixRefRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_REF_RELATIONSHIP} can be deleted through this method.`);
  }
  const { from, to } = await deleteRelationsByFromAndTo(context, user, stixObjectOrRelationshipId, toId, relationshipType, ABSTRACT_STIX_REF_RELATIONSHIP, opts);
  await notify((BUS_TOPICS[type as BusTopicsKeyType]).EDIT_TOPIC, from, user);
  return { ...stixObjectOrRelationship, from, to };
};
