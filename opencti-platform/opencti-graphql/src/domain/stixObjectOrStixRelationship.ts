import { elLoadById } from '../database/engine';
import { READ_PLATFORM_INDICES, UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE } from '../database/utils';
import { type EntityOptions, storeLoadById } from '../database/middleware-loader';
import { ABSTRACT_STIX_OBJECT, ABSTRACT_STIX_REF_RELATIONSHIP, ABSTRACT_STIX_RELATIONSHIP } from '../schema/general';
import { FunctionalError, UnsupportedError } from '../config/errors';
import { isStixRefRelationship, RELATION_CREATED_BY, RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';
import { pageEntitiesOrRelationsConnection, storeLoadByIdWithRefs, transformPatchToInput, updateAttributeFromLoadedWithRefs, validateCreatedBy } from '../database/middleware';
import { notify } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import type { AuthContext, AuthUser } from '../types/user';
import { type StixRefRelationshipAddInput, type StixRefRelationshipsAddInput } from '../generated/graphql';
import type { BasicStoreCommon, BasicStoreObject, BasicConnection } from '../types/store';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { buildRelationData } from '../database/data-builder';
import { validateMarking } from '../utils/access';

type BusTopicsKeyType = keyof typeof BUS_TOPICS;

export const findById = async <T extends BasicStoreObject> (context: AuthContext, user: AuthUser, id: string): Promise<T> => {
  return await elLoadById(context, user, id, { indices: READ_PLATFORM_INDICES }) as unknown as T;
};

export const findStixObjectOrRelationshipsPaginated = async <T extends BasicStoreObject> (context: AuthContext, user: AuthUser,
  args: EntityOptions<BasicStoreCommon>): Promise<BasicConnection<T>> => {
  return await pageEntitiesOrRelationsConnection(context, user, [ABSTRACT_STIX_OBJECT, ABSTRACT_STIX_RELATIONSHIP], args) as unknown as BasicConnection<T>;
};

const patchElementWithRefRelationships = async (
  context: AuthContext,
  user: AuthUser,
  stixObjectOrRelationshipId: string,
  type: string,
  relationship_type: string,
  targets: string[],
  operation: 'add' | 'remove',
  opts = {},
) => {
  const initial = await storeLoadByIdWithRefs(context, user, stixObjectOrRelationshipId, { type });
  if (!initial) {
    throw FunctionalError('Element can not be loaded', { stixObjectOrRelationshipId });
  }
  const fieldName = schemaRelationsRefDefinition.convertDatabaseNameToInputName(initial.entity_type, relationship_type);
  if (!fieldName) {
    throw UnsupportedError('This relationship type is not supported', { relationship_type });
  }
  const inputs = transformPatchToInput({ [fieldName]: targets }, { [fieldName]: operation });
  const { element: patchedFrom } = await updateAttributeFromLoadedWithRefs(context, user, initial, inputs, opts);
  return patchedFrom;
};

export const stixObjectOrRelationshipAddRefRelation = async (
  context: AuthContext,
  user: AuthUser,
  stixObjectOrRelationshipId: string,
  input: StixRefRelationshipAddInput,
  type: string,
  opts = {},
): Promise<any> => { // TODO remove any when all resolvers in ts
  // Validate specific relations, created by and markings
  if (input.relationship_type === RELATION_OBJECT_MARKING) {
    await validateMarking(context, user, input.toId);
  }
  if (input.relationship_type === RELATION_CREATED_BY) {
    await validateCreatedBy(context, user, input.toId);
  }
  // Add the relationship with patching
  const to = await findById(context, user, input.toId);
  const patchedFrom = await patchElementWithRefRelationships(context, user, stixObjectOrRelationshipId, type, input.relationship_type, [input.toId], UPDATE_OPERATION_ADD, opts);
  const { element: refRelation } = await buildRelationData(context, user, { from: patchedFrom, to, relationship_type: input.relationship_type });
  await notify(BUS_TOPICS[type as BusTopicsKeyType].EDIT_TOPIC, refRelation, user);
  return refRelation as any;
};
export const stixObjectOrRelationshipAddRefRelations = async (
  context: AuthContext,
  user: AuthUser,
  stixObjectOrRelationshipId: string,
  input: StixRefRelationshipsAddInput,
  type: string,
  opts = {},
) => {
  return patchElementWithRefRelationships(context, user, stixObjectOrRelationshipId, type, input.relationship_type, input.toIds, UPDATE_OPERATION_ADD, opts);
};

export const stixObjectOrRelationshipDeleteRefRelation = async (
  context: AuthContext,
  user: AuthUser,
  stixObjectOrRelationshipId: string,
  toId: string,
  relationshipType: string,
  type: string,
  opts = {},
): Promise<any> => { // TODO remove any when all resolvers in ts
  const stixObjectOrRelationship = await storeLoadById(context, user, stixObjectOrRelationshipId, type);
  if (!stixObjectOrRelationship) {
    throw FunctionalError('Cannot delete the relation, Stix-Object or Stix-Relationship cannot be found.', { id: stixObjectOrRelationshipId });
  }
  if (!isStixRefRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_REF_RELATIONSHIP} can be deleted through this method.`, { id: stixObjectOrRelationshipId });
  }
  return patchElementWithRefRelationships(context, user, stixObjectOrRelationshipId, type, relationshipType, [toId], UPDATE_OPERATION_REMOVE, opts);
};
