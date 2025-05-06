import { dissoc, propOr } from 'ramda';
import { storeLoadByIdWithRefs, updateAttribute, updateAttributeFromLoadedWithRefs } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ABSTRACT_STIX_REF_RELATIONSHIP, ABSTRACT_STIX_RELATIONSHIP } from '../schema/general';
import { FunctionalError } from '../config/errors';
import { isStixRefRelationship, META_RELATIONS, STIX_REF_RELATIONSHIP_TYPES } from '../schema/stixRefRelationship';
import { internalLoadById, listRelations, storeLoadById } from '../database/middleware-loader';
import { stixCoreRelationshipCleanContext, stixCoreRelationshipEditContext } from './stixCoreRelationship';
import { schemaTypesDefinition } from '../schema/schema-types';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { findById as findStixObjectOrStixRelationshipById } from './stixObjectOrStixRelationship';
import { elCount } from '../database/engine';
import { READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS, READ_INDEX_STIX_META_RELATIONSHIPS, UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE } from '../database/utils';

// Query

export const findAll = async (context, user, args) => {
  return listRelations(context, user, propOr(STIX_REF_RELATIONSHIP_TYPES, 'relationship_type', args), args);
};
export const findById = async (context, user, stixRefRelationshipId) => {
  // Not use ABSTRACT_STIX_REF_RELATIONSHIP to have compatibility on parent type with ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP type
  return storeLoadById(context, user, stixRefRelationshipId, ABSTRACT_STIX_RELATIONSHIP);
};
const notNestedRefRelation = META_RELATIONS.map((arr) => arr.databaseName);
export const findNested = async (context, user, args) => {
  const relationTypes = schemaTypesDefinition.get(ABSTRACT_STIX_REF_RELATIONSHIP).filter((type) => !notNestedRefRelation.includes(type));
  return listRelations(context, user, relationTypes, args);
};
export const schemaRefRelationships = async (context, user, id, toType) => {
  return findStixObjectOrStixRelationshipById(context, user, id)
    .then((entity) => {
      const from = schemaRelationsRefDefinition.getRelationsRef(entity.entity_type)
        .filter((ref) => !notNestedRefRelation.includes(ref.databaseName))
        .filter((ref) => (!ref.isRefExistingForTypes ? true : ref.isRefExistingForTypes(entity.entity_type, toType)))
        .map((ref) => ref.databaseName)
        .sort();
      const to = schemaRelationsRefDefinition.getRelationsRef(toType)
        .filter((ref) => !notNestedRefRelation.includes(ref.databaseName))
        .filter((ref) => (!ref.isRefExistingForTypes ? true : ref.isRefExistingForTypes(toType, entity.entity_type)))
        .map((ref) => ref.databaseName)
        .sort();
      return { entity, from, to };
    });
};
export const isDatable = (entityType, relationshipType) => {
  return schemaRelationsRefDefinition.isDatable(entityType, relationshipType);
};

// Mutation
// @Deprecated method.
// updateField must be directly used
export const addStixRefRelationship = async (context, user, stixRefRelationship) => {
  if (!isStixRefRelationship(stixRefRelationship.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_REF_RELATIONSHIP} can be added through this method, got ${stixRefRelationship.relationship_type}.`);
  }
  const fromPromise = storeLoadByIdWithRefs(context, user, stixRefRelationship.fromId);
  const toPromise = internalLoadById(context, user, stixRefRelationship.toId);
  const [from, to] = await Promise.all([fromPromise, toPromise]);
  if (!from || !to) {
    throw FunctionalError('MISSING_ELEMENTS', {
      from: stixRefRelationship.fromId,
      from_missing: !from,
      to: stixRefRelationship.toId,
      to_missing: !to
    });
  }
  const refInputName = schemaRelationsRefDefinition.convertDatabaseNameToInputName(from.entity_type, stixRefRelationship.relationship_type);
  const inputs = [{ key: refInputName, value: [stixRefRelationship.toId], operation: UPDATE_OPERATION_ADD }];
  await updateAttributeFromLoadedWithRefs(context, user, from, inputs);
  const opts = {
    first: 1,
    connectionFormat: false,
    fromId: from.internal_id,
    toId: to.internal_id,
    orderBy: 'created_at',
    orderMode: 'desc'
  };
  const lastCreatedRef = await listRelations(context, user, stixRefRelationship.relationship_type, opts);
  return notify(BUS_TOPICS[ABSTRACT_STIX_REF_RELATIONSHIP].ADDED_TOPIC, lastCreatedRef[0], user);
};
export const stixRefRelationshipEditField = async (context, user, stixRefRelationshipId, input) => {
  // Not use ABSTRACT_STIX_REF_RELATIONSHIP to have compatibility on parent type with ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP type
  const stixRefRelation = await storeLoadById(context, user, stixRefRelationshipId, ABSTRACT_STIX_RELATIONSHIP);
  if (!stixRefRelation) {
    throw FunctionalError('Cannot delete the relation, Stix-Ref-Relation cannot be found.');
  }
  const { element } = await updateAttribute(context, user, stixRefRelationshipId, ABSTRACT_STIX_RELATIONSHIP, input);
  return notify(BUS_TOPICS[ABSTRACT_STIX_REF_RELATIONSHIP].EDIT_TOPIC, element, user);
};
export const stixRefRelationshipDelete = async (context, user, stixRefRelationshipId) => {
  // Not use storeLoadById to have compatibility on parent type with ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP type
  const stixRefRelation = await storeLoadById(context, user, stixRefRelationshipId, ABSTRACT_STIX_RELATIONSHIP);
  if (!stixRefRelation) {
    throw FunctionalError('Cannot delete the relation, Stix-Ref-Relation cannot be found.');
  }
  const fromPromise = storeLoadByIdWithRefs(context, user, stixRefRelation.fromId);
  const toPromise = internalLoadById(context, user, stixRefRelation.toId);
  const [from, to] = await Promise.all([fromPromise, toPromise]);
  if (!from || !to) {
    throw FunctionalError('MISSING_ELEMENTS', {
      from: stixRefRelation.fromId,
      from_missing: !from,
      to: stixRefRelation.toId,
      to_missing: !to
    });
  }
  const refInputName = schemaRelationsRefDefinition.convertDatabaseNameToInputName(from.entity_type, stixRefRelation.relationship_type);
  const inputs = [{ key: refInputName, value: [stixRefRelation.toId], operation: UPDATE_OPERATION_REMOVE }];
  await updateAttributeFromLoadedWithRefs(context, user, from, inputs);

  await notify(BUS_TOPICS[ABSTRACT_STIX_REF_RELATIONSHIP].DELETE_TOPIC, stixRefRelation, user);
  return stixRefRelationshipId;
};

// Context

export const stixRefRelationshipCleanContext = async (context, user, stixRefRelationshipId) => {
  return stixCoreRelationshipCleanContext(context, user, stixRefRelationshipId);
};
export const stixRefRelationshipEditContext = async (context, user, stixRefRelationshipId, input) => {
  return stixCoreRelationshipEditContext(context, user, stixRefRelationshipId, input);
};

// Count

export const stixRefRelationshipsNumber = (context, user, args) => {
  const types = args.types ?? [];
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_REF_RELATIONSHIP);
  }
  const countArgs = { ...args, types };
  const indices = [READ_INDEX_STIX_META_RELATIONSHIPS, READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS];
  return {
    count: elCount(context, user, indices, countArgs),
    total: elCount(context, user, indices, dissoc('endDate', countArgs)),
  };
};
