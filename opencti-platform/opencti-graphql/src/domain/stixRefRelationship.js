import { dissoc, uniq } from 'ramda';
import { createRelation, deleteElementById, storeLoadByIdWithRefs, updateAttribute } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import {
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ABSTRACT_STIX_REF_RELATIONSHIP,
  ABSTRACT_STIX_RELATIONSHIP
} from '../schema/general';
import { FunctionalError } from '../config/errors';
import { isStixRefRelationship, META_RELATIONS, STIX_REF_RELATIONSHIP_TYPES } from '../schema/stixRefRelationship';
import { internalLoadById, pageRelationsConnection, storeLoadById } from '../database/middleware-loader';
import { stixCoreRelationshipCleanContext, stixCoreRelationshipEditContext } from './stixCoreRelationship';
import { schemaTypesDefinition } from '../schema/schema-types';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { findById as findStixObjectOrStixRelationshipById } from './stixObjectOrStixRelationship';
import { elCount } from '../database/engine';
import { READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS, READ_INDEX_STIX_META_RELATIONSHIPS } from '../database/utils';
import { findSubTypePaginated as findSubTypes } from './subType';

// Query

export const findRefRelationshipsPaginated = async (context, user, args) => {
  return pageRelationsConnection(context, user, args.relationship_type ?? STIX_REF_RELATIONSHIP_TYPES, args);
};
export const findById = async (context, user, stixRefRelationshipId) => {
  // Not use ABSTRACT_STIX_REF_RELATIONSHIP to have compatibility on parent type with ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP type
  return storeLoadById(context, user, stixRefRelationshipId, ABSTRACT_STIX_RELATIONSHIP);
};
const notNestedRefRelation = META_RELATIONS.map((arr) => arr.databaseName);
export const findNestedPaginated = async (context, user, args) => {
  const relationTypes = schemaTypesDefinition.get(ABSTRACT_STIX_REF_RELATIONSHIP).filter((type) => !notNestedRefRelation.includes(type));
  return pageRelationsConnection(context, user, relationTypes, args);
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

// return the possible types with which an entity type can have a nested relation ref
export const schemaRefRelationshipsPossibleTypes = async (context, user, entityType) => {
  const registeredTypes = schemaRelationsRefDefinition.getRegisteredTypes();
  const possibleToTypes = uniq(schemaRelationsRefDefinition.getRelationsRef(entityType)
    .filter((ref) => !notNestedRefRelation.includes(ref.databaseName))
    .flatMap((ref) => ref.toTypes));
  const possibleFromTypes = registeredTypes.filter((type) => {
    const reversedRelationRefs = schemaRelationsRefDefinition.getRelationsRef(type)
      .filter((ref) => !notNestedRefRelation.includes(ref.databaseName))
      .filter((ref) => (!ref.isRefExistingForTypes ? true : ref.isRefExistingForTypes(type, entityType)));
    return reversedRelationRefs.length > 0;
  });
  const possibleTypes = [...possibleFromTypes, ...possibleToTypes];
  // clean target types if it includes abstract types
  const scos = await findSubTypes(context, user, { type: ABSTRACT_STIX_CYBER_OBSERVABLE });
  const sdos = await findSubTypes(context, user, { type: ABSTRACT_STIX_DOMAIN_OBJECT });
  let cleanedPossibleTypes = possibleTypes;
  if (cleanedPossibleTypes.includes(ABSTRACT_STIX_CORE_OBJECT)) {
    cleanedPossibleTypes = [ABSTRACT_STIX_CORE_OBJECT];
  } else {
    if (cleanedPossibleTypes.includes(ABSTRACT_STIX_CYBER_OBSERVABLE)) {
      cleanedPossibleTypes = cleanedPossibleTypes.filter((t) => !scos.edges.map((n) => n.node.id).includes(t));
    }
    if (cleanedPossibleTypes.includes(ABSTRACT_STIX_DOMAIN_OBJECT)) {
      cleanedPossibleTypes = cleanedPossibleTypes.filter((t) => !sdos.edges.map((n) => n.node.id).includes(t));
    }
  }
  return cleanedPossibleTypes;
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
  return createRelation(context, user, stixRefRelationship);
};
export const stixRefRelationshipEditField = async (context, user, stixRefRelationshipId, input) => {
  // Not use ABSTRACT_STIX_REF_RELATIONSHIP to have compatibility on parent type with ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP type
  const stixRefRelation = await storeLoadById(context, user, stixRefRelationshipId, ABSTRACT_STIX_RELATIONSHIP);
  if (!stixRefRelation) {
    throw FunctionalError('Cannot delete the relation, Stix-Ref-Relation cannot be found.', { id: stixRefRelationshipId });
  }
  const { element } = await updateAttribute(context, user, stixRefRelationshipId, ABSTRACT_STIX_RELATIONSHIP, input);
  return notify(BUS_TOPICS[ABSTRACT_STIX_REF_RELATIONSHIP].EDIT_TOPIC, element, user);
};
export const stixRefRelationshipDelete = async (context, user, stixRefRelationshipId) => {
  const stixRefRelationship = await findById(context, user, stixRefRelationshipId);
  await deleteElementById(context, user, stixRefRelationshipId, stixRefRelationship.relationship_type);
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
