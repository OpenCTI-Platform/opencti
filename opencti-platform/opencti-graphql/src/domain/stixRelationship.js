import * as R from 'ramda';
import { GraphQLError } from 'graphql/index';
import { ApolloServerErrorCode } from '@apollo/server/errors';
import { deleteElementById, distributionRelations, timeSeriesRelations } from '../database/middleware';
import { ABSTRACT_STIX_RELATIONSHIP } from '../schema/general';
import { buildRelationsFilter, pageRelationsConnection, storeLoadById } from '../database/middleware-loader';
import { isEmptyField, READ_INDEX_INFERRED_RELATIONSHIPS, READ_RELATIONSHIPS_INDICES } from '../database/utils';
import { elCount } from '../database/engine';
import { STIX_SPEC_VERSION, stixCoreRelationshipsMapping } from '../database/stix';
import { UnsupportedError } from '../config/errors';
import { schemaTypesDefinition } from '../schema/schema-types';
import { isStixRelationship } from '../schema/stixRelationship';
import { addDynamicFromAndToToFilters } from '../utils/filtering/filtering-utils';

export const findStixRelationPaginated = async (context, user, args) => {
  const filters = addDynamicFromAndToToFilters(args);
  const fullArgs = { ...args, filters };
  let relationshipTypesInput = fullArgs.relationship_type;
  if (!Array.isArray(relationshipTypesInput)) {
    relationshipTypesInput = relationshipTypesInput ? [relationshipTypesInput] : [];
  }
  const relationshipTypes = buildRelationshipTypes(relationshipTypesInput);
  return pageRelationsConnection(context, user, relationshipTypes, R.dissoc('relationship_type', fullArgs));
};

export const findById = (context, user, stixRelationshipId) => {
  return storeLoadById(context, user, stixRelationshipId, ABSTRACT_STIX_RELATIONSHIP);
};

export const stixRelationshipDelete = async (context, user, stixRelationshipId) => {
  await deleteElementById(context, user, stixRelationshipId, ABSTRACT_STIX_RELATIONSHIP);
  return stixRelationshipId;
};

const buildRelationshipTypes = (relationshipTypes) => {
  if (isEmptyField(relationshipTypes)) {
    return [ABSTRACT_STIX_RELATIONSHIP];
  }

  const isValidRelationshipTypes = relationshipTypes.every((type) => isStixRelationship(type));

  if (!isValidRelationshipTypes) {
    const options = { types: relationshipTypes, extensions: { code: ApolloServerErrorCode.BAD_USER_INPUT } };
    throw new GraphQLError('Invalid argument: relationship_type is not a stix-relationship', options);
  }
  return relationshipTypes;
};

// region stats
export const stixRelationshipsDistribution = async (context, user, args) => {
  const relationship_type = buildRelationshipTypes(args.relationship_type);
  const filters = addDynamicFromAndToToFilters(args);
  const fullArgs = { ...args, relationship_type, filters };
  return distributionRelations(context, context.user, fullArgs);
};
export const stixRelationshipsNumber = async (context, user, args) => {
  const relationship_type = buildRelationshipTypes(args.relationship_type);
  const filters = addDynamicFromAndToToFilters(args);
  const fullArgs = { ...args, relationship_type, filters };
  const numberArgs = buildRelationsFilter(relationship_type, fullArgs);
  const indices = args.onlyInferred ? [READ_INDEX_INFERRED_RELATIONSHIPS] : [READ_RELATIONSHIPS_INDICES];
  return {
    count: elCount(context, user, indices, numberArgs),
    total: elCount(context, user, indices, R.dissoc('endDate', numberArgs)),
  };
};
export const stixRelationshipsTimeSeries = async (context, user, args) => {
  const relationship_type = buildRelationshipTypes(args.relationship_type);
  const finalArgs = { ...args, relationship_type };
  return timeSeriesRelations(context, context.user, finalArgs);
};
export const stixRelationshipsMultiTimeSeries = async (context, user, args) => {
  const relationship_type = buildRelationshipTypes(args.relationship_type);
  if (!args.timeSeriesParameters) {
    return [];
  }
  return Promise.all(args.timeSeriesParameters.map(async (timeSeriesParameter) => {
    const filters = addDynamicFromAndToToFilters(timeSeriesParameter);
    const fullArgs = { ...timeSeriesParameter, filters };
    return { data: timeSeriesRelations(context, user, { ...args, relationship_type, ...fullArgs }) };
  }));
};
// endregion

export const getSpecVersionOrDefault = ({ spec_version }) => spec_version ?? STIX_SPEC_VERSION;

export const schemaTypesMapping = (mapping) => {
  const entries = Object.entries(mapping);
  const flatEntries = [];
  entries.forEach(([key, values]) => {
    const [fromType, toType] = key.split('_');
    const generatedEntries = flattenEntries(fromType, toType, values);
    flatEntries.push(...generatedEntries);
  });

  return mergeEntries(flatEntries.map(([key, values]) => {
    return {
      key,
      values: values.map((def) => def.name)
    };
  }));
};
export const schemaRelationsTypesMapping = () => {
  return schemaTypesMapping(stixCoreRelationshipsMapping);
};

const isParentType = (key) => {
  return schemaTypesDefinition.hasChildren(key);
};

const getChildren = (type) => {
  if (!isParentType(type)) {
    throw UnsupportedError(`${type} is not supported`);
  }

  return schemaTypesDefinition.get(type);
};

const flattenEntries = (fromType, toType, values) => {
  if (!isParentType(fromType) && !isParentType(toType)) {
    return [[`${fromType}_${toType}`, values]];
  }

  const entries = [];

  if (isParentType(fromType) && !isParentType(toType)) {
    const children = getChildren(fromType);
    children.forEach((child) => {
      const newEntry = flattenEntries(child, toType, values).flat();
      entries.push(newEntry);
    });
  }

  if (!isParentType(fromType) && isParentType(toType)) {
    const children = getChildren(toType);
    children.forEach((child) => {
      const newEntry = flattenEntries(fromType, child, values).flat();
      entries.push(newEntry);
    });
  }

  if (isParentType(fromType) && isParentType(toType)) {
    const toTypeChildren = getChildren(toType);
    const fromTypeChildren = getChildren(fromType);

    fromTypeChildren.forEach((fromChild) => {
      toTypeChildren.forEach((toChild) => {
        const newEntry = flattenEntries(fromChild, toChild, values).flat();
        entries.push(newEntry);
      });
    });
  }

  return entries;
};

const mergeEntries = (entries) => entries.reduce((result, currentItem) => {
  const existingItem = result.find((item) => item.key === currentItem.key);
  if (existingItem) {
    currentItem.values.forEach((value) => {
      if (!existingItem.values.includes(value)) {
        existingItem.values.push(value);
      }
    });
  } else {
    result.push({ ...currentItem });
  }
  return result;
}, []);
