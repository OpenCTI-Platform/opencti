import * as R from 'ramda';
import { GraphQLError } from 'graphql/index';
import { ApolloServerErrorCode } from '@apollo/server/errors';
import { deleteElementById, distributionRelations, timeSeriesRelations } from '../database/middleware';
import { ABSTRACT_STIX_OBJECT, ABSTRACT_STIX_RELATIONSHIP } from '../schema/general';
import { buildRelationsFilter, listEntities, listRelationsPaginated, storeLoadById } from '../database/middleware-loader';
import { fillTimeSeries, isEmptyField, READ_INDEX_INFERRED_RELATIONSHIPS, READ_RELATIONSHIPS_INDICES } from '../database/utils';
import { elCount, MAX_RUNTIME_RESOLUTION_SIZE } from '../database/engine';
import { STIX_SPEC_VERSION, stixCoreRelationshipsMapping } from '../database/stix';
import { UnsupportedError } from '../config/errors';
import { schemaTypesDefinition } from '../schema/schema-types';
import { isFilterGroupNotEmpty } from '../utils/filtering/filtering-utils';
import { isStixRelationship } from '../schema/stixRelationship';

export const buildArgsFromDynamicFilters = async (context, user, args) => {
  const { dynamicFrom, dynamicTo } = args;
  const listEntitiesWithFilters = async (filters) => listEntities(context, user, [ABSTRACT_STIX_OBJECT], {
    connectionFormat: false,
    first: MAX_RUNTIME_RESOLUTION_SIZE,
    bypassSizeLimit: true, // ensure that max runtime prevent on ES_MAX_PAGINATION
    baseData: true,
    filters
  });
  let finalArgs = args;
  if (isFilterGroupNotEmpty(dynamicFrom)) {
    const fromIds = await listEntitiesWithFilters(dynamicFrom).then((result) => result.map((n) => n.id));
    if (fromIds.length > 0) {
      finalArgs = { ...finalArgs, fromId: args.fromId ? [...fromIds, args.fromId] : fromIds, dynamicFrom: undefined };
    } else {
      return { dynamicArgs: null, isEmptyDynamic: true };
    }
  } else {
    finalArgs = { ...finalArgs, dynamicFrom: undefined };
  }
  if (isFilterGroupNotEmpty(dynamicTo)) {
    const toIds = await listEntitiesWithFilters(dynamicTo).then((result) => result.map((n) => n.id));
    if (toIds.length > 0) {
      finalArgs = { ...finalArgs, toId: args.toId ? [...toIds, args.toId] : toIds, dynamicTo: undefined };
    } else {
      return { dynamicArgs: null, isEmptyDynamic: true };
    }
  } else {
    finalArgs = { ...finalArgs, dynamicTo: undefined };
  }
  return { dynamicArgs: finalArgs, isEmptyDynamic: false };
};

export const findAll = async (context, user, args) => {
  const { dynamicArgs, isEmptyDynamic } = await buildArgsFromDynamicFilters(context, user, args);
  if (isEmptyDynamic) {
    return { edges: [] };
  }
  const type = isEmptyField(dynamicArgs.relationship_type) ? ABSTRACT_STIX_RELATIONSHIP : dynamicArgs.relationship_type;
  return listRelationsPaginated(context, user, type, R.dissoc('relationship_type', dynamicArgs));
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
    throw new GraphQLError('Invalid argument: relationship_type is not a stix-relationship', { extensions: { code: ApolloServerErrorCode.BAD_USER_INPUT } });
  }
  return relationshipTypes;
};

// region stats
export const stixRelationshipsDistribution = async (context, user, args) => {
  const relationship_type = buildRelationshipTypes(args.relationship_type);
  const { dynamicArgs, isEmptyDynamic } = await buildArgsFromDynamicFilters(context, user, { ...args, relationship_type });
  if (isEmptyDynamic) {
    return [];
  }
  return distributionRelations(context, context.user, dynamicArgs);
};
export const stixRelationshipsNumber = async (context, user, args) => {
  const relationship_type = buildRelationshipTypes(args.relationship_type);
  const { dynamicArgs, isEmptyDynamic } = await buildArgsFromDynamicFilters(context, user, args);
  if (isEmptyDynamic) {
    return { count: 0, total: 0 };
  }
  const numberArgs = buildRelationsFilter(relationship_type, dynamicArgs);
  const indices = args.onlyInferred ? [READ_INDEX_INFERRED_RELATIONSHIPS] : [READ_RELATIONSHIPS_INDICES];
  return {
    count: elCount(context, user, indices, numberArgs),
    total: elCount(context, user, indices, R.dissoc('endDate', numberArgs)),
  };
};
export const stixRelationshipsMultiTimeSeries = async (context, user, args) => {
  return Promise.all(args.timeSeriesParameters.map(async (timeSeriesParameter) => {
    const { startDate, endDate, interval } = args;
    const { dynamicArgs, isEmptyDynamic } = await buildArgsFromDynamicFilters(context, user, timeSeriesParameter);
    if (isEmptyDynamic) {
      return { data: fillTimeSeries(startDate, endDate, interval, []) };
    }
    return { data: timeSeriesRelations(context, user, { ...args, ...dynamicArgs }) };
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
