import * as R from 'ramda';
import { GraphQLError } from 'graphql/index';
import { ApolloServerErrorCode } from '@apollo/server/errors';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { createRelation, deleteElementById, deleteRelationsByFromAndTo, timeSeriesRelations, updateAttribute } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { FunctionalError } from '../config/errors';
import { elCount } from '../database/engine';
import { fillTimeSeries, isEmptyField, isNotEmptyField, READ_INDEX_INFERRED_RELATIONSHIPS, READ_INDEX_STIX_CORE_RELATIONSHIPS } from '../database/utils';
import { isStixCoreRelationship, stixCoreRelationshipOptions } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, buildRefRelationKey } from '../schema/general';
import { RELATION_CREATED_BY, } from '../schema/stixRefRelationship';
import { buildRelationsFilter, listRelations, storeLoadById } from '../database/middleware-loader';
import { askListExport, exportTransformFilters } from './stix';
import { workToExportFile } from './work';
import { stixObjectOrRelationshipAddRefRelation, stixObjectOrRelationshipAddRefRelations, stixObjectOrRelationshipDeleteRefRelation } from './stixObjectOrStixRelationship';
import { addFilter } from '../utils/filtering/filtering-utils';
import { buildArgsFromDynamicFilters, stixRelationshipsDistribution } from './stixRelationship';

export const findAll = async (context, user, args) => {
  return listRelations(context, user, R.propOr(ABSTRACT_STIX_CORE_RELATIONSHIP, 'relationship_type', args), args);
};

export const findById = (context, user, stixCoreRelationshipId) => {
  return storeLoadById(context, user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP);
};

const buildStixCoreRelationshipTypes = (relationshipTypes) => {
  if (isEmptyField(relationshipTypes)) {
    return [ABSTRACT_STIX_CORE_RELATIONSHIP];
  }
  const isValidRelationshipTypes = relationshipTypes.every((type) => isStixCoreRelationship(type));
  if (!isValidRelationshipTypes) {
    throw new GraphQLError('Invalid argument: relationship_type is not a stix-core-relationship', { extensions: { code: ApolloServerErrorCode.BAD_USER_INPUT } });
  }
  return relationshipTypes;
};

// region stats
// TODO future refacto : use the more generic functions of domain/stixRelationship.js
export const stixCoreRelationshipsDistribution = async (context, user, args) => {
  const relationship_type = buildStixCoreRelationshipTypes(args.relationship_type);
  return stixRelationshipsDistribution(context, user, { ...args, relationship_type });
};
export const stixCoreRelationshipsNumber = async (context, user, args) => {
  const { authorId } = args;
  const relationship_type = buildStixCoreRelationshipTypes(args.relationship_type);
  const { dynamicArgs, isEmptyDynamic } = await buildArgsFromDynamicFilters(context, user, { ...args, relationship_type });
  if (isEmptyDynamic) {
    return { count: 0, total: 0 };
  }
  let finalArgs = dynamicArgs;
  if (isNotEmptyField(authorId)) {
    const filters = addFilter(args.filters, buildRefRelationKey(RELATION_CREATED_BY, '*'), authorId);
    finalArgs = { ...finalArgs, filters };
  }
  const numberArgs = buildRelationsFilter(relationship_type, finalArgs);
  const indices = args.onlyInferred ? [READ_INDEX_INFERRED_RELATIONSHIPS] : [READ_INDEX_STIX_CORE_RELATIONSHIPS, READ_INDEX_INFERRED_RELATIONSHIPS];
  return {
    count: elCount(context, user, indices, numberArgs),
    total: elCount(context, user, indices, R.dissoc('endDate', numberArgs)),
  };
};
export const stixCoreRelationshipsMultiTimeSeries = async (context, user, args) => {
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

export const stixRelations = (context, user, stixCoreObjectId, args) => {
  const finalArgs = R.assoc('fromId', stixCoreObjectId, args);
  return findAll(context, user, finalArgs);
};

// region export
export const stixCoreRelationshipsExportAsk = async (context, user, args) => {
  const { exportContext, format, exportType, contentMaxMarkings, selectedIds, fileMarkings } = args;
  const { fromOrToId, elementWithTargetTypes, fromId, fromRole, fromTypes, toId, toRole, toTypes, relationship_type } = args;
  const { search, orderBy, orderMode, filters } = args;
  const argsFilters = { search, orderBy, orderMode, filters };
  const ordersOpts = stixCoreRelationshipOptions.StixCoreRelationshipsOrdering;
  const initialParams = { fromOrToId, elementWithTargetTypes, fromId, fromRole, fromTypes, toId, toRole, toTypes, relationship_type };
  const listParams = { ...initialParams, ...await exportTransformFilters(context, user, argsFilters, ordersOpts) };
  const works = await askListExport(context, user, exportContext, format, selectedIds, listParams, exportType, contentMaxMarkings, fileMarkings);
  return works.map((w) => workToExportFile(w));
};
// endregion

// region mutations
export const addStixCoreRelationship = async (context, user, stixCoreRelationship) => {
  if (!isStixCoreRelationship(stixCoreRelationship.relationship_type)) {
    throw FunctionalError('Only stix-core-relationship can be created through this method.');
  }
  const created = await createRelation(context, user, stixCoreRelationship);
  return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].ADDED_TOPIC, created, user);
};

export const stixCoreRelationshipDelete = async (context, user, stixCoreRelationshipId) => {
  await deleteElementById(context, user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP);
  return stixCoreRelationshipId;
};

export const stixCoreRelationshipDeleteByFromAndTo = async (context, user, fromId, toId, relationshipType) => {
  if (!isStixCoreRelationship(relationshipType)) {
    throw FunctionalError('Only stix-core-relationship can be deleted through this method.');
  }
  await deleteRelationsByFromAndTo(context, user, fromId, toId, relationshipType, ABSTRACT_STIX_CORE_RELATIONSHIP);
  return true;
};

export const stixCoreRelationshipEditField = async (context, user, stixCoreRelationshipId, input, opts = {}) => {
  const stixCoreRelationship = await storeLoadById(context, user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP);
  if (!stixCoreRelationship) {
    throw FunctionalError('Cannot edit the field, stix-core-relationship cannot be found.');
  }
  const { element } = await updateAttribute(context, user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP, input, opts);
  return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].EDIT_TOPIC, element, user);
};

// region relation ref
export const stixCoreRelationshipAddRelation = async (context, user, stixCoreRelationshipId, input) => {
  return stixObjectOrRelationshipAddRefRelation(context, user, stixCoreRelationshipId, input, ABSTRACT_STIX_CORE_RELATIONSHIP);
};
export const stixCoreRelationshipAddRelations = async (context, user, stixCoreRelationshipId, input, opts = {}) => {
  return stixObjectOrRelationshipAddRefRelations(context, user, stixCoreRelationshipId, input, ABSTRACT_STIX_CORE_RELATIONSHIP, opts);
};
export const stixCoreRelationshipDeleteRelation = async (context, user, stixCoreRelationshipId, toId, relationshipType, opts = {}) => {
  return stixObjectOrRelationshipDeleteRefRelation(context, user, stixCoreRelationshipId, toId, relationshipType, ABSTRACT_STIX_CORE_RELATIONSHIP, opts);
};
// endregion

// region context
export const stixCoreRelationshipCleanContext = (context, user, stixCoreRelationshipId) => {
  delEditContext(user, stixCoreRelationshipId);
  return storeLoadById(context, user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP).then((stixCoreRelationship) => {
    return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].EDIT_TOPIC, stixCoreRelationship, user);
  });
};

export const stixCoreRelationshipEditContext = (context, user, stixCoreRelationshipId, input) => {
  setEditContext(user, stixCoreRelationshipId, input);
  return storeLoadById(context, user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP).then((stixCoreRelationship) => {
    return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].EDIT_TOPIC, stixCoreRelationship, user);
  });
};
// endregion
