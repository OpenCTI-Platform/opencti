import * as R from 'ramda';
import { GraphQLError } from 'graphql/index';
import { ApolloServerErrorCode } from '@apollo/server/errors';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { createRelation, deleteElementById, deleteRelationsByFromAndTo, timeSeriesRelations, updateAttribute } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { FunctionalError } from '../config/errors';
import { elCount } from '../database/engine';
import { isEmptyField, isNotEmptyField, READ_INDEX_INFERRED_RELATIONSHIPS, READ_INDEX_STIX_CORE_RELATIONSHIPS } from '../database/utils';
import { isStixCoreRelationship, stixCoreRelationshipOptions } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, buildRefRelationKey } from '../schema/general';
import { RELATION_CREATED_BY, } from '../schema/stixRefRelationship';
import { buildRelationsFilter, pageRelationsConnection, storeLoadById } from '../database/middleware-loader';
import { askListExport, exportTransformFilters } from './stix';
import { workToExportFile } from './work';
import { stixObjectOrRelationshipAddRefRelation, stixObjectOrRelationshipAddRefRelations, stixObjectOrRelationshipDeleteRefRelation } from './stixObjectOrStixRelationship';
import { addDynamicFromAndToToFilters, addFilter } from '../utils/filtering/filtering-utils';
import { stixRelationshipsDistribution } from './stixRelationship';
import { elRemoveElementFromDraft } from '../database/draft-engine';

export const findStixCoreRelationshipsPaginated = async (context, user, args) => {
  const filters = addDynamicFromAndToToFilters(args);
  const fullArgs = { ...args, filters };
  let relationshipTypesInput = fullArgs.relationship_type;
  if (!Array.isArray(relationshipTypesInput)) {
    relationshipTypesInput = relationshipTypesInput ? [relationshipTypesInput] : [];
  }
  const relationshipTypes = buildStixCoreRelationshipTypes(relationshipTypesInput);
  return pageRelationsConnection(context, user, relationshipTypes, R.dissoc('relationship_type', fullArgs));
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
    const options = { types: relationshipTypes, extensions: { code: ApolloServerErrorCode.BAD_USER_INPUT } };
    throw new GraphQLError('Invalid argument: relationship_type is not a stix-core-relationship', options);
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
  const filtersWithDynamic = addDynamicFromAndToToFilters(args);
  const fullArgs = { ...args, filters: filtersWithDynamic };
  const { authorId } = fullArgs;
  const relationship_type = buildStixCoreRelationshipTypes(fullArgs.relationship_type);
  let finalArgs = fullArgs;
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
  const relationship_type = buildStixCoreRelationshipTypes(args.relationship_type);
  return Promise.all(args.timeSeriesParameters.map(async (timeSeriesParameter) => {
    const filters = addDynamicFromAndToToFilters(timeSeriesParameter);
    const fullArgs = { ...timeSeriesParameter, filters };
    return { data: timeSeriesRelations(context, user, { ...args, relationship_type, ...fullArgs }) };
  }));
};
// endregion

// region export
export const stixCoreRelationshipsExportAsk = async (context, user, args) => {
  const { exportContext, format, exportType, contentMaxMarkings, selectedIds, fileMarkings } = args;
  const { fromOrToId, elementWithTargetTypes, fromId, fromRole, fromTypes, toId, toRole, toTypes, relationship_type } = args;
  const { search, orderBy, orderMode, filters } = args;
  const argsFilters = { search, orderBy, orderMode, filters };
  const ordersOpts = stixCoreRelationshipOptions.StixCoreRelationshipsOrdering;
  const initialParams = { fromOrToId, elementWithTargetTypes, fromId, fromRole, fromTypes, toId, toRole, toTypes, relationship_type };
  const transformFilters = await exportTransformFilters(context, user, argsFilters, ordersOpts, user.id);
  const listParams = { ...initialParams, ...transformFilters };
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
  const stixCoreRelationship = await findById(context, user, stixCoreRelationshipId);
  await deleteElementById(context, user, stixCoreRelationshipId, stixCoreRelationship.relationship_type);
  return stixCoreRelationshipId;
};

export const stixCoreRelationshipDeleteByFromAndTo = async (context, user, fromId, toId, relationshipType) => {
  if (!isStixCoreRelationship(relationshipType)) {
    throw FunctionalError('Only stix-core-relationship can be deleted through this method, not ${relationshipType}.');
  }
  await deleteRelationsByFromAndTo(context, user, fromId, toId, relationshipType, ABSTRACT_STIX_CORE_RELATIONSHIP);
  return true;
};

export const stixCoreRelationshipEditField = async (context, user, stixCoreRelationshipId, input, opts = {}) => {
  const stixCoreRelationship = await storeLoadById(context, user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP);
  if (!stixCoreRelationship) {
    throw FunctionalError('Cannot edit the field, stix-core-relationship cannot be found.', { id: stixCoreRelationshipId });
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
export const stixCoreRelationshipCleanContext = async (context, user, stixCoreRelationshipId) => {
  await delEditContext(user, stixCoreRelationshipId);
  const stixCoreRelationship = await storeLoadById(context, user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP);
  return await notify(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].EDIT_TOPIC, stixCoreRelationship, user);
};

export const stixCoreRelationshipEditContext = async (context, user, stixCoreRelationshipId, input) => {
  await setEditContext(user, stixCoreRelationshipId, input);
  const stixCoreRelationship = await storeLoadById(context, user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP);
  return await notify(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].EDIT_TOPIC, stixCoreRelationship, user);
};
// endregion

export const stixCoreRelationshipRemoveFromDraft = async (context, user, stixCoreObjectId) => {
  const stixCoreRelationship = await storeLoadById(context, user, stixCoreObjectId, ABSTRACT_STIX_CORE_RELATIONSHIP, { includeDeletedInDraft: true });
  if (!stixCoreRelationship) {
    throw FunctionalError('Cannot remove the object from draft, Stix-Core-Relationship cannot be found.', { id: stixCoreObjectId });
  }
  // TODO currently not locked, but might need to be
  await elRemoveElementFromDraft(context, user, stixCoreRelationship);
  return stixCoreRelationship.id;
};
