import * as R from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  batchListThroughGetFrom,
  batchListThroughGetTo,
  createRelation,
  deleteElementById,
  deleteRelationsByFromAndTo,
  distributionRelations,
  timeSeriesRelations,
  updateAttribute,
} from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { FunctionalError } from '../config/errors';
import { elCount } from '../database/engine';
import { fillTimeSeries, isNotEmptyField, READ_INDEX_INFERRED_RELATIONSHIPS, READ_INDEX_STIX_CORE_RELATIONSHIPS } from '../database/utils';
import { isStixCoreRelationship, stixCoreRelationshipOptions } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, buildRefRelationKey, ENTITY_TYPE_CONTAINER, ENTITY_TYPE_IDENTITY } from '../schema/general';
import {
  RELATION_CREATED_BY,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
} from '../schema/stixRefRelationship';
import { ENTITY_TYPE_CONTAINER_NOTE, ENTITY_TYPE_CONTAINER_OPINION, ENTITY_TYPE_CONTAINER_REPORT } from '../schema/stixDomainObject';
import { ENTITY_TYPE_EXTERNAL_REFERENCE, ENTITY_TYPE_KILL_CHAIN_PHASE, ENTITY_TYPE_LABEL, ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { buildRelationsFilter, listRelations, storeLoadById } from '../database/middleware-loader';
import { askListExport, exportTransformFilters } from './stix';
import { workToExportFile } from './work';
import { ENTITY_TYPE_CONTAINER_CASE } from '../modules/case/case-types';
import { stixObjectOrRelationshipAddRefRelation, stixObjectOrRelationshipAddRefRelations, stixObjectOrRelationshipDeleteRefRelation } from './stixObjectOrStixRelationship';
import { addFilter } from '../utils/filtering/filtering-utils';
import { buildArgsFromDynamicFilters } from './stixRelationship';

export const findAll = async (context, user, args) => {
  return listRelations(context, user, R.propOr(ABSTRACT_STIX_CORE_RELATIONSHIP, 'relationship_type', args), args);
};

export const findById = (context, user, stixCoreRelationshipId) => {
  return storeLoadById(context, user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP);
};

// region stats
// TODO future refacto : use the more generic functions of domain/stixRelationship.js
export const stixCoreRelationshipsDistribution = async (context, user, args) => {
  // it's not possible to have a dynamicFrom and dynamicTo in args here for the moment
  // consider adding these fields in opencti.graphql if you want to use them
  const { dynamicArgs, isEmptyDynamic } = await buildArgsFromDynamicFilters(context, user, args);
  if (isEmptyDynamic) {
    return [];
  }
  return distributionRelations(context, context.user, dynamicArgs);
};
export const stixCoreRelationshipsNumber = async (context, user, args) => {
  const { relationship_type = [ABSTRACT_STIX_CORE_RELATIONSHIP], authorId } = args;
  const { dynamicArgs, isEmptyDynamic } = await buildArgsFromDynamicFilters(context, user, args);
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

export const batchCreatedBy = async (context, user, stixCoreRelationshipIds) => {
  const batchCreators = await batchListThroughGetTo(
    context,
    user,
    stixCoreRelationshipIds,
    RELATION_CREATED_BY,
    ENTITY_TYPE_IDENTITY
  );
  return batchCreators.map((b) => (b.edges.length > 0 ? R.head(b.edges).node : null));
};

export const batchContainers = async (context, user, stixCoreRelationshipIds) => {
  return batchListThroughGetFrom(context, user, stixCoreRelationshipIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER);
};

export const batchReports = async (context, user, stixCoreRelationshipIds) => {
  return batchListThroughGetFrom(context, user, stixCoreRelationshipIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_REPORT);
};

export const batchCases = async (context, user, stixCoreRelationshipIds) => {
  return batchListThroughGetFrom(context, user, stixCoreRelationshipIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_CASE);
};

export const batchNotes = (context, user, stixCoreRelationshipIds) => {
  return batchListThroughGetFrom(context, user, stixCoreRelationshipIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_NOTE);
};

export const batchOpinions = (context, user, stixCoreRelationshipIds) => {
  return batchListThroughGetFrom(context, user, stixCoreRelationshipIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_OPINION);
};

export const batchLabels = (context, user, stixCoreRelationshipIds) => {
  return batchListThroughGetTo(context, user, stixCoreRelationshipIds, RELATION_OBJECT_LABEL, ENTITY_TYPE_LABEL);
};

export const batchMarkingDefinitions = (context, user, stixCoreRelationshipIds) => {
  return batchListThroughGetTo(context, user, stixCoreRelationshipIds, RELATION_OBJECT_MARKING, ENTITY_TYPE_MARKING_DEFINITION);
};

export const batchExternalReferences = (context, user, stixCoreRelationshipIds) => {
  return batchListThroughGetTo(
    context,
    user,
    stixCoreRelationshipIds,
    RELATION_EXTERNAL_REFERENCE,
    ENTITY_TYPE_EXTERNAL_REFERENCE
  );
};

export const batchKillChainPhases = (context, user, stixCoreRelationshipIds) => {
  return batchListThroughGetTo(context, user, stixCoreRelationshipIds, RELATION_KILL_CHAIN_PHASE, ENTITY_TYPE_KILL_CHAIN_PHASE);
};

export const stixRelations = (context, user, stixCoreObjectId, args) => {
  const finalArgs = R.assoc('fromId', stixCoreObjectId, args);
  return findAll(context, user, finalArgs);
};

// region export
export const stixCoreRelationshipsExportAsk = async (context, user, args) => {
  const { exportContext, format, exportType, maxMarkingDefinition, selectedIds } = args;
  const { fromOrToId, elementWithTargetTypes, fromId, fromRole, fromTypes, toId, toRole, toTypes, relationship_type } = args;
  const { search, orderBy, orderMode, filters } = args;
  const argsFilters = { search, orderBy, orderMode, filters };
  const ordersOpts = stixCoreRelationshipOptions.StixCoreRelationshipsOrdering;
  const initialParams = { fromOrToId, elementWithTargetTypes, fromId, fromRole, fromTypes, toId, toRole, toTypes, relationship_type };
  const listParams = { ...initialParams, ...exportTransformFilters(argsFilters, ordersOpts) };
  const works = await askListExport(context, user, exportContext, format, selectedIds, listParams, exportType, maxMarkingDefinition);
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
