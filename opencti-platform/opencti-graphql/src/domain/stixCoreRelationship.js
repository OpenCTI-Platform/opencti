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
import {
  isNotEmptyField,
  READ_INDEX_INFERRED_RELATIONSHIPS,
  READ_INDEX_STIX_CORE_RELATIONSHIPS
} from '../database/utils';
import { isStixCoreRelationship, stixCoreRelationshipOptions } from '../schema/stixCoreRelationship';
import {
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_META_RELATIONSHIP,
  ENTITY_TYPE_IDENTITY
} from '../schema/general';
import {
  isStixMetaRelationship,
  RELATION_CREATED_BY,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
} from '../schema/stixMetaRelationship';
import {
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
} from '../schema/stixDomainObject';
import {
  ENTITY_TYPE_EXTERNAL_REFERENCE,
  ENTITY_TYPE_KILL_CHAIN_PHASE,
  ENTITY_TYPE_LABEL,
  ENTITY_TYPE_MARKING_DEFINITION,
} from '../schema/stixMetaObject';
import {
  buildEntityFilters,
  internalLoadById,
  listEntities,
  listRelations,
  storeLoadById
} from '../database/middleware-loader';
import { askEntityExport, askListExport, exportTransformFilters } from './stix';
import { workToExportFile } from './work';
import { upload } from '../database/file-storage';
import { ENTITY_TYPE_CONTAINER_CASE } from '../modules/case/case-types';

export const findAll = async (context, user, args) => {
  return listRelations(context, user, R.propOr(ABSTRACT_STIX_CORE_RELATIONSHIP, 'relationship_type', args), args);
};

export const findById = (context, user, stixCoreRelationshipId) => {
  return storeLoadById(context, user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP);
};

// region stats
export const stixCoreRelationshipsDistribution = async (context, user, args) => {
  const { dynamicFrom, dynamicTo } = args;
  let finalArgs = args;
  if (dynamicFrom && isNotEmptyField(dynamicFrom)) {
    const fromIds = await listEntities(context, user, [ABSTRACT_STIX_CORE_OBJECT], { connectionFormat: false, first: 500, filters: dynamicFrom })
      .then((result) => result.map((n) => n.id));
    finalArgs = { ...finalArgs, fromId: args.fromId ? [...fromIds, args.fromId] : fromIds };
  }
  if (dynamicTo && isNotEmptyField(dynamicTo)) {
    const toIds = await listEntities(context, user, [ABSTRACT_STIX_CORE_OBJECT], { connectionFormat: false, first: 500, filters: dynamicTo })
      .then((result) => result.map((n) => n.id));
    finalArgs = { ...finalArgs, toId: args.toId ? [...toIds, args.toId] : toIds };
  }
  return distributionRelations(context, context.user, finalArgs);
};
export const stixCoreRelationshipsNumber = (context, user, args) => {
  const { relationship_type = [ABSTRACT_STIX_CORE_RELATIONSHIP] } = args;
  const numberArgs = buildEntityFilters({ ...args, types: relationship_type });
  const indices = args.onlyInferred ? [READ_INDEX_INFERRED_RELATIONSHIPS] : [READ_INDEX_STIX_CORE_RELATIONSHIPS, READ_INDEX_INFERRED_RELATIONSHIPS];
  return {
    count: elCount(context, user, indices, numberArgs),
    total: elCount(context, user, indices, R.dissoc('endDate', numberArgs)),
  };
};
export const stixCoreRelationshipsMultiTimeSeries = (context, user, args) => {
  return Promise.all(args.timeSeriesParameters.map((timeSeriesParameter) => {
    return { data: timeSeriesRelations(context, user, { ...args, ...timeSeriesParameter }) };
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
  const { format, type, exportType, maxMarkingDefinition, selectedIds } = args;
  const { search, orderBy, orderMode, filters, filterMode } = args;
  const argsFilters = { search, orderBy, orderMode, filters, filterMode };
  const filtersOpts = stixCoreRelationshipOptions.StixCoreRelationshipsFilter;
  const ordersOpts = stixCoreRelationshipOptions.StixCoreRelationshipsOrdering;
  let newArgsFiltersFilters = argsFilters.filters;
  const initialParams = {};
  if (argsFilters.filters && argsFilters.filters.length > 0) {
    if (argsFilters.filters.filter((n) => n.key.includes('relationship_type')).length > 0) {
      initialParams.relationship_type = R.head(R.head(argsFilters.filters.filter((n) => n.key.includes('relationship_type'))).values);
      newArgsFiltersFilters = newArgsFiltersFilters.filter((n) => !n.key.includes('relationship_type'));
    }
    if (argsFilters.filters.filter((n) => n.key.includes('elementId')).length > 0) {
      initialParams.elementId = R.head(R.head(argsFilters.filters.filter((n) => n.key.includes('elementId'))).values);
      newArgsFiltersFilters = newArgsFiltersFilters.filter((n) => !n.key.includes('elementId'));
    }
    if (argsFilters.filters.filter((n) => n.key.includes('fromId')).length > 0) {
      initialParams.fromId = R.head(R.head(argsFilters.filters.filter((n) => n.key.includes('fromId'))).values);
      newArgsFiltersFilters = newArgsFiltersFilters.filter((n) => !n.key.includes('fromId'));
    }
    if (argsFilters.filters.filter((n) => n.key.includes('toId')).length > 0) {
      initialParams.toId = R.head(R.head(argsFilters.filters.filter((n) => n.key.includes('toId'))).values);
      newArgsFiltersFilters = newArgsFiltersFilters.filter((n) => !n.key.includes('toId'));
    }
    if (argsFilters.filters.filter((n) => n.key.includes('elementWithTargetTypes')).length > 0) {
      initialParams.elementWithTargetTypes = R.head(argsFilters.filters.filter((n) => n.key.includes('elementWithTargetTypes'))).values;
      newArgsFiltersFilters = newArgsFiltersFilters.filter((n) => !n.key.includes('elementWithTargetTypes'));
    }
    if (argsFilters.filters.filter((n) => n.key.includes('fromTypes')).length > 0) {
      initialParams.fromTypes = R.head(argsFilters.filters.filter((n) => n.key.includes('fromTypes'))).values;
      newArgsFiltersFilters = newArgsFiltersFilters.filter((n) => !n.key.includes('fromTypes'));
    }
    if (argsFilters.filters.filter((n) => n.key.includes('toTypes')).length > 0) {
      initialParams.toTypes = R.head(argsFilters.filters.filter((n) => n.key.includes('toTypes'))).values;
      newArgsFiltersFilters = newArgsFiltersFilters.filter((n) => !n.key.includes('toTypes'));
    }
  }
  const finalArgsFilter = {
    ...argsFilters,
    filters: newArgsFiltersFilters
  };
  const listParams = { ...initialParams, ...exportTransformFilters(finalArgsFilter, filtersOpts, ordersOpts) };
  const works = await askListExport(context, user, format, type, selectedIds, listParams, exportType, maxMarkingDefinition);
  return works.map((w) => workToExportFile(w));
};
export const stixCoreRelationshipExportAsk = async (context, user, args) => {
  const { format, stixCoreRelationshipId = null, exportType = null, maxMarkingDefinition = null } = args;
  const entity = stixCoreRelationshipId ? await storeLoadById(context, user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP) : null;
  const works = await askEntityExport(context, user, format, entity, exportType, maxMarkingDefinition);
  return works.map((w) => workToExportFile(w));
};
export const stixCoreRelationshipsExportPush = async (context, user, type, file, listFilters) => {
  await upload(context, user, `export/${type}`, file, { list_filters: listFilters });
  return true;
};
export const stixCoreRelationshipExportPush = async (context, user, entityId, file) => {
  const entity = await internalLoadById(context, user, entityId);
  await upload(context, user, `export/${entity.entity_type}/${entityId}`, file, { entity_id: entityId });
  return true;
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
  return deleteElementById(context, user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP);
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

export const stixCoreRelationshipAddRelation = async (context, user, stixCoreRelationshipId, input) => {
  const stixCoreRelationship = await storeLoadById(context, user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP);
  if (!stixCoreRelationship) {
    throw FunctionalError('Cannot add the relation, stix-core-relationship cannot be found.');
  }
  if (!isStixMetaRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = R.assoc('fromId', stixCoreRelationshipId, input);
  return createRelation(context, user, finalInput).then((relationData) => {
    notify(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].EDIT_TOPIC, relationData, user);
    return relationData;
  });
};

export const stixCoreRelationshipDeleteRelation = async (context, user, stixCoreRelationshipId, toId, relationshipType) => {
  const stixCoreRelationship = await storeLoadById(context, user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP);
  if (!stixCoreRelationship) {
    throw FunctionalError(`Cannot delete the relation, ${ABSTRACT_STIX_CORE_RELATIONSHIP} cannot be found.`);
  }
  if (!isStixMetaRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(
    context,
    user,
    stixCoreRelationshipId,
    toId,
    relationshipType,
    ABSTRACT_STIX_META_RELATIONSHIP
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].EDIT_TOPIC, stixCoreRelationship, user);
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
