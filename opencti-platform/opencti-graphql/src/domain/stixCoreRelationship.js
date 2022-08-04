import * as R from 'ramda';
import { map } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteElementById,
  deleteRelationsByFromAndTo,
  batchListThroughGetFrom,
  batchListThroughGetTo,
  storeLoadById,
  updateAttribute, internalLoadById
} from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { FunctionalError } from '../config/errors';
import { elCount } from '../database/engine';
import { INDEX_INFERRED_RELATIONSHIPS, READ_INDEX_STIX_CORE_RELATIONSHIPS } from '../database/utils';
import { isStixCoreRelationship, stixCoreRelationshipOptions } from '../schema/stixCoreRelationship';
import {
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
import { listRelations } from '../database/middleware-loader';
import { askEntityExport, askListExport, exportTransformFilters } from './stix';
import { workToExportFile } from './work';
import { upload } from '../database/file-storage';

export const findAll = async (user, args) => {
  return listRelations(user, R.propOr(ABSTRACT_STIX_CORE_RELATIONSHIP, 'relationship_type', args), args);
};

export const findById = (user, stixCoreRelationshipId) => {
  return storeLoadById(user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP);
};

export const stixCoreRelationshipsNumber = (user, args) => {
  const types = [];
  if (args.type) {
    if (isStixCoreRelationship(args.type)) {
      types.push(args.type);
    }
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_CORE_RELATIONSHIP);
  }
  const finalArgs = R.assoc('types', types, args);
  return {
    count: elCount(user, [READ_INDEX_STIX_CORE_RELATIONSHIPS, INDEX_INFERRED_RELATIONSHIPS], finalArgs),
    total: elCount(
      user,
      [READ_INDEX_STIX_CORE_RELATIONSHIPS, INDEX_INFERRED_RELATIONSHIPS],
      R.dissoc('endDate', finalArgs)
    ),
  };
};

export const batchCreatedBy = async (user, stixCoreRelationshipIds) => {
  const batchCreators = await batchListThroughGetTo(
    user,
    stixCoreRelationshipIds,
    RELATION_CREATED_BY,
    ENTITY_TYPE_IDENTITY
  );
  return batchCreators.map((b) => (b.edges.length > 0 ? R.head(b.edges).node : null));
};

export const batchReports = async (user, stixCoreRelationshipIds) => {
  return batchListThroughGetFrom(user, stixCoreRelationshipIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_REPORT);
};

export const batchNotes = (user, stixCoreRelationshipIds) => {
  return batchListThroughGetFrom(user, stixCoreRelationshipIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_NOTE);
};

export const batchOpinions = (user, stixCoreRelationshipIds) => {
  return batchListThroughGetFrom(user, stixCoreRelationshipIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_OPINION);
};

export const batchLabels = (user, stixCoreRelationshipIds) => {
  return batchListThroughGetTo(user, stixCoreRelationshipIds, RELATION_OBJECT_LABEL, ENTITY_TYPE_LABEL);
};

export const batchMarkingDefinitions = (user, stixCoreRelationshipIds) => {
  return batchListThroughGetTo(user, stixCoreRelationshipIds, RELATION_OBJECT_MARKING, ENTITY_TYPE_MARKING_DEFINITION);
};

export const batchExternalReferences = (user, stixCoreRelationshipIds) => {
  return batchListThroughGetTo(
    user,
    stixCoreRelationshipIds,
    RELATION_EXTERNAL_REFERENCE,
    ENTITY_TYPE_EXTERNAL_REFERENCE
  );
};

export const batchKillChainPhases = (user, stixCoreRelationshipIds) => {
  return batchListThroughGetTo(user, stixCoreRelationshipIds, RELATION_KILL_CHAIN_PHASE, ENTITY_TYPE_KILL_CHAIN_PHASE);
};

export const stixRelations = (user, stixCoreObjectId, args) => {
  const finalArgs = R.assoc('fromId', stixCoreObjectId, args);
  return findAll(user, finalArgs);
};

// region export
export const stixCoreRelationshipsExportAsk = async (user, args) => {
  const { format, type, exportType, maxMarkingDefinition } = args;
  const { search, orderBy, orderMode, filters, filterMode } = args;
  const argsFilters = { search, orderBy, orderMode, filters, filterMode };
  const filtersOpts = stixCoreRelationshipOptions.StixCoreRelationshipsFilter;
  const ordersOpts = stixCoreRelationshipOptions.StixCoreRelationshipsOrdering;
  let newArgsFiltersFilters = argsFilters.filters;
  const initialParams = {};
  if (argsFilters.filters && argsFilters.filters.length > 0) {
    if (argsFilters.filters.filter((n) => n.key === 'relationship_type').length > 0) {
      initialParams.relationship_type = R.head(R.head(argsFilters.filters.filter((n) => n.key === 'relationship_type')).values);
      newArgsFiltersFilters = newArgsFiltersFilters.filter((n) => n.key !== 'relationship_type');
    }
    if (argsFilters.filters.filter((n) => n.key === 'fromId').length > 0) {
      initialParams.fromId = R.head(R.head(argsFilters.filters.filter((n) => n.key === 'fromId')).values);
      newArgsFiltersFilters = newArgsFiltersFilters.filter((n) => n.key !== 'fromId');
    }
    if (argsFilters.filters.filter((n) => n.key === 'toId').length > 0) {
      initialParams.toId = R.head(R.head(argsFilters.filters.filter((n) => n.key === 'toId')).values);
      newArgsFiltersFilters = newArgsFiltersFilters.filter((n) => n.key !== 'toId');
    }
    if (argsFilters.filters.filter((n) => n.key === 'fromTypes').length > 0) {
      initialParams.fromTypes = R.head(argsFilters.filters.filter((n) => n.key === 'fromTypes')).values;
      newArgsFiltersFilters = newArgsFiltersFilters.filter((n) => n.key !== 'fromTypes');
    }
    if (argsFilters.filters.filter((n) => n.key === 'toTypes').length > 0) {
      initialParams.toTypes = R.head(argsFilters.filters.filter((n) => n.key === 'toTypes')).values;
      newArgsFiltersFilters = newArgsFiltersFilters.filter((n) => n.key !== 'toTypes');
    }
  }
  const finalArgsFilter = R.assoc('filters', newArgsFiltersFilters, argsFilters);
  const listParams = { ...initialParams, ...exportTransformFilters(finalArgsFilter, filtersOpts, ordersOpts) };
  const works = await askListExport(user, format, type, listParams, exportType, maxMarkingDefinition);
  return map((w) => workToExportFile(w), works);
};
export const stixCoreRelationshipExportAsk = async (user, args) => {
  const { format, stixCoreRelationshipId = null, exportType = null, maxMarkingDefinition = null } = args;
  const entity = stixCoreRelationshipId ? await storeLoadById(user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP) : null;
  const works = await askEntityExport(user, format, entity, exportType, maxMarkingDefinition);
  return map((w) => workToExportFile(w), works);
};
export const stixCoreRelationshipsExportPush = async (user, type, file, listFilters) => {
  await upload(user, `export/${type}`, file, { list_filters: listFilters });
  return true;
};
export const stixCoreRelationshipExportPush = async (user, entityId, file) => {
  const entity = await internalLoadById(user, entityId);
  await upload(user, `export/${entity.entity_type}/${entityId}`, file, { entity_id: entityId });
  return true;
};
// endregion

// region mutations
export const addStixCoreRelationship = async (user, stixCoreRelationship) => {
  if (!isStixCoreRelationship(stixCoreRelationship.relationship_type)) {
    throw FunctionalError('Only stix-core-relationship can be created through this method.');
  }
  const created = await createRelation(user, stixCoreRelationship);
  return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].ADDED_TOPIC, created, user);
};

export const stixCoreRelationshipDelete = async (user, stixCoreRelationshipId) => {
  return deleteElementById(user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP);
};

export const stixCoreRelationshipDeleteByFromAndTo = async (user, fromId, toId, relationshipType) => {
  if (!isStixCoreRelationship(relationshipType)) {
    throw FunctionalError('Only stix-core-relationship can be deleted through this method.');
  }
  await deleteRelationsByFromAndTo(user, fromId, toId, relationshipType, ABSTRACT_STIX_CORE_RELATIONSHIP);
  return true;
};

export const stixCoreRelationshipEditField = async (user, stixCoreRelationshipId, input, opts = {}) => {
  const stixCoreRelationship = await storeLoadById(user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP);
  if (!stixCoreRelationship) {
    throw FunctionalError('Cannot edit the field, stix-core-relationship cannot be found.');
  }
  const { element } = await updateAttribute(user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP, input, opts);
  return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].EDIT_TOPIC, element, user);
};

export const stixCoreRelationshipAddRelation = async (user, stixCoreRelationshipId, input) => {
  const stixCoreRelationship = await storeLoadById(user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP);
  if (!stixCoreRelationship) {
    throw FunctionalError('Cannot add the relation, stix-core-relationship cannot be found.');
  }
  if (!isStixMetaRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = R.assoc('fromId', stixCoreRelationshipId, input);
  return createRelation(user, finalInput).then((relationData) => {
    notify(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].EDIT_TOPIC, relationData, user);
    return relationData;
  });
};

export const stixCoreRelationshipDeleteRelation = async (user, stixCoreRelationshipId, toId, relationshipType) => {
  const stixCoreRelationship = await storeLoadById(user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP);
  if (!stixCoreRelationship) {
    throw FunctionalError(`Cannot delete the relation, ${ABSTRACT_STIX_CORE_RELATIONSHIP} cannot be found.`);
  }
  if (!isStixMetaRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(
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
export const stixCoreRelationshipCleanContext = (user, stixCoreRelationshipId) => {
  delEditContext(user, stixCoreRelationshipId);
  return storeLoadById(user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP).then((stixCoreRelationship) => {
    return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].EDIT_TOPIC, stixCoreRelationship, user);
  });
};

export const stixCoreRelationshipEditContext = (user, stixCoreRelationshipId, input) => {
  setEditContext(user, stixCoreRelationshipId, input);
  return storeLoadById(user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP).then((stixCoreRelationship) => {
    return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].EDIT_TOPIC, stixCoreRelationship, user);
  });
};
// endregion
