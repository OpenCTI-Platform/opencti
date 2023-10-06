import * as R from 'ramda';
import { getEntitiesMapFromCache } from '../database/cache';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { SYSTEM_USER } from './access';
import { UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE, UPDATE_OPERATION_REPLACE } from '../database/utils';

export const cleanMarkings = async (context, values) => {
  const markingsMap = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  const defaultMarkingValues = values?.map((d) => markingsMap.get(d) ?? d) ?? [];
  const defaultGroupedMarkings = R.groupBy((m) => m.definition_type, defaultMarkingValues);
  return Object.entries(defaultGroupedMarkings).map(([_, key]) => {
    const max = Math.max(...key.map((m) => m.x_opencti_order));
    const results = key.filter((m) => m.x_opencti_order === max);
    return R.uniqWith((a, b) => a.id === b.id, results);
  }).flat();
};

export const handleMarkingOperations = async (context, currentMarkings, refs, operation) => {
  // Get all marking definitions
  const markingsMap = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  // Get object entries from markings Map, convert into array without duplicate values
  const markingsAdded = [...new Set(Object.values(Object.fromEntries(markingsMap)))].filter((m) => refs.includes(m.id));
  // If multiple markings is added, filter and keep the highest rank
  const markingsAddedCleaned = await cleanMarkings(context, markingsAdded);

  const operationUpdated = { operation, refs };

  const markingsInCommon = currentMarkings.filter((item) => markingsAddedCleaned.some((m) => m.definition_type === item.definition_type));

  if (operation === UPDATE_OPERATION_ADD) {
    if (markingsInCommon.length === 0) {
      // If markings in input is thoroughly different from current
      operationUpdated.operation = UPDATE_OPERATION_ADD;
      operationUpdated.refs = markingsAddedCleaned.map((m) => m.id);
      return operationUpdated;
    }

    if (markingsAddedCleaned.some((mark) => currentMarkings.some((mark2) => mark2.definition_type === mark.definition_type && mark2.x_opencti_order !== mark.x_opencti_order))) {
      const markingsToKeep = await cleanMarkings(context, [...currentMarkings, ...markingsAddedCleaned]);

      const markingsAddedHasHigherOrder = currentMarkings
        .some((currentMarking) => markingsAddedCleaned
          .some((markingAdded) => markingAdded.definition_type === currentMarking.definition_type && markingAdded.x_opencti_order > currentMarking.x_opencti_order));

      // NEED TO DO A REPLACE
      // If some of the added item has a higher rank than before, replace
      if (markingsAddedHasHigherOrder) {
        operationUpdated.operation = UPDATE_OPERATION_REPLACE;
        operationUpdated.refs = markingsToKeep.map((m) => m.id);
        return operationUpdated;
      }
      operationUpdated.operation = UPDATE_OPERATION_ADD;
      operationUpdated.refs = markingsToKeep.filter((m) => !currentMarkings.some(({ id }) => id === m.id)).map((m) => m.id);
      return operationUpdated;
    }
    // THIS IS A ADD
    operationUpdated.operation = UPDATE_OPERATION_ADD;
    operationUpdated.refs = markingsAddedCleaned.map((m) => m.id);
    return operationUpdated;
  }

  if (operation === UPDATE_OPERATION_REPLACE) {
    operationUpdated.operation = UPDATE_OPERATION_REPLACE;
    operationUpdated.refs = markingsAddedCleaned.map((m) => m.id);
    return operationUpdated;
  }

  if (operation === UPDATE_OPERATION_REMOVE) {
    return operationUpdated;
  }

  return operationUpdated;
};
