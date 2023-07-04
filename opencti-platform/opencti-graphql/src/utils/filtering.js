import { buildRefRelationKey, STIX_TYPE_RELATION, STIX_TYPE_SIGHTING } from '../schema/general';
import {
  RELATION_CREATED_BY,
  RELATION_OBJECT,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
} from '../schema/stixRefRelationship';
import { RELATION_INDICATES } from '../schema/stixCoreRelationship';
import { isUserCanAccessStixElement, SYSTEM_USER } from './access';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from '../types/stix-extensions';
import { generateInternalType, getParentTypes } from '../schema/schemaUtils';
import { getEntitiesMapFromCache } from '../database/cache';
import { stixRefsExtractor } from '../schema/stixEmbeddedRelationship';
import { generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_RESOLVED_FILTERS } from '../schema/stixDomainObject';
import { extractStixRepresentative } from '../database/stix-representative';

// Resolutions
export const MARKING_FILTER = 'markedBy';
export const CREATED_BY_FILTER = 'createdBy';
export const CREATOR_FILTER = 'creator';
export const ASSIGNEE_FILTER = 'assigneeTo';
export const PARTICIPANT_FILTER = 'participant';
export const OBJECT_CONTAINS_FILTER = 'objectContains';
export const RELATION_FROM = 'fromId';
export const RELATION_TO = 'toId';
export const INSTANCE_FILTER = 'elementId';
export const NEGATION_FILTER_SUFFIX = '_not_eq';
export const RESOLUTION_FILTERS = [
  MARKING_FILTER,
  CREATED_BY_FILTER,
  ASSIGNEE_FILTER,
  PARTICIPANT_FILTER,
  OBJECT_CONTAINS_FILTER,
  RELATION_FROM,
  RELATION_TO,
  INSTANCE_FILTER
];
export const ENTITY_FILTERS = [
  INSTANCE_FILTER,
  RELATION_FROM,
  RELATION_TO,
  CREATED_BY_FILTER,
  OBJECT_CONTAINS_FILTER,
];
// Values
export const LABEL_FILTER = 'labelledBy';
export const TYPE_FILTER = 'entity_type';
export const INDICATOR_FILTER = 'indicator_types';
export const SCORE_FILTER = 'x_opencti_score';
export const DETECTION_FILTER = 'x_opencti_detection';
export const WORKFLOW_FILTER = 'x_opencti_workflow_id';
export const CONFIDENCE_FILTER = 'confidence';
export const REVOKED_FILTER = 'revoked';
export const PATTERN_FILTER = 'pattern_type';
export const RELATION_FROM_TYPES = 'fromTypes';
export const RELATION_TO_TYPES = 'toTypes';

export const GlobalFilters = {
  createdBy: buildRefRelationKey(RELATION_CREATED_BY),
  markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
  labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
  indicates: buildRefRelationKey(RELATION_INDICATES),
  objectContains: buildRefRelationKey(RELATION_OBJECT),
  creator: 'creator_id',
};

export const extractFilterIdsToResolve = (filters) => {
  const filterEntries = Object.entries(filters);
  return filterEntries
    .filter(([key]) => RESOLUTION_FILTERS
      .map((r) => [r, r + NEGATION_FILTER_SUFFIX])
      .flat()
      .includes(key))
    .map(([, values]) => values.map((v) => v.id))
    .flat();
};

// build a map ([id]: StixObject) with the resolved filters accessible for a user
export const resolvedFiltersMapForUser = async (context, user, filters) => {
  const resolveUserMap = new Map();
  const resolvedMap = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_RESOLVED_FILTERS);
  const filterEntries = Object.entries(filters);
  for (let index = 0; index < filterEntries.length; index += 1) {
    const [key, rawValues] = filterEntries[index];
    for (let vIndex = 0; vIndex < rawValues.length; vIndex += 1) {
      const v = rawValues[vIndex];
      if (RESOLUTION_FILTERS.includes(key) && resolvedMap.has(v.id)) {
        const stixInstance = resolvedMap.get(v.id);
        const isUserHasAccessToElement = await isUserCanAccessStixElement(context, user, stixInstance);
        if (isUserHasAccessToElement) {
          resolveUserMap.set(stixInstance.id, stixInstance);
        }
      }
    }
  }
  return resolveUserMap;
};

export const convertFiltersFrontendFormat = async (context, user, filters) => {
  // Grab all values that are internal_id that needs to be converted to standard_ids
  const resolvedMap = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_RESOLVED_FILTERS);
  // Remap the format of specific keys
  const adaptedFilters = [];
  const filterEntries = Object.entries(filters);
  for (let index = 0; index < filterEntries.length; index += 1) {
    const [key, rawValues] = filterEntries[index];
    const values = [];
    for (let vIndex = 0; vIndex < rawValues.length; vIndex += 1) {
      const v = rawValues[vIndex];
      if (RESOLUTION_FILTERS.includes(key) && resolvedMap.has(v.id)) {
        const stixInstance = resolvedMap.get(v.id);
        const isUserHasAccessToElement = await isUserCanAccessStixElement(context, user, stixInstance);
        const value = extractStixRepresentative(stixInstance);
        // add id if user has access to the element
        values.push({ id: isUserHasAccessToElement ? v.id : '<invalid access>', value });
        // add standard id if user has access to the element
        values.push({ id: isUserHasAccessToElement ? stixInstance.id : '<invalid access>', value });
      } else {
        values.push(v);
      }
    }
    if (key.endsWith('start_date') || key.endsWith('_gt')) {
      const workingKey = key.replace('_start_date', '').replace('_gt', '');
      adaptedFilters.push({ key: workingKey, operator: 'gt', values });
    } else if (key.endsWith('end_date') || key.endsWith('_lt')) {
      const workingKey = key.replace('_end_date', '').replace('_lt', '');
      adaptedFilters.push({ key: workingKey, operator: 'lt', values });
    } else if (key.endsWith('_gte')) {
      const workingKey = key.replace('_gte', '');
      adaptedFilters.push({ key: workingKey, operator: 'gte', values });
    } else if (key.endsWith('_lte')) {
      const workingKey = key.replace('_lte', '');
      adaptedFilters.push({ key: workingKey, operator: 'lte', values });
    } else if (key.endsWith('_not_eq')) {
      const workingKey = key.replace('_not_eq', '');
      adaptedFilters.push({ key: workingKey, operator: 'not_eq', values, filterMode: 'and' });
    } else {
      adaptedFilters.push({ key, operator: 'eq', values, filterMode: 'or' });
    }
  }
  return adaptedFilters;
};

export const convertFiltersToQueryOptions = async (context, user, filters, opts = {}) => {
  const { after, before, defaultTypes = [], field = 'updated_at', orderMode = 'asc' } = opts;
  const queryFilters = [];
  const types = [...defaultTypes];
  if (filters) {
    const adaptedFilters = await convertFiltersFrontendFormat(context, user, filters);
    for (let index = 0; index < adaptedFilters.length; index += 1) {
      // eslint-disable-next-line prefer-const
      let { key, operator, values, filterMode } = adaptedFilters[index];
      if (key === TYPE_FILTER) {
        types.push(...values.map((v) => v.id));
      } else {
        queryFilters.push({ key: GlobalFilters[key] || key, values: values.map((v) => v.id), operator, filterMode });
      }
    }
  }
  if (after) {
    queryFilters.push({ key: field, values: [after], operator: 'gte' });
  }
  if (before) {
    queryFilters.push({ key: field, values: [before], operator: 'lte' });
  }
  return { types, orderMode, orderBy: [field, 'internal_id'], filters: queryFilters };
};

const testRelationFromFilter = (stix, extractedIds, operator) => {
  if (stix.type === STIX_TYPE_RELATION) {
    const idFromFound = extractedIds.includes(stix.source_ref);
    // If source is available but must not be
    if (operator === 'not_eq' && idFromFound) {
      return false;
    }
    // If source is not available but must be
    if (operator === 'eq' && !idFromFound) {
      return false;
    }
  } else if (stix.type === STIX_TYPE_SIGHTING) {
    const isFromFound = extractedIds.includes(stix.sighting_of_ref);
    // If source is available but must not be
    if (operator === 'not_eq' && isFromFound) {
      return false;
    }
    // If source is not available but must be
    if (operator === 'eq' && !isFromFound) {
      return false;
    }
  } else {
    return false;
  }
  return true;
};

const testRelationToFilter = (stix, extractedIds, operator) => {
  if (stix.type === STIX_TYPE_RELATION) {
    const idToFound = extractedIds.includes(stix.target_ref);
    // If target is available but must not be
    if (operator === 'not_eq' && idToFound) {
      return false;
    }
    // If target is not available but must be
    if (operator === 'eq' && !idToFound) {
      return false;
    }
  } else if (stix.type === STIX_TYPE_SIGHTING) {
    const idsFromFound = extractedIds.some((r) => stix.where_sighted_refs.includes(r));
    // If target is available but must not be
    if (operator === 'not_eq' && idsFromFound) {
      return false;
    }
    // If target is not available but must be
    if (operator === 'eq' && !idsFromFound) {
      return false;
    }
  } else {
    return false;
  }
  return true;
};

const testRefsFilter = (stix, extractedIds, operator) => {
  const refs = stixRefsExtractor(stix, generateStandardId);
  const isRefFound = extractedIds.some((r) => refs.includes(r));
  // If ref is available but must not be
  if (operator === 'not_eq' && isRefFound) {
    return false;
  }
  // If ref is not available but must be
  if (operator === 'eq' && !isRefFound) {
    return false;
  }
  return true;
};

const testObjectContainsFilter = (stix, extractedIds, operator) => {
  const instanceObjects = [...(stix.object_refs ?? []), ...(stix.extensions?.[STIX_EXT_OCTI]?.object_refs_inferred ?? [])];
  const isRefFound = extractedIds.some((r) => instanceObjects.includes(r));
  // If ref is available but must not be
  if (operator === 'not_eq' && isRefFound) {
    return false;
  }
  // If ref is not available but must be
  if (operator === 'eq' && !isRefFound) {
    return false;
  }
  return true;
};

const isMatchNumeric = (values, operator, instanceValue) => {
  const { id } = values.at(0) ?? {};
  const numeric = parseInt(id, 10);
  let found;
  switch (operator) {
    case 'lt':
      found = instanceValue < numeric;
      break;
    case 'lte':
      found = instanceValue <= numeric;
      break;
    case 'gt':
      found = instanceValue > numeric;
      break;
    case 'gte':
      found = instanceValue >= numeric;
      break;
    default:
      found = instanceValue === numeric;
  }
  return found;
};

export const isStixMatchFilters = async (context, user, stix, adaptedFilters, useSideEventMatching = false) => {
  // We can start checking the user can access the stix (marking + segregation).
  const isUserHasAccessToElement = await isUserCanAccessStixElement(context, user, stix);
  if (!isUserHasAccessToElement) {
    return false;
  }
  // User is granted, but we still need to apply filters if needed
  for (let index = 0; index < adaptedFilters.length; index += 1) {
    const { key, operator, values } = adaptedFilters[index];
    if (values.length > 0) {
      // Markings filtering
      if (key === MARKING_FILTER) {
        const instanceMarkings = stix.object_marking_refs || [];
        const ids = values.map((v) => v.id);
        const isMarkingAvailable = ids.some((r) => instanceMarkings.includes(r));
        // If marking is available but must not be
        if (operator === 'not_eq' && isMarkingAvailable) {
          return false;
        }
        // If marking is not available but must be
        if (operator === 'eq' && !isMarkingAvailable) {
          return false;
        }
      }
      // Entity type filtering
      if (key === TYPE_FILTER) {
        const instanceType = stix.extensions?.[STIX_EXT_OCTI]?.type ?? generateInternalType(stix);
        const instanceAllTypes = [instanceType, ...getParentTypes(instanceType)];
        const isTypeAvailable = values.some((v) => instanceAllTypes.includes(v.id));
        // If entity type is available but must not be
        if (operator === 'not_eq' && isTypeAvailable) {
          return false;
        }
        // If entity type is not available but must be
        if (operator === 'eq' && !isTypeAvailable) {
          return false;
        }
      }
      // Entity filtering
      if (key === INSTANCE_FILTER) {
        const instanceId = stix.extensions?.[STIX_EXT_OCTI]?.id;
        const extractedIds = values.map((v) => v.id);
        const isIdAvailable = instanceId && extractedIds.includes(instanceId);
        if (!useSideEventMatching) {
          // If entity is available but must not be
          if (operator === 'not_eq' && isIdAvailable) {
            return false;
          }
          // If entity is not available but must be
          if (operator === 'eq' && !isIdAvailable) {
            return false;
          }
        } else { // side events only
          if (operator === 'not_eq') {
            return false; // no application
          }
          // If entity is not available but must be
          // test on relationships target/source and on objectContains
          if (operator === 'eq'
            && !testRelationFromFilter(stix, extractedIds, operator)
            && !testRelationToFilter(stix, extractedIds, operator)
            && !testRefsFilter(stix, extractedIds, operator)
          ) {
            return false;
          }
        }
      }
      // Indicator type filtering
      if (key === INDICATOR_FILTER) {
        const indicators = stix.indicator_types ?? [];
        const extractedValues = values.map((v) => v.value);
        const isTypeAvailable = extractedValues.some((r) => indicators.includes(r));
        // If indicator type is available but must not be
        if (operator === 'not_eq' && isTypeAvailable) {
          return false;
        }
        // If indicator type is not available but must be
        if (operator === 'eq' && !isTypeAvailable) {
          return false;
        }
      }
      // Workflow filtering
      if (key === WORKFLOW_FILTER) {
        const workflowId = stix.extensions[STIX_EXT_OCTI].workflow_id;
        const isWorkflowAvailable = workflowId && values.map((v) => v.id).includes(workflowId);
        // If workflow is available but must not be
        if (operator === 'not_eq' && isWorkflowAvailable) {
          return false;
        }
        // If workflow is not available but must be
        if (operator === 'eq' && !isWorkflowAvailable) {
          return false;
        }
      }
      // CreatedBy filtering
      if (key === CREATED_BY_FILTER) {
        const ids = values.map((v) => v.id);
        const createdBy = stix.created_by_ref ?? stix.extensions?.[STIX_EXT_OCTI_SCO]?.created_by_ref;
        const isCreatedByAvailable = createdBy && ids.includes(createdBy);
        // If creator is available but must not be
        if (operator === 'not_eq' && isCreatedByAvailable) {
          return false;
        }
        // If creator is not available but must be
        if (operator === 'eq' && !isCreatedByAvailable) {
          return false;
        }
      }
      // Technical creator filter
      if (key === CREATOR_FILTER) {
        const creators = stix.extensions[STIX_EXT_OCTI]?.creator_ids ?? [];
        const extractedValues = values.map((v) => v.id);
        const isCreatorAvailable = extractedValues.some((r) => creators.includes(r));
        // If creator is available but must not be
        if (operator === 'not_eq' && isCreatorAvailable) {
          return false;
        }
        // If creator is not available but must be
        if (operator === 'eq' && !isCreatorAvailable) {
          return false;
        }
      }
      // Assignee filtering
      if (key === ASSIGNEE_FILTER) {
        const assignees = stix.extensions[STIX_EXT_OCTI]?.assignee_ids ?? [];
        const extractedValues = values.map((v) => v.id);
        const isAssigneeAvailable = extractedValues.some((r) => assignees.includes(r));
        // If assignee is available but must not be
        if (operator === 'not_eq' && isAssigneeAvailable) {
          return false;
        }
        // If assignee is not available but must be
        if (operator === 'eq' && !isAssigneeAvailable) {
          return false;
        }
      }
      // Labels filtering
      if (key === LABEL_FILTER) {
        // Handle no label filtering
        const isNoLabelRequire = values.map((v) => v.id).includes(null);
        if (operator === 'not_eq' && isNoLabelRequire && (stix.labels ?? []).length === 0) {
          return false;
        }
        if (operator === 'eq' && isNoLabelRequire && (stix.labels ?? []).length > 0) {
          return false;
        }
        // Get only required labels
        const labels = values.map((v) => (v.id ? v.value : null)).filter((v) => v !== null);
        if (labels.length > 0) {
          const dataLabels = [...(stix.labels ?? []), ...(stix.extensions?.[STIX_EXT_OCTI_SCO]?.labels ?? [])];
          const isLabelAvailable = labels.some((r) => dataLabels.includes(r));
          // If label is available but must not be
          if (operator === 'not_eq' && isLabelAvailable) {
            return false;
          }
          // If label is not available but must be
          if (operator === 'eq' && !isLabelAvailable) {
            return false;
          }
        }
      }
      // Revoked filtering
      if (key === REVOKED_FILTER) {
        const { id } = values.at(0) ?? {};
        const isRevoked = (id === 'true') === stix.revoked;
        if (!isRevoked) {
          return false;
        }
      }
      //  Detection filtering
      if (key === DETECTION_FILTER) {
        const { id } = values.at(0) ?? {};
        const isDetection = (id === 'true') === stix.extensions?.[STIX_EXT_OCTI]?.detection;
        if (!isDetection) {
          return false;
        }
      }
      // Numeric filtering
      if (key === SCORE_FILTER) {
        const instanceValue = stix[SCORE_FILTER] ?? stix.extensions?.[STIX_EXT_OCTI_SCO]?.score;
        if (!isMatchNumeric(values, operator, instanceValue)) {
          return false;
        }
      }
      if (key === CONFIDENCE_FILTER) {
        const instanceValue = stix[CONFIDENCE_FILTER];
        if (!isMatchNumeric(values, operator, instanceValue)) {
          return false;
        }
      }
      // Pattern type filtering
      if (key === PATTERN_FILTER) {
        const currentPattern = stix.pattern_type;
        const isPatternFound = values.map((v) => v.id).includes(currentPattern);
        // If pattern is available but must not be
        if (operator === 'not_eq' && isPatternFound) {
          return false;
        }
        // If pattern is not available but must be
        if (operator === 'eq' && !isPatternFound) {
          return false;
        }
      }
      // object Refs filtering
      if (key === OBJECT_CONTAINS_FILTER) {
        if (!testObjectContainsFilter(stix, values.map((v) => v.id), operator)) {
          return false;
        }
      }
      // region specific for relationships
      if (key === RELATION_FROM) { // 'fromId'
        if (!testRelationFromFilter(stix, values.map((v) => v.id), operator)) {
          return false;
        }
      }
      if (key === RELATION_TO) { // 'toId'
        if (!testRelationToFilter(stix, values.map((v) => v.id), operator)) {
          return false;
        }
      }
      if (key === RELATION_FROM_TYPES) { // fromTypes
        if (stix.type === STIX_TYPE_RELATION) {
          const sourceType = stix.extensions[STIX_EXT_OCTI].source_type;
          const sourceAllTypes = [sourceType, ...getParentTypes(sourceType)];
          const isTypeAvailable = values.some((v) => sourceAllTypes.includes(v.id));
          // If source type is available but must not be
          if (operator === 'not_eq' && isTypeAvailable) {
            return false;
          }
          // If source type is not available but must be
          if (operator === 'eq' && !isTypeAvailable) {
            return false;
          }
        } else if (stix.type === STIX_TYPE_SIGHTING) {
          const sourceType = stix.extensions[STIX_EXT_OCTI].sighting_of_type;
          const sourceAllTypes = [sourceType, ...getParentTypes(sourceType)];
          const isTypeAvailable = values.some((v) => sourceAllTypes.includes(v.id));
          // If source type is available but must not be
          if (operator === 'not_eq' && isTypeAvailable) {
            return false;
          }
          // If source type is not available but must be
          if (operator === 'eq' && !isTypeAvailable) {
            return false;
          }
        } else {
          return false;
        }
      }
      if (key === RELATION_TO_TYPES) { // toTypes
        if (stix.type === STIX_TYPE_RELATION) {
          const targetType = stix.extensions[STIX_EXT_OCTI].target_type;
          const targetAllTypes = [targetType, ...getParentTypes(targetType)];
          const isTypeAvailable = values.some((v) => targetAllTypes.includes(v.id));
          // If source type is available but must not be
          if (operator === 'not_eq' && isTypeAvailable) {
            return false;
          }
          // If source type is not available but must be
          if (operator === 'eq' && !isTypeAvailable) {
            return false;
          }
        } else if (stix.type === STIX_TYPE_SIGHTING) {
          const targetTypes = stix.extensions[STIX_EXT_OCTI].where_sighted_types;
          const targetAllTypes = targetTypes.map((t) => [t, ...getParentTypes(t)]).flat();
          const isTypeAvailable = values.some((v) => targetAllTypes.includes(v.id));
          // If source type is available but must not be
          if (operator === 'not_eq' && isTypeAvailable) {
            return false;
          }
          // If source type is not available but must be
          if (operator === 'eq' && !isTypeAvailable) {
            return false;
          }
        } else {
          return false;
        }
      }
      // endregion
    }
  }
  return true;
};
