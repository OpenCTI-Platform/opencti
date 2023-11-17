import { STIX_TYPE_RELATION, STIX_TYPE_SIGHTING } from '../../../schema/general';
import { stixRefsExtractor } from '../../../schema/stixEmbeddedRelationship';
import { generateStandardId } from '../../../schema/identifier';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from '../../../types/stix-extensions';
import { isUserCanAccessStixElement } from '../../access';
import { generateInternalType, getParentTypes } from '../../../schema/schemaUtils';
import {
  ASSIGNEE_FILTER,
  CONFIDENCE_FILTER,
  PATTERN_FILTER,
  MAIN_OBSERVABLE_TYPE_FILTER,
  OBJECT_CONTAINS_FILTER,
  CREATED_BY_FILTER, CREATOR_FILTER, DETECTION_FILTER,
  INDICATOR_FILTER,
  INSTANCE_FILTER, LABEL_FILTER,
  MARKING_FILTER, REVOKED_FILTER,
  SCORE_FILTER,
  PRIORITY_FILTER,
  SEVERITY_FILTER,
  TYPE_FILTER,
  WORKFLOW_FILTER,
  RELATION_TO_FILTER,
  RELATION_TO_TYPES_FILTER,
  RELATION_FROM_FILTER,
  RELATION_FROM_TYPES_FILTER,
} from '../filtering-constants';

export const testRelationFromFilter = (stix, extractedIds, operator) => {
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

export const testRelationToFilter = (stix, extractedIds, operator) => {
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

export const testRefsFilter = (stix, extractedIds, operator) => {
  const refs = stixRefsExtractor(stix, generateStandardId);
  const isRefFound = extractedIds.some((r) => refs.includes(r));
  // If ref is available but must not be
  if (operator === 'not_eq' && isRefFound) {
    return false;
  }
  // If ref is not available but must be
  return !(operator === 'eq' && !isRefFound);
};

const testObjectsFilter = (stix, extractedIds, operator) => {
  const instanceObjects = [...(stix.object_refs ?? []), ...(stix.extensions?.[STIX_EXT_OCTI]?.object_refs_inferred ?? [])];
  const isRefFound = extractedIds.some((r) => instanceObjects.includes(r));
  // If ref is available but must not be
  if (operator === 'not_eq' && isRefFound) {
    return false;
  }
  // If ref is not available but must be
  return !(operator === 'eq' && !isRefFound);
};

export const isMatchNumeric = (values, operator, instanceValue) => {
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
          // test on relationships target/source and on objects
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
        // Need lowercase because in frontend, using "runtimeAttribute" based on keyword which is always lowercased
        const extractedValues = values.map((v) => v.value.toLowerCase());
        const isTypeAvailable = extractedValues.some((r) => indicators.includes(r.toLowerCase()));
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
      if (key === SEVERITY_FILTER) {
        const severity = stix[SEVERITY_FILTER];
        // no-severity is a filter { id: '', value '' } ; we use null to track it below
        // comparison is case-insensitive (P2 or p2 for instance)
        const ids = values.map((v) => (v.id ? v.id.toLowerCase() : null));
        const isSeverityAvailable = severity ? ids.includes(severity.toLowerCase()) : ids.includes(null);
        // If available but must not be
        if (operator === 'not_eq' && isSeverityAvailable) {
          return false;
        }
        // If not available but must be
        if (operator === 'eq' && !isSeverityAvailable) {
          return false;
        }
      }
      if (key === PRIORITY_FILTER) {
        const priority = stix[PRIORITY_FILTER];
        const ids = values.map((v) => (v.id ? v.id.toLowerCase() : null));
        const isPriorityAvailable = priority ? ids.includes(priority.toLowerCase()) : ids.includes(null);
        // If available but must not be
        if (operator === 'not_eq' && isPriorityAvailable) {
          return false;
        }
        // If not available but must be
        if (operator === 'eq' && !isPriorityAvailable) {
          return false;
        }
      }
      // Numeric filtering
      if (key === SCORE_FILTER) {
        const instanceValue = stix[SCORE_FILTER] ?? stix.extensions?.[STIX_EXT_OCTI]?.score ?? stix.extensions?.[STIX_EXT_OCTI_SCO]?.score;
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
        // Need lowercase because in frontend, using "runtimeAttribute" based on keyword which is always lowercased
        const isPatternFound = values.map((v) => v.id.toLowerCase()).includes(currentPattern?.toLowerCase());
        // If pattern is available but must not be
        if (operator === 'not_eq' && isPatternFound) {
          return false;
        }
        // If pattern is not available but must be
        if (operator === 'eq' && !isPatternFound) {
          return false;
        }
      }
      // Main Observable Filter filtering
      if (key === MAIN_OBSERVABLE_TYPE_FILTER) {
        const currentMainObservableType = stix.extensions?.[STIX_EXT_OCTI]?.main_observable_type;
        // Need lowercase because in frontend, using "runtimeAttribute" based on keyword which is always lowercased
        const isMainObservableTypeFound = values.map((v) => v.id.toLowerCase()).includes(currentMainObservableType?.toLowerCase());
        // If main observable type is available but must not be
        if (operator === 'not_eq' && isMainObservableTypeFound) {
          return false;
        }
        // If main observable type is not available but must be
        if (operator === 'eq' && !isMainObservableTypeFound) {
          return false;
        }
      }
      // object Refs filtering
      if (key === OBJECT_CONTAINS_FILTER) {
        if (!testObjectsFilter(stix, values.map((v) => v.id), operator)) {
          return false;
        }
      }
      // region specific for relationships
      if (key === RELATION_FROM_FILTER) { // 'fromId'
        if (!testRelationFromFilter(stix, values.map((v) => v.id), operator)) {
          return false;
        }
      }
      if (key === RELATION_TO_FILTER) { // 'toId'
        if (!testRelationToFilter(stix, values.map((v) => v.id), operator)) {
          return false;
        }
      }
      if (key === RELATION_FROM_TYPES_FILTER) { // fromTypes
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
      if (key === RELATION_TO_TYPES_FILTER) { // toTypes
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
