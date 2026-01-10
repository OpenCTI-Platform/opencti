import { type Filter, type FilterGroup, FilterMode, FilterOperator } from '../../generated/graphql';
import type { AuthContext, AuthUser } from '../../types/user';
import {
  ALIAS_FILTER,
  BULK_SEARCH_KEYWORDS_FILTER,
  BULK_SEARCH_KEYWORDS_FILTER_KEYS,
  COMPUTED_RELIABILITY_FILTER,
  ID_SUBFILTER,
  IDS_FILTER,
  INSTANCE_DYNAMIC_REGARDING_OF,
  INSTANCE_REGARDING_OF,
  INSTANCE_RELATION_FILTER,
  INSTANCE_RELATION_TYPES_FILTER,
  IS_INFERRED_FILTER,
  isComplexConversionFilterKey,
  LAST_PIR_SCORE_DATE_FILTER,
  LAST_PIR_SCORE_DATE_SUBFILTER,
  PIR_IDS_SUBFILTER,
  PIR_SCORE_FILTER,
  PIR_SCORE_SUBFILTER,
  RELATION_DYNAMIC_FROM_FILTER,
  RELATION_DYNAMIC_SUBFILTER,
  RELATION_DYNAMIC_TO_FILTER,
  RELATION_FROM_FILTER,
  RELATION_FROM_ROLE_FILTER,
  RELATION_FROM_TYPES_FILTER,
  RELATION_INFERRED_SUBFILTER,
  RELATION_TO_FILTER,
  RELATION_TO_ROLE_FILTER,
  RELATION_TO_SIGHTING_FILTER,
  RELATION_TO_TYPES_FILTER,
  RELATION_TYPE_FILTER,
  RELATION_TYPE_SUBFILTER,
  SOURCE_RELIABILITY_FILTER,
  TYPE_FILTER,
  USER_SERVICE_ACCOUNT_FILTER,
  WORKFLOW_FILTER,
  X_OPENCTI_WORKFLOW_ID,
} from './filtering-constants';
import { ForbiddenAccess, FunctionalError, ResourceNotFoundError, UnsupportedError } from '../../config/errors';
import { ATTRIBUTE_ALIASES, ATTRIBUTE_ALIASES_OPENCTI, ENTITY_TYPE_IDENTITY_INDIVIDUAL, ENTITY_TYPE_IDENTITY_SYSTEM } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../modules/organization/organization-types';
import { isEmptyField, isNotEmptyField, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../../database/utils';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_OBJECT, buildRefRelationKey, ID_INFERRED, ID_INTERNAL } from '../../schema/general';
import { addFilter } from './filtering-utils';
import type { BasicStoreBase, BasicWorkflowStatus } from '../../types/store';
import { getPirWithAccessCheck } from '../../modules/pir/pir-checkPirAccess';
import { authorizedMembers, type ComplexAttribute } from '../../schema/attribute-definition';
import { isMetricsName } from '../../modules/metrics/metrics-utils';
import { isObjectAttribute, schemaAttributesDefinition } from '../../schema/schema-attributes';
import { computeQueryIndices, elFindByIds, elList, elPaginate, ES_MAX_PAGINATION } from '../../database/engine';
import { keepMostRestrictiveTypes } from '../../schema/schemaUtils';
import { RELATION_IN_PIR } from '../../schema/internalRelationship';
import { isUserHasCapability, PIRAPI } from '../access';
import { uniqAsyncMap } from '../data-processing';
import { ENTITY_TYPE_PIR } from '../../modules/pir/pir-types';
import { getEntitiesListFromCache } from '../../database/cache';
import { ENTITY_TYPE_STATUS } from '../../schema/internalObject';
import { IDS_ATTRIBUTES } from '../../domain/attribute-utils';

export const adaptFilterToRegardingOfFilterKey = async (context: AuthContext, user: AuthUser, filter: TaggedFilter) => {
  const { key: filterKey, postFilteringTag } = filter;
  const regardingFilters = [];
  const idParameter = filter.values.find((i) => i.key === ID_SUBFILTER);
  const typeParameter = filter.values.find((i) => i.key === RELATION_TYPE_SUBFILTER);
  const dynamicParameter = filter.values.find((i) => i.key === RELATION_DYNAMIC_SUBFILTER);
  const inferredParameter = filter.values.find((i) => i.key === RELATION_INFERRED_SUBFILTER);
  // Check parameters
  if (!idParameter && !dynamicParameter && !typeParameter) {
    throw UnsupportedError('Id or dynamic or relationship type are needed for this filtering key', { key: filterKey });
  }
  if (dynamicParameter && !typeParameter?.values?.length) {
    throw UnsupportedError('Relationship type is needed for dynamic in regards of filtering', { key: filterKey, type: typeParameter });
  }
  // Check operator
  if (filter.operator && filter.operator !== 'eq' && filter.operator !== 'not_eq') { // should be eq or not_eq
    throw UnsupportedError('regardingOf filter only supports equality restriction');
  }
  if (inferredParameter && filter.operator && filter.operator !== 'eq') {
    // if inferred parameter is specified, operator should be eq because inferred parameter is treated in post-filtering, which only handles eq operator
    throw UnsupportedError('regardingOf filter with inferred subfilter only supports eq operator');
  }
  // Check for PIR has it required
  if (typeParameter) {
    const isPirRelatedType = (typeParameter.values ?? []).includes(RELATION_IN_PIR);
    if (isPirRelatedType && !isUserHasCapability(user, PIRAPI)) {
      throw ForbiddenAccess('You are not allowed to use PIR filtering');
    }
  }
  let ids = idParameter?.values ?? [];
  // Limit the number of possible ids in the regardingOf
  if (ids.length > ES_MAX_PAGINATION) {
    throw UnsupportedError('Too much ids specified', { size: ids.length, max: ES_MAX_PAGINATION });
  }
  if (ids.length > 0) {
    // Keep ids the user has access to
    const filteredEntities = await elFindByIds(context, user, ids, { baseData: true }) as BasicStoreBase[];
    // If no type specified, we also need to check if the user have the correct capability for Pirs
    if (!typeParameter && !isUserHasCapability(user, PIRAPI)) {
      const isIncludingPir = (await uniqAsyncMap(filteredEntities, (value) => value.entity_type))
        .includes(ENTITY_TYPE_PIR);
      if (isIncludingPir) {
        throw ForbiddenAccess('You are not allowed to use PIR filtering');
      }
    }
    ids = filteredEntities.map((n) => n.id);
    if (ids.length === 0) { // If no id available, reject the query
      throw ResourceNotFoundError('Specified ids not found or restricted');
    }
  }
  // Check dynamic
  const dynamicFilter = dynamicParameter?.values ?? [];
  if (isNotEmptyField(dynamicFilter)) {
    const computedIndices = computeQueryIndices([], [ABSTRACT_STIX_OBJECT]);
    const relatedEntities = await elPaginate(context, user, computedIndices, {
      connectionFormat: false,
      first: ES_MAX_PAGINATION,
      baseData: true,
      filters: addFilter(dynamicFilter[0], TYPE_FILTER, [ABSTRACT_STIX_CORE_OBJECT]),
    }) as BasicStoreBase[];
    if (relatedEntities.length > 0) {
      const relatedIds = relatedEntities.map((n) => n.id);
      ids.push(...relatedIds);
    } else {
      ids.push('<invalid id>'); // To force empty result in the query result
    }
  }
  const types = typeParameter?.values;
  // Construct and push the final regarding of filter
  const mode = (filter.operator === 'eq' || isEmptyField(filter.operator)) ? FilterMode.Or : FilterMode.And;
  if (isEmptyField(ids)) {
    const keys = isEmptyField(types)
      ? buildRefRelationKey('*', '*')
      : types.map((t: string) => buildRefRelationKey(t, '*'));
    keys.forEach((relKey: string) => {
      regardingFilters.push({ key: [relKey], operator: filter.operator, values: ['EXISTS'], postFilteringTag });
    });
  } else {
    const keys = isEmptyField(types)
      ? buildRefRelationKey('*', '*')
      : types.flatMap((t: string) => [buildRefRelationKey(t, ID_INTERNAL), buildRefRelationKey(t, ID_INFERRED)]);
    regardingFilters.push({ key: keys, operator: filter.operator, mode, values: ids, postFilteringTag });
  }
  return { newFilterGroup: { mode, filters: regardingFilters, filterGroups: [] } };
};

export const adaptFilterToIdsFilterKey = (filter: Filter) => {
  const { key, mode = FilterMode.Or, operator = FilterOperator.Eq } = filter;
  const arrayKeys = Array.isArray(key) ? key : [key];
  if (arrayKeys[0] !== IDS_FILTER || arrayKeys.length > 1) {
    throw UnsupportedError('A filter with these multiple keys is not supported', { keys: arrayKeys });
  }
  if (mode === 'and') {
    throw UnsupportedError('Unsupported filter: \'And\' operator between values of a filter with key = \'ids\' is not supported');
  }
  // at this point arrayKey === ['ids'], and mode is always 'or'

  // we'll build these new filters or filterGroup, depending on the situation
  let newFilterGroup: FilterGroup | undefined;

  const idsArray = [...IDS_ATTRIBUTES]; // the keys to handle additionally

  if (operator === 'nil' || operator === 'not_nil') { // nil and not_nil operators must have a single key
    const filters = idsArray.map((idKey) => {
      return { ...filter, key: [idKey] };
    });
    newFilterGroup = {
      mode: FilterMode.And,
      filters,
      filterGroups: [],
    };
    return { newFilterGroup };
  }

  // at this point, operator !== nil and operator !== not_nil
  // we replace the key "ids" by the list of ids attribute (internal_id, standard_id, ...)
  const newFilter = { ...filter, key: idsArray };

  // depending on the operator, only one of newFilter and newFilterGroup is defined
  return { newFilter, newFilterGroup };
};

const adaptFilterToEntityTypeFilterKey = (filter: any) => {
  // If filter key = entity_type, we should also handle parent_types
  // Example: filter = {mode: 'or', operator: 'eq', key: ['entity_type'], values: ['Report', 'Stix-Cyber-Observable']}
  // we check parent_types because otherwise we would never match Stix-Cyber-Observable which is an abstract parent type
  const { key, mode = FilterMode.Or, operator = FilterOperator.Eq } = filter;
  const arrayKeys = Array.isArray(key) ? key : [key];
  if (arrayKeys.length > 1) {
    throw UnsupportedError('A filter with these multiple keys is not supported', { keys: arrayKeys });
  }
  // at this point arrayKeys === ['entity_type']

  // we'll build these new filters or filterGroup, depending on the situation
  let newFilter: Filter | undefined;
  let newFilterGroup: FilterGroup | undefined;

  if (operator === 'nil' || operator === 'not_nil') { // nil and not_nil operators must have a single key
    newFilterGroup = {
      mode: FilterMode.And,
      filters: [
        filter,
        {
          ...filter,
          key: ['parent_types'],
        },
      ],
      filterGroups: [],
    };
    return { newFilter, newFilterGroup };
  }

  // In case where filter values is an empty array
  if (filter.values.length === 0) {
    return { newFilter, newFilterGroup };
  }

  // at this point, operator !== nil and operator !== not_nil
  if (mode === 'or') {
    // in elastic, having several keys is an implicit 'or' between the keys, so we can just add the key in the list
    // and we will search in both entity_types and parent_types
    newFilter = { ...filter, key: arrayKeys.concat(['parent_types']) };
  }

  if (mode === 'and') {
    let { values } = filter;
    if (operator === 'eq') {
      // 'and'+'eq' => keep only the most restrictive entity types
      // because in elastic entity_type is a unique value (not an abstract type)
      // for example [Report, Container] => [Report]
      // for example [Report, Stix-Cyber-Observable] => [Report, Stix-Cyber-Observable]
      values = keepMostRestrictiveTypes(filter.values);
    }

    // we must split the keys in different filters to get different elastic matches, so we construct a filterGroup
    // - if the operator is 'eq', it means we have to check equality against the type
    // and all parent types, so it's a filterGroup with 'or' operator
    // - if the operator is 'not_eq', it means we have to check that there is no match in type
    // and all parent types, so it's a filterGroup with 'and' operator
    newFilterGroup = {
      mode: operator === 'eq' ? FilterMode.Or : FilterMode.And,
      filters: [
        { ...filter, key: ['entity_type'], values },
        { ...filter, key: ['parent_types'], values },
      ],
      filterGroups: [],
    };
  }

  // depending on the operator (or/and), only one of newFilter and newFilterGroup is defined
  return { newFilter, newFilterGroup };
};

const adaptFilterToWorkflowFilterKey = async (context: AuthContext, user: AuthUser, filter: Filter) => {
  // workflow_id filter values can be both status ids and status templates ids
  const { key, mode = FilterMode.Or, operator = FilterOperator.Eq, values } = filter;
  const arrayKeys = Array.isArray(key) ? key : [key];
  if (arrayKeys.length > 1) {
    throw UnsupportedError(`A filter with these multiple keys is not supported : ${arrayKeys}`);
  }
  if (![WORKFLOW_FILTER, X_OPENCTI_WORKFLOW_ID].includes(arrayKeys[0])) {
    throw UnsupportedError('The key is not correct', { keys: arrayKeys });
  }
  let newFilterGroup: FilterGroup | undefined;
  let newFilter;
  if (operator === 'nil' || operator === 'not_nil') { // no status template <-> no status // at least a status template <-> at least a status
    newFilter = {
      ...filter,
      key: ['x_opencti_workflow_id'], // we just have to change the key
    };
  } else if (operator === 'eq' || operator === 'not_eq') {
    const statuses = await getEntitiesListFromCache<BasicWorkflowStatus>(context, user, ENTITY_TYPE_STATUS);
    const filters = [];
    for (let i = 0; i < values.length; i += 1) {
      const filterValue = values[i];
      // fetch the statuses associated to the filter value
      // (keep the statuses with their id corresponding to the filter value, or with their template id corresponding to the filter value)
      const associatedStatuses = statuses.filter((status) => (filterValue === status.id || filterValue === status.template_id));
      // we construct a new filter that matches against the status internal_id with a template id in the filters values
      // !!! it works to do the mode/operator filter on the status (and not on the template)
      // because a status can only have a single template and because the operators are full-match operators (eq/not_eq) !!!
      const associatedStatuseIds = associatedStatuses.length > 0 ? associatedStatuses.map((status) => status.internal_id) : ['<no-status-matching-filter>'];
      filters.push({
        key: ['x_opencti_workflow_id'],
        values: associatedStatuseIds,
        mode: operator === 'eq'
          ? FilterMode.Or // at least one associated status should match
          : FilterMode.And, // all the associated status of the value shouldn't match
        operator,
      });
    }
    newFilterGroup = {
      mode: mode ?? FilterMode.Or,
      filters,
      filterGroups: [],
    };
  } else {
    throw UnsupportedError('The operators supported for a filter with key=workflow_id is not supported.', { operator });
  }
  return { newFilter, newFilterGroup };
};

const adaptFilterValueToIsInferredFilter = (value: any, operator: FilterOperator | null | undefined = FilterOperator.Eq) => {
  const equivalentBooleanValueIsTrue = value === 'true';
  const wildcardOperator = (operator === 'eq' && equivalentBooleanValueIsTrue)
    || (operator === 'not_eq' && !equivalentBooleanValueIsTrue)
    ? 'wildcard'
    : 'not_wildcard';
  return {
    key: ['i_rule_*'],
    values: ['*'],
    operator: wildcardOperator as FilterOperator,
  };
};

const adaptFilterToSourceReliabilityFilterKey = async (context: AuthContext, user: AuthUser, filter: Filter) => {
  const { key, mode = FilterMode.Or, operator = FilterOperator.Eq, values } = filter;
  const arrayKeys = Array.isArray(key) ? key : [key];
  if (arrayKeys[0] !== SOURCE_RELIABILITY_FILTER || arrayKeys.length > 1) {
    throw UnsupportedError('A filter with these multiple keys is not supported', { keys: arrayKeys });
  }
  // at this point arrayKey === ['source_reliability']

  let newFilter: Filter | undefined;
  let newFilterGroup: FilterGroup | undefined;

  // in case we want to filter by source reliability (reliability of author)
  // we need to find all authors filtered by reliability and filter on these authors
  const authorTypes = [
    ENTITY_TYPE_IDENTITY_INDIVIDUAL,
    ENTITY_TYPE_IDENTITY_ORGANIZATION,
    ENTITY_TYPE_IDENTITY_SYSTEM,
  ];
  const reliabilityFilter = {
    mode: FilterMode.And,
    filters: [{ key: ['x_opencti_reliability'], operator, values, mode }],
    filterGroups: [],
  };
  const opts = { types: authorTypes, filters: reliabilityFilter };
  const authors = await elList(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, opts); // the authors with reliability matching the filter
  // we construct a new filter that matches against the creator internal_id respecting the filtering
  const authorIds = authors.length > 0 ? authors.map((author) => author.internal_id) : ['<no-author-matching-filter>'];
  if (operator === 'nil' || operator === 'not_eq') {
    // the entities we want:
    // (don't have an author) OR (have an author that doesn't have a reliability if operator = 'nil' / doesn't have the right reliability if operator = 'not_eq')
    newFilterGroup = {
      mode: FilterMode.Or,
      filters: [
        {
          key: ['rel_created-by.internal_id'],
          values: authorIds, // here these authors have no reliability (if operator = 'nil') or not the right one (if operator = 'not_eq')
          mode: FilterMode.Or,
          operator: FilterOperator.Eq,
        },
        {
          key: ['rel_created-by.internal_id'],
          values: [],
          mode: FilterMode.Or,
          operator: FilterOperator.Nil,
        },
      ],
      filterGroups: [],
    };
  } else {
    // the entities we want have an author that respect the reliability filtering (= an author of the authorIds list)
    newFilter = {
      key: ['rel_created-by.internal_id'],
      values: authorIds,
      mode: FilterMode.Or,
      operator: FilterOperator.Eq,
    };
  }

  return { newFilter, newFilterGroup };
};

const adaptFilterToFromToTypesFilterKeys = (filter: Filter) => {
  const filterKey = filter.key[0];
  const side = filterKey === RELATION_FROM_TYPES_FILTER ? 'from' : 'to';
  const nested = [
    { key: 'types', operator: filter.operator, values: filter.values },
    { key: 'role', operator: 'wildcard', values: [`*_${side}`] },
  ];
  const newFilter = { key: ['connections'], nested, mode: filter.mode, values: [] };
  return { newFilter };
};

const adaptFilterToFromOrToFilterKeys = (filter: Filter) => {
  // fromOrToId and elementWithTargetTypes filters
  // are composed of a condition on fromId/fromType and a condition on toId/toType of a relationship
  const { key, operator = FilterOperator.Eq, mode = FilterMode.Or, values } = filter;
  const arrayKeys = Array.isArray(key) ? key : [key];
  if (arrayKeys.length > 1) {
    throw UnsupportedError('A filter with these multiple keys is not supported', { keys: arrayKeys });
  }
  let nestedKey;
  if (arrayKeys[0] === INSTANCE_RELATION_TYPES_FILTER) {
    nestedKey = 'types';
  } else if (arrayKeys[0] === INSTANCE_RELATION_FILTER) {
    nestedKey = 'internal_id';
  } else {
    throw UnsupportedError('A related relations filter with this key is not supported', { key: arrayKeys[0] });
  }

  let newFilterGroup: FilterGroup | undefined;
  // define mode for the filter group
  let globalMode = FilterMode.Or;
  if (operator === 'eq' || operator === 'not_nil') {
    // relatedType = malware <-> fromType = malware OR toType = malware
    // relatedType is not empty <-> fromType is not empty OR toType is not empty
    globalMode = FilterMode.Or;
  } else if (operator === 'not_eq' || operator === 'nil') {
    // relatedType != malware <-> fromType != malware AND toType != malware
    // relatedType is empty <-> fromType is empty AND toType is empty
    globalMode = FilterMode.And;
  } else {
    throw Error(`${INSTANCE_RELATION_TYPES_FILTER} filter only support 'eq', 'not_eq', 'nil' and 'not_nil' operators, not ${operator}.`);
  }
  // define the filter group
  if (operator === 'eq' || operator === 'not_eq') {
    const filterGroupsForValues = values.map((val) => {
      const nestedFrom = [
        { key: nestedKey, operator, values: [val] },
        { key: 'role', operator: FilterOperator.Wildcard, values: ['*_from'] },
      ];
      const nestedTo = [
        { key: nestedKey, operator, values: [val] },
        { key: 'role', operator: FilterOperator.Wildcard, values: ['*_to'] },
      ];
      return {
        mode: globalMode,
        filters: [{ key: ['connections'], nested: nestedFrom, mode, values: [] }, { key: ['connections'], nested: nestedTo, mode, values: [] }],
        filterGroups: [],
      };
    });
    newFilterGroup = {
      mode: mode ?? FilterMode.Or,
      filters: [],
      filterGroups: filterGroupsForValues,
    };
  } else if (operator === 'nil' || operator === 'not_nil') {
    const nestedFrom = [
      { key: nestedKey, operator, values: [] },
      { key: 'role', operator: 'wildcard', values: ['*_from'] },
    ];
    const nestedTo = [
      { key: nestedKey, operator, values: [] },
      { key: 'role', operator: 'wildcard', values: ['*_to'] },
    ];
    const innerFilters = [{ key: ['connections'], nested: nestedFrom, mode, values: [] }, { key: ['connections'], nested: nestedTo, mode, values: [] }];
    newFilterGroup = {
      mode: globalMode,
      filters: innerFilters,
      filterGroups: [],
    };
  }
  return { newFilterGroup };
};

const adaptFilterToFromToIdsFilterKeys = async (context: AuthContext, user: AuthUser, filter: Filter) => {
  const filterKey = filter.key[0];
  const isDynamic = filterKey === RELATION_DYNAMIC_FROM_FILTER || filterKey === RELATION_DYNAMIC_TO_FILTER;
  const dynamicIds = [];
  if (isDynamic) {
    const computedIndices = computeQueryIndices([], [ABSTRACT_STIX_OBJECT]);
    const targetEntities = await elPaginate(context, user, computedIndices, {
      connectionFormat: false,
      first: ES_MAX_PAGINATION,
      bypassSizeLimit: true, // ensure that max runtime prevent on ES_MAX_PAGINATION
      baseData: true,
      filters: addFilter(filter.values[0], TYPE_FILTER, [ABSTRACT_STIX_CORE_OBJECT]),
    }) as BasicStoreBase[];
    if (targetEntities.length > 0) {
      const relatedIds = targetEntities.map((n) => n.id);
      dynamicIds.push(...relatedIds);
    }
  };

  const side = filterKey === RELATION_FROM_FILTER || filterKey === RELATION_DYNAMIC_FROM_FILTER ? 'from' : 'to';
  const nested = [
    { key: 'internal_id', operator: filter.operator, values: isDynamic ? dynamicIds : filter.values },
    { key: 'role', operator: 'wildcard', values: [`*_${side}`] },
  ];
  const newFilter = { key: ['connections'], nested, mode: filter.mode, values: [] };
  return { newFilter };
};

const adaptFilterToFromToRoleFilterKeys = (filter: Filter) => {
  const filterKey = filter.key[0];
  const side = filterKey === RELATION_FROM_ROLE_FILTER ? 'from' : 'to';
  // Retro compatibility for buildAggregationRelationFilter that use fromRole depending on isTo attribute
  const values = filter.values.map((r) => (!r.endsWith('_from') && !r.endsWith('_to') ? `${r}_${side}` : r));
  const nested = [{ key: 'role', operator: filter.operator, values }];
  const newFilter = { key: ['connections'], nested, mode: filter.mode, values: [] };
  return { newFilter };
};

const adaptFilterToAliasFilterKey = (filter: Filter) => {
  const newFilterGroup = {
    mode: filter.operator === 'nil' || (filter.operator?.startsWith('not_') && filter.operator !== 'not_nil')
      ? FilterMode.And
      : FilterMode.Or,
    filters: [
      { ...filter, key: [ATTRIBUTE_ALIASES] },
      { ...filter, key: [ATTRIBUTE_ALIASES_OPENCTI] },
    ],
    filterGroups: [],
  };
  return { newFilterGroup };
};

const adaptFilterToIsInferredFilterKey = (filter: Filter) => {
  // an entity/relationship is inferred <=> a field i_rule_XX is defined, indicating the inferred rule that created the element (ex: i_rule_location_targets)
  let newFilter;
  let newFilterGroup;
  if (filter.values.length === 1) {
    const value = filter.values[0];
    newFilter = adaptFilterValueToIsInferredFilter(value, filter.operator);
  } else {
    newFilterGroup = {
      mode: filter.mode ?? FilterMode.And,
      filters: filter.values.map((v) => adaptFilterValueToIsInferredFilter(v, filter.operator)) as Filter[],
      filterGroups: [],
    };
  }
  return { newFilter, newFilterGroup };
};

const adaptFilterToPirFilterKeys = async (context: AuthContext, user: AuthUser, filterKey: string, filter: Filter) => {
  const pirIds: string[] = filter.values.find((v) => v.key === PIR_IDS_SUBFILTER)?.values ?? [];
  if (pirIds.length === 0) {
    throw FunctionalError('This filter should be related to at least 1 Pir', { filter });
  }
  // check the user has access to the PIR
  await Promise.all(pirIds.map((pirId) => getPirWithAccessCheck(context, user, pirId)));
  // push the nested pir filter associated to the given PIR IDs
  const subKey = filterKey === PIR_SCORE_FILTER ? PIR_SCORE_SUBFILTER : LAST_PIR_SCORE_DATE_SUBFILTER;
  const subFilter = filter.values.find((v) => v.key === subKey);
  const newFilter = {
    key: ['pir_information'],
    values: [],
    nested: [
      { ...subFilter, key: filterKey },
      { key: 'pir_id', values: pirIds, operator: FilterOperator.Eq },
    ],
  };
  return { newFilter, newFilterGroup: undefined };
};

const adaptFilterToServiceAccountFilterKey = (filter: Filter) => {
  const { operator, mode, values } = filter;
  let newFilter;
  let newFilterGroup;
  if (values.includes('false') && values.includes('true') && mode === FilterMode.And) {
    if (operator === FilterOperator.Eq) {
      newFilter = filter; // nothing to modify
    } else if (operator === FilterOperator.NotEq) {
      newFilterGroup = {
        mode: FilterMode.And,
        filters: [{
          key: [USER_SERVICE_ACCOUNT_FILTER],
          values: [],
          operator: FilterOperator.NotNil,
        },
        filter],
        filterGroups: [],
      };
    }
  } else if ((values.includes('false') && operator === FilterOperator.Eq)
    || (values.includes('true') && operator === FilterOperator.NotEq)) {
    // if user_service_account = false, return also users with with null user_service_account
    newFilterGroup = {
      mode: FilterMode.Or,
      filters: [{
        key: [USER_SERVICE_ACCOUNT_FILTER],
        values: [],
        operator: FilterOperator.Nil,
      },
      filter],
      filterGroups: [],
    };
  } else {
    newFilter = filter; // nothing to modify
  }
  return { newFilter, newFilterGroup };
};

const adaptFilterForMetricsFilterKeys = async (filter: Filter) => {
  const newFilter = {
    key: ['metrics'],
    mode: FilterMode.And,
    nested: [
      { key: 'name', values: [filter.key], operator: FilterOperator.Eq },
      { key: 'value', values: filter.values, operator: filter.operator, mode: filter.mode },
    ],
    values: [],
  };
  return { newFilter, newFilterGroup: undefined };
};

const adaptFilterToComputedReliabilityFilterKey = async (context: AuthContext, user: AuthUser, filter: Filter) => {
  const { key, operator = FilterOperator.Eq } = filter;
  const arrayKeys = Array.isArray(key) ? key : [key];
  if (arrayKeys[0] !== COMPUTED_RELIABILITY_FILTER || arrayKeys.length > 1) {
    throw UnsupportedError('A filter with these multiple keys is not supported', { keys: arrayKeys });
  }
  if (!['eq', 'not_eq', 'nil', 'not_nil'].includes(operator as string)) {
    throw UnsupportedError('This operator is not supported for this filter key', { keys: arrayKeys, operator });
  }
  // at this point arrayKey === ['computed_reliability']

  let newFilterGroup: FilterGroup | undefined;

  const { newFilter: sourceReliabilityFilter, newFilterGroup: sourceReliabilityFilterGroup } = await adaptFilterToSourceReliabilityFilterKey(
    context,
    user,
    { ...filter, key: [SOURCE_RELIABILITY_FILTER] },
  );
  const isConditionAdditional = operator === 'not_eq' || operator === 'nil'; // if we have one of these operators, the condition on reliability and the condition on source reliability should be both respected
  // else, (the condition on reliability should be respected) OR (reliability is empty and the condition should be respected on source_reliability)

  if (!isConditionAdditional) {
    // if !isConditionalAdditional: computed reliability filter = (reliability filter) OR (reliability is empty AND source_reliability filter)
    // // example: computed reliability filter = (reliability = A) OR (reliability is empty AND source_reliability = A)
    newFilterGroup = sourceReliabilityFilter ? {
      mode: FilterMode.Or,
      filters: [{
        ...filter,
        key: ['x_opencti_reliability'],
      }],
      filterGroups: [{
        mode: FilterMode.And,
        filters: [
          {
            key: ['x_opencti_reliability'],
            values: [],
            operator: FilterOperator.Nil,
            mode: FilterMode.Or,
          },
          sourceReliabilityFilter,
        ],
        filterGroups: [],
      }],
    } : {
      mode: FilterMode.Or,
      filters: [{
        ...filter,
        key: ['x_opencti_reliability'],
      }],
      filterGroups: [{
        mode: FilterMode.And,
        filters: [
          {
            key: ['x_opencti_reliability'],
            values: [],
            operator: FilterOperator.Nil,
            mode: FilterMode.Or,
          },
        ],
        filterGroups: sourceReliabilityFilterGroup ? [sourceReliabilityFilterGroup] : [],
      }],
    };
  } else {
    // if isConditionalAdditional: computed reliability filter = (reliability filter) AND (source_reliability filter)
    // // example: computed reliability filter = (reliability != A) AND (source_reliability != A)
    newFilterGroup = sourceReliabilityFilter ? {
      mode: FilterMode.And,
      filters: [
        {
          ...filter,
          key: ['x_opencti_reliability'],
        },
        sourceReliabilityFilter,
      ],
      filterGroups: [],
    } : {
      mode: FilterMode.And,
      filters: [{
        ...filter,
        key: ['x_opencti_reliability'],
      }],
      filterGroups: sourceReliabilityFilterGroup ? [sourceReliabilityFilterGroup] : [],
    };
  }

  return { newFilterGroup };
};
export type TaggedFilter = Filter & { postFilteringTag?: string };
export type TaggedFilterGroup = {
  mode: FilterMode;
  filters: TaggedFilter[];
  filterGroups: TaggedFilterGroup[];
};
/**
 * Complete the filter if needed for several special filter keys
 * Some keys need this preprocessing before building the query:
 * - regardingOf: we need to handle the relationship_type and the element id involved in the relationship
 * - ids: we will match the ids in filter against internal id, standard id, stix ids
 * - entity_type / relationship_type: we need to handle parent types
 * - workflow_id: handle both status and status template of the entity status
 * - source_reliability: created_by (author) can be an individual, organization or a system
 * - fromOrToId, fromId, toId, fromTypes, toTypes: for relationship, we need to create nested filters
 */
export const completeSpecialFilterKeys = async (
  context: AuthContext,
  user: AuthUser,
  inputFilters: TaggedFilterGroup,
): Promise<TaggedFilterGroup> => {
  const { filters = [], filterGroups = [] } = inputFilters;
  const finalFilters = [];
  const finalFilterGroups: TaggedFilterGroup[] = [];
  for (let index = 0; index < filterGroups.length; index += 1) {
    const filterGroup = filterGroups[index];
    const newFilterGroup = await completeSpecialFilterKeys(context, user, filterGroup);
    finalFilterGroups.push(newFilterGroup);
  }
  for (let index = 0; index < filters.length; index += 1) {
    const filter = filters[index];
    const { key } = filter;
    const arrayKeys = Array.isArray(key) ? key : [key];
    if (arrayKeys.some((filterKey) => isComplexConversionFilterKey(filterKey))) {
      if (arrayKeys.length > 1) {
        throw UnsupportedError('A filter with these multiple keys is not supported', { keys: arrayKeys });
      }
      const filterKey = arrayKeys[0];
      if (filterKey === INSTANCE_REGARDING_OF || filterKey === INSTANCE_DYNAMIC_REGARDING_OF) {
        const { newFilterGroup } = await adaptFilterToRegardingOfFilterKey(context, user, filter);
        finalFilterGroups.push(newFilterGroup);
      }
      if (filterKey === IDS_FILTER) {
        // the special filter key 'ids' take all the ids into account
        const { newFilter, newFilterGroup } = adaptFilterToIdsFilterKey(filter);
        if (newFilter) {
          finalFilters.push(newFilter);
        }
        if (newFilterGroup) {
          finalFilterGroups.push(newFilterGroup);
        }
      }
      if (filterKey === TYPE_FILTER || filterKey === RELATION_TYPE_FILTER) {
        // add parent_types checking (in case the given value in type is an abstract type)
        const { newFilter, newFilterGroup } = adaptFilterToEntityTypeFilterKey(filter);
        if (newFilter) {
          finalFilters.push(newFilter);
        }
        if (newFilterGroup) {
          finalFilterGroups.push(newFilterGroup);
        }
      }
      if (filterKey === WORKFLOW_FILTER || filterKey === X_OPENCTI_WORKFLOW_ID) {
        // in case we want to filter by status template (template of a workflow status) or status
        // we need to find all statuses filtered by status template and filter on these statuses
        const { newFilter, newFilterGroup } = await adaptFilterToWorkflowFilterKey(context, user, filter);
        if (newFilter) {
          finalFilters.push(newFilter);
        }
        if (newFilterGroup) {
          finalFilterGroups.push(newFilterGroup);
        }
      }
      if (filterKey === COMPUTED_RELIABILITY_FILTER) {
        // filter by computed reliability (reliability, or reliability of author if no reliability)
        const { newFilterGroup } = await adaptFilterToComputedReliabilityFilterKey(context, user, filter);
        if (newFilterGroup) {
          finalFilterGroups.push(newFilterGroup);
        }
      }
      if (filterKey === SOURCE_RELIABILITY_FILTER) {
        // in case we want to filter by source reliability (reliability of author)
        // we need to find all authors filtered by reliability and filter on these authors
        const { newFilter, newFilterGroup } = await adaptFilterToSourceReliabilityFilterKey(context, user, filter);
        if (newFilter) {
          finalFilters.push(newFilter);
        }
        if (newFilterGroup) {
          finalFilterGroups.push(newFilterGroup);
        }
      }
      if (filterKey === INSTANCE_RELATION_FILTER) {
        const { newFilterGroup } = adaptFilterToFromOrToFilterKeys(filter);
        if (newFilterGroup) {
          finalFilterGroups.push(newFilterGroup);
        }
      }
      if (filterKey === RELATION_FROM_FILTER || filterKey === RELATION_DYNAMIC_FROM_FILTER
        || filterKey === RELATION_TO_FILTER || filterKey === RELATION_DYNAMIC_TO_FILTER
        || filterKey === RELATION_TO_SIGHTING_FILTER) {
        const { newFilter } = await adaptFilterToFromToIdsFilterKeys(context, user, filter);
        finalFilters.push(newFilter);
      }
      if (filterKey === RELATION_FROM_TYPES_FILTER || filterKey === RELATION_TO_TYPES_FILTER) {
        const { newFilter } = adaptFilterToFromToTypesFilterKeys(filter);
        finalFilters.push(newFilter);
      }
      if (filterKey === INSTANCE_RELATION_TYPES_FILTER) {
        const { newFilterGroup } = adaptFilterToFromOrToFilterKeys(filter);
        if (newFilterGroup) {
          finalFilterGroups.push(newFilterGroup);
        }
      }
      if (filterKey === RELATION_FROM_ROLE_FILTER || filterKey === RELATION_TO_ROLE_FILTER) {
        const { newFilter } = adaptFilterToFromToRoleFilterKeys(filter);
        finalFilters.push(newFilter);
      }
      if (filterKey === 'authorized_members.id' || filterKey === 'restricted_members.id') {
        const nested = [{ key: 'id', operator: filter.operator, values: filter.values }];
        finalFilters.push({ key: [authorizedMembers.name], nested, mode: filter.mode, values: [] });
      }
      if (filterKey === ALIAS_FILTER) {
        const { newFilterGroup } = adaptFilterToAliasFilterKey(filter);
        finalFilterGroups.push(newFilterGroup);
      }
      if (filterKey === IS_INFERRED_FILTER) {
        const { newFilter, newFilterGroup } = adaptFilterToIsInferredFilterKey(filter);
        if (newFilter) {
          finalFilters.push(newFilter);
        }
        if (newFilterGroup) {
          finalFilterGroups.push(newFilterGroup);
        }
      }
      if (filterKey === PIR_SCORE_FILTER || filterKey === LAST_PIR_SCORE_DATE_FILTER) {
        const { newFilter } = await adaptFilterToPirFilterKeys(context, user, filterKey, filter);
        finalFilters.push(newFilter);
      }
      if (filterKey === USER_SERVICE_ACCOUNT_FILTER) {
        const { newFilter, newFilterGroup } = adaptFilterToServiceAccountFilterKey(filter);
        if (newFilter) {
          finalFilters.push(newFilter);
        }
        if (newFilterGroup) {
          finalFilterGroups.push(newFilterGroup);
        }
      }

      if (filterKey === BULK_SEARCH_KEYWORDS_FILTER) {
        const newFilter = {
          ...filter,
          key: BULK_SEARCH_KEYWORDS_FILTER_KEYS,
        };
        finalFilters.push(newFilter);
      }

      if (isMetricsName(filterKey)) {
        const { newFilter } = await adaptFilterForMetricsFilterKeys(filter);
        finalFilters.push(newFilter);
      }
    } else if (arrayKeys.some((filterKey) => isObjectAttribute(filterKey)) && !arrayKeys.some((filterKey) => filterKey === 'connections')) {
      if (arrayKeys.length > 1) {
        throw UnsupportedError('A filter with these multiple keys is not supported', { keys: arrayKeys });
      }
      const definition = schemaAttributesDefinition.getAttributeByName(key[0]) as ComplexAttribute;
      if (definition.format === 'standard') {
        finalFilterGroups.push({
          mode: filter.mode ?? FilterMode.And,
          filters: filter.values.map((v) => {
            const filterKeys = Array.isArray(v.key) ? v.key : [v.key];
            return { ...v, key: filterKeys.map((k: any) => `${k}.${v.key}`) };
          }),
          filterGroups: [],
        });
      } else if (definition.format === 'nested') {
        finalFilters.push({ key, operator: filter.operator, nested: filter.values, mode: filter.mode, values: [] });
      } else {
        throw UnsupportedError('Object attribute format is not filterable', { format: definition.format });
      }
    } else {
      // not a special case, leave the filter unchanged
      // Of special case but in a multi keys filter but is currently not supported
      finalFilters.push(filter);
    }
  }
  return {
    ...inputFilters,
    filters: finalFilters,
    filterGroups: finalFilterGroups,
  };
};
