import * as R from 'ramda';
import { Client } from '@elastic/elasticsearch';
import type { Client as NewTypes } from '@elastic/elasticsearch/api/new';
import type { ErrorCause, MappingRuntimeFields, SearchHit } from '@elastic/elasticsearch/api/types';
import { cursorToOffset, isEmptyField, isNotEmptyField, READ_ENTITIES_INDICES } from './utils';
import {
  BASE_TYPE_RELATION,
  buildRefRelationKey,
  buildRefRelationSearchKey,
  ENTITY_TYPE_IDENTITY,
  ID_INTERNAL,
  ID_STANDARD,
  IDS_STIX, REL_INDEX_PREFIX,
  RULE_PREFIX
} from '../schema/general';
import { dateAttributes, isRuntimeAttribute, numericOrBooleanAttributes } from '../schema/fieldDataAdapter';
import { DatabaseError, UnsupportedError } from '../config/errors';
import { logApp } from '../config/conf';
import {
  elGenerateFullTextSearchShould,
  ES_IGNORE_THROTTLED,
  ES_MAX_PAGINATION,
  isRuntimeSortEnable,
} from './engine';
import { BYPASS } from '../utils/access';
import { RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';
import type { AuthUser } from '../types/user';
import { runtimeFieldObservableValueScript } from '../utils/format';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import type {
  StoreConnection,
  BasicStoreEntity,
  BasicStoreObject,
  StoreRawRelation, BasicStoreRelation,
  StoreRuntimeAttribute, StoreRawRule
} from '../types/store';

interface paginateFilters {
  ids?: Array<string>;
  first?: number;
  after?: string;
  orderBy?: string;
  orderMode?: 'asc' | 'desc';
  types?: Array<string>;
  filterMode?: 'and' | 'or';
  search?: string;
  connectionFormat?: boolean;
  filters?: Array<{
    key:string;
    operator?:string;
    filterMode?: 'and' | 'or';
    // eslint-disable-next-line
    values?: Array<any>;
    nested?: Array<{
      key:string,
      // eslint-disable-next-line
      values: Array<any>
      operator?:string;
    }>
  }>;
}

const MAX_SEARCH_SIZE = 5000;
export const RUNTIME_ATTRIBUTES: StoreRuntimeAttribute = {
  observable_value: {
    field: 'observable_value.keyword',
    type: 'keyword',
    getSource: async () => runtimeFieldObservableValueScript(),
    getParams: async () => undefined,
  },
  createdBy: {
    field: 'createdBy.keyword',
    type: 'keyword',
    getSource: async () => `
        if (doc.containsKey('rel_created-by.internal_id')) {
          def creatorId = doc['rel_created-by.internal_id.keyword'];
          if (creatorId.size() == 1) {
            def creatorName = params[creatorId[0]];
            emit(creatorName != null ? creatorName : 'Unknown')
          } else {
            emit('Unknown')
          }
        } else {
          emit('Unknown')
        }
    `,
    getParams: async (user: AuthUser) => {
      // eslint-disable-next-line @typescript-eslint/no-use-before-define
      const identities = await elPaginate(user, READ_ENTITIES_INDICES, {
        types: [ENTITY_TYPE_IDENTITY],
        first: MAX_SEARCH_SIZE,
        connectionFormat: false,
      });
      return R.mergeAll(identities.map((i) => ({ [i.internal_id]: i.name })));
    },
  },
  objectMarking: {
    field: 'objectMarking.keyword',
    type: 'keyword',
    getSource: async () => `
        if (doc.containsKey('rel_object-marking.internal_id')) {
          def markingId = doc['rel_object-marking.internal_id.keyword'];
          if (markingId.size() >= 1) {
            def markingName = params[markingId[0]];
            emit(markingName != null ? markingName : 'Unknown')
          } else {
            emit('Unknown')
          }
        } else {
          emit('Unknown')
        }
    `,
    getParams: async (user: AuthUser) => {
      // eslint-disable-next-line @typescript-eslint/no-use-before-define
      const identities = await elPaginate(user, READ_ENTITIES_INDICES, {
        types: [ENTITY_TYPE_MARKING_DEFINITION],
        first: MAX_SEARCH_SIZE,
        connectionFormat: false,
      }) as unknown as Array<BasicStoreEntity>;
      return R.mergeAll(identities.map((i) => ({ [i.internal_id]: i.definition })));
    },
  },
};

const elMergeRelation = (concept: StoreRawRelation, fromConnection: StoreConnection | undefined, toConnection: StoreConnection | undefined): BasicStoreRelation => {
  if (!fromConnection || !toConnection) {
    throw DatabaseError('[ELASTIC] Something fail in reconstruction of the relation', concept.internal_id);
  }
  return {
    ...concept,
    // from
    from: undefined,
    fromId: fromConnection.internal_id,
    fromRole: fromConnection.role,
    fromType: R.head(fromConnection.types),
    // to
    to: undefined,
    toId: toConnection.internal_id,
    toRole: toConnection.role,
    toType: R.head(toConnection.types),
  };
};
const elRebuildRelation = (concept: StoreRawRelation): BasicStoreRelation => {
  const { connections } = concept;
  const entityType = concept.entity_type;
  const fromConnection = R.find((connection) => connection.role === `${entityType}_from`, connections);
  const toConnection = R.find((connection) => connection.role === `${entityType}_to`, connections);
  const relation = elMergeRelation(concept, fromConnection, toConnection);
  relation.relationship_type = relation.entity_type;
  return relation;
};
const elDataConverter = (esHit: SearchHit<BasicStoreObject>): BasicStoreObject => {
  const elementData: BasicStoreObject | undefined = esHit._source;
  if (!elementData) {
    throw UnsupportedError('Cannot converted not found element');
  }
  // If relation, convert the connections
  const isRelation = elementData.base_type === BASE_TYPE_RELATION;
  const data = isRelation ? elRebuildRelation(elementData as StoreRawRelation) : elementData;
  // region rules generation
  const entries = Object.entries(data);
  const ruleInferences = [];
  for (let index = 0; index < entries.length; index += 1) {
    const [key, val] = entries[index];
    if (key.startsWith(RULE_PREFIX)) {
      const rule = key.substring(RULE_PREFIX.length);
      const ruleDefinitions = Object.values(val) as unknown as Array<StoreRawRule>;
      for (let rIndex = 0; rIndex < ruleDefinitions.length; rIndex += 1) {
        const { inferred, explanation } = ruleDefinitions[rIndex];
        const attributes = R.toPairs(inferred).map((s) => ({ field: R.head(s), value: String(R.last(s)) }));
        ruleInferences.push({ rule, explanation, attributes });
      }
    } else if (key.startsWith(REL_INDEX_PREFIX)) {
      // Rebuild rel to stix attributes
      // const rel = key.substring(REL_INDEX_PREFIX.length);
      // const [relType] = rel.split('.');
      // const relData = isSingleStixEmbeddedRelationship(relType) ? R.head(val) : val;
      // if (isStixDomainObject())
      // if (relType === RELATION_OBJECT_MARKING) {
      //   data.object_marking_ids = relData;
      // }
    }
  }
  if (ruleInferences.length > 0) {
    data.x_opencti_inferences = ruleInferences;
  }
  // endregion
  return data;
};

const buildMarkingRestriction = (user: AuthUser) => {
  const must = [];
  // eslint-disable-next-line camelcase
  const must_not = [];
  // Check user rights
  const isBypass = R.find((s) => s.name === BYPASS, user.capabilities || []) !== undefined;
  if (!isBypass) {
    if (user.allowed_marking.length === 0) {
      // If user have no marking, he can only access to data with no markings.
      must_not.push({ exists: { field: buildRefRelationKey(RELATION_OBJECT_MARKING) } });
    } else {
      // Markings should be group by types for restriction
      const userGroupedMarkings = R.groupBy((m) => m.definition_type, user.allowed_marking);
      const allGroupedMarkings = R.groupBy((m) => m.definition_type, user.all_marking);
      const markingGroups = Object.keys(allGroupedMarkings);
      const mustNotHaveOneOf = [];
      for (let index = 0; index < markingGroups.length; index += 1) {
        const markingGroup = markingGroups[index];
        const markingsForGroup = allGroupedMarkings[markingGroup].map((i) => i.internal_id);
        const userMarkingsForGroup = (userGroupedMarkings[markingGroup] || []).map((i) => i.internal_id);
        // Get all markings the user has no access for this group
        const res = markingsForGroup.filter((m) => !userMarkingsForGroup.includes(m));
        if (res.length > 0) {
          mustNotHaveOneOf.push(res);
        }
      }
      // If use have marking, he can access to data with no marking && data with according marking
      const mustNotMarkingTerms = [];
      for (let i = 0; i < mustNotHaveOneOf.length; i += 1) {
        const markings = mustNotHaveOneOf[i];
        const should = markings.map((m) => ({ match: { [buildRefRelationSearchKey(RELATION_OBJECT_MARKING)]: m } }));
        mustNotMarkingTerms.push({
          bool: {
            should,
            minimum_should_match: 1,
          },
        });
      }
      const markingBool = {
        bool: {
          should: [
            {
              bool: {
                must_not: [{ exists: { field: buildRefRelationSearchKey(RELATION_OBJECT_MARKING) } }],
              },
            },
            {
              bool: {
                must_not: mustNotMarkingTerms,
              },
            },
          ],
          minimum_should_match: 1,
        },
      };
      must.push(markingBool);
    }
  }
  return { must, must_not };
};

// @ts-expect-error @elastic/elasticsearch
const client: NewTypes = new Client({ node: 'http://localhost:9200' });

export const elPaginate = async (user: AuthUser, indexName: string | Array<string>, options: paginateFilters = {}) : Promise<Array<BasicStoreObject>> => {
  // eslint-disable-next-line no-use-before-define
  const { ids = [], first = 200, after, orderBy = null, orderMode = 'asc' } = options;
  // noinspection JSUnusedLocalSymbols
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { types = null, filters = [], filterMode = 'and', search = null, connectionFormat = true } = options;
  const searchAfter = after ? cursorToOffset(after) : null;
  let must: Array<object> = [];
  let mustnot: Array<object> = [];
  let ordering: Array<{ [k: string]: 'asc' | 'desc' } > = [];
  const markingRestrictions = buildMarkingRestriction(user);
  must.push(...markingRestrictions.must);
  mustnot.push(...markingRestrictions.must_not);
  if (ids.length > 0) {
    const idsTermsPerType = [];
    const elementTypes = [ID_INTERNAL, ID_STANDARD, IDS_STIX];
    for (let i = 0; i < ids.length; i += 1) {
      const id = ids[i];
      for (let indexType = 0; indexType < elementTypes.length; indexType += 1) {
        const elementType = elementTypes[indexType];
        const term = { [`${elementType}.keyword`]: id };
        idsTermsPerType.push({ term });
      }
    }
    must = R.append({ bool: { should: idsTermsPerType, minimum_should_match: 1 } }, must);
  }
  if (types !== null && types.length > 0) {
    const should = R.flatten(
      types.map((typeValue) => {
        return [
          { match_phrase: { 'entity_type.keyword': typeValue } },
          { match_phrase: { 'parent_types.keyword': typeValue } },
        ];
      })
    );
    must = R.append({ bool: { should, minimum_should_match: 1 } }, must);
  }
  let mustFilters: Array<object> = [];
  const validFilters = (filters || []).filter((f) => (f?.values ?? []).length > 0 || (f?.nested ?? []).length > 0);
  if (validFilters.length > 0) {
    for (let index = 0; index < validFilters.length; index += 1) {
      const valuesFiltering = [];
      const { key, values, nested, operator = 'eq', filterMode: localFilterMode = 'or' } = validFilters[index];
      if (nested) {
        const nestedMust = [];
        for (let nestIndex = 0; nestIndex < nested.length; nestIndex += 1) {
          const nestedElement = nested[nestIndex];
          const { key: nestedKey, values: nestedValues, operator: nestedOperator = 'eq' } = nestedElement;
          const nestedShould = [];
          for (let i = 0; i < nestedValues.length; i += 1) {
            if (nestedOperator === 'wildcard') {
              nestedShould.push({
                query_string: {
                  query: `${nestedValues[i].toString()}`,
                  fields: [`${key}.${nestedKey}`],
                },
              });
            } else {
              nestedShould.push({
                match_phrase: { [`${key}.${nestedKey}`]: nestedValues[i].toString() },
              });
            }
          }
          const should = {
            bool: {
              should: nestedShould,
              minimum_should_match: localFilterMode === 'or' ? 1 : nestedShould.length,
            },
          };
          nestedMust.push(should);
        }
        const nestedQuery = {
          path: key,
          query: {
            bool: {
              must: nestedMust,
            },
          },
        };
        mustFilters = R.append({ nested: nestedQuery }, mustFilters);
      } else if (values) {
        for (let i = 0; i < values.length; i += 1) {
          if (values[i] === null) {
            mustnot = R.append({ exists: { field: key } }, mustnot);
          } else if (values[i] === 'EXISTS') {
            valuesFiltering.push({ exists: { field: key } });
          } else if (operator === 'eq') {
            const isDateOrNumber = dateAttributes.includes(key) || numericOrBooleanAttributes.includes(key);
            valuesFiltering.push({
              match_phrase: { [`${isDateOrNumber ? key : `${key}.keyword`}`]: values[i].toString() },
            });
          } else if (operator === 'match') {
            valuesFiltering.push({
              match_phrase: { [key]: values[i].toString() },
            });
          } else if (operator === 'wildcard') {
            valuesFiltering.push({
              query_string: {
                query: `"${values[i].toString()}"`,
                fields: [key],
              },
            });
          } else {
            valuesFiltering.push({ range: { [key]: { [operator]: values[i] } } });
          }
        }
        mustFilters = R.append(
          {
            bool: {
              should: valuesFiltering,
              minimum_should_match: localFilterMode === 'or' ? 1 : valuesFiltering.length,
            },
          },
          mustFilters
        );
      }
    }
  }
  if (filterMode === 'or') {
    must = R.append({ bool: { should: mustFilters, minimum_should_match: 1 } }, must);
  } else {
    must = [...must, ...mustFilters];
  }
  if (search !== null && search.length > 0) {
    const shouldSearch = elGenerateFullTextSearchShould(search);
    const bool = {
      bool: {
        should: shouldSearch,
        minimum_should_match: 1,
      },
    };
    must = R.append(bool, must);
  }
  // Handle orders
  if (isNotEmptyField(orderBy)) {
    const orderCriterion = Array.isArray(orderBy) ? orderBy : [orderBy];
    for (let index = 0; index < orderCriterion.length; index += 1) {
      const orderCriteria = orderCriterion[index];
      const isDateOrNumber = dateAttributes.includes(orderCriteria) || numericOrBooleanAttributes.includes(orderCriteria);
      const orderKeyword = isDateOrNumber ? orderCriteria : `${orderCriteria}.keyword`;
      const order = { [orderKeyword]: orderMode };
      ordering = R.append(order, ordering);
      must = R.append({ exists: { field: orderKeyword } }, must);
    }
    // Add standard_id if not specify to ensure ordering uniqueness
    if (!orderCriterion.includes('standard_id')) {
      ordering.push({ 'standard_id.keyword': 'asc' });
    }
  } else if (search !== null && search.length > 0) {
    ordering.push({ _score: 'desc' });
  } else { // If not ordering criteria, order by standard_id
    ordering.push({ 'standard_id.keyword': 'asc' });
  }
  // Build runtime mappings
  const runtimeMappings: MappingRuntimeFields = {};
  if (orderBy && isRuntimeAttribute(orderBy)) {
    const runtime = RUNTIME_ATTRIBUTES[orderBy];
    if (isEmptyField(runtime)) {
      throw UnsupportedError(`Unsupported runtime field ${orderBy}`);
    }
    const source = await runtime.getSource();
    const params = await runtime.getParams(user);
    runtimeMappings[runtime.field] = {
      type: runtime.type,
      script: { source, params },
    };
  }
  // Build query
  // Add extra configuration
  const querySize = first || 10;
  if (isNotEmptyField(runtimeMappings)) {
    const isRuntimeSortFeatureEnable = isRuntimeSortEnable();
    if (!isRuntimeSortFeatureEnable) {
      throw UnsupportedError(`Sorting of field ${orderBy} is only possible with elastic >=7.12`);
    }
    // query.body.runtime_mappings = runtimeMappings;
  }
  if (querySize > ES_MAX_PAGINATION) {
    const message = `You cannot ask for more than ${ES_MAX_PAGINATION} results. If you need more, please use pagination`;
    throw DatabaseError(message);
  }
  const query = {
    index: indexName,
    ignore_throttled: ES_IGNORE_THROTTLED,
    track_total_hits: true,
    body: {
      size: querySize,
      sort: ordering,
      runtime_mappings: runtimeMappings,
      search_after: searchAfter,
      query: {
        bool: {
          must,
          must_not: mustnot,
        },
      }
    }
  };

  logApp.debug('[SEARCH ENGINE] paginate', { query });

  return client.search<BasicStoreObject>(query).then((data) => {
    const { hits } = data.body.hits;
    const convertedHits = hits.map((n: SearchHit<BasicStoreObject>) => elDataConverter(n));
    // if (connectionFormat) {
    //   const nodeHits = R.map((n) => ({ node: n, sort: n.sort }), convertedHits);
    //   return buildPagination(first, searchAfter, nodeHits, data.body.hits.total.value);
    // }
    return convertedHits;
  }).catch(
    /* istanbul ignore next */ (err) => {
      // Because we create the mapping at element creation
      // We log the error only if its not a mapping not found error
      const rootCauses: ErrorCause[] = err.meta.body.error.root_cause;
      const numberOfCauses = rootCauses.length;
      const invalidMappingCauses = rootCauses.map((r) => r.reason)
        .filter((r) => R.includes('No mapping found for', r) || R.includes('no such index', r));
      // If uncontrolled error, log and propagate
      if (numberOfCauses > invalidMappingCauses.length) {
        logApp.error('[SEARCH ENGINE] Paginate fail', { error: err, query });
        throw err;
      } else {
        // return connectionFormat ? buildPagination(0, null, [], 0) : [];
      }
      return [];
    }
  );
};
