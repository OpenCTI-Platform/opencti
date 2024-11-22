import * as R from 'ramda';
import { getEntityFromCache } from './cache';
import { booleanConf } from '../config/conf';
import { FunctionalError, UnsupportedError } from '../config/errors';
import { iAliasedIds, internalId, standardId, xOpenctiStixIds } from '../schema/attribute-definition';
import { buildRefRelationKey, buildRefRelationSearchKey, ID_INTERNAL, ID_STANDARD, IDS_STIX, isAbstract } from '../schema/general';
import { ENTITY_TYPE_SETTINGS, isInternalObject } from '../schema/internalObject';
import {
  ATTRIBUTE_ABSTRACT,
  ATTRIBUTE_DESCRIPTION,
  ATTRIBUTE_DESCRIPTION_OPENCTI,
  ATTRIBUTE_EXPLANATION,
  ATTRIBUTE_NAME,
  isStixDomainObject,
  STIX_ORGANIZATIONS_RESTRICTED,
  STIX_ORGANIZATIONS_UNRESTRICTED
} from '../schema/stixDomainObject';
import { isStixRefRelationship, RELATION_CREATED_BY, RELATION_GRANTED_TO, RELATION_OBJECT_MARKING, STIX_REF_RELATIONSHIP_TYPES } from '../schema/stixRefRelationship';
import { BYPASS, computeUserMemberAccessIds, INTERNAL_USERS, isBypassUser, MEMBER_ACCESS_ALL } from '../utils/access';
import { isDateNumericOrBooleanAttribute, isObjectFlatAttribute, schemaAttributesDefinition } from '../schema/schema-attributes';
import {
  inferIndexFromConceptType,
  isEmptyField,
  isNotEmptyField,
  READ_DATA_INDICES,
  READ_ENTITIES_INDICES,
  READ_INDEX_INFERRED_ENTITIES,
  READ_INDEX_INFERRED_RELATIONSHIPS,
  READ_INDEX_INTERNAL_OBJECTS,
  READ_INDEX_INTERNAL_RELATIONSHIPS,
  READ_INDEX_STIX_CORE_RELATIONSHIPS,
  READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS,
  READ_INDEX_STIX_CYBER_OBSERVABLES,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_INDEX_STIX_META_OBJECTS,
  READ_INDEX_STIX_META_RELATIONSHIPS,
  READ_INDEX_STIX_SIGHTING_RELATIONSHIPS,
  READ_RELATIONSHIPS_INDICES
} from './utils';
import { isFilterGroupNotEmpty } from '../utils/filtering/filtering-utils';
import { isBasicObject, isStixCoreObject, isStixObject } from '../schema/stixCoreObject';
import { isStixMetaObject } from '../schema/stixMetaObject';
import { isBasicRelationship, isStixRelationship } from '../schema/stixRelationship';
import { isInternalRelationship } from '../schema/internalRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';

export const buildTypesBoolQuery = (types) => {
  if (types && types.length > 0) {
    const shouldType = {
      bool: {
        should: [
          { terms: { 'entity_type.keyword': types } },
          { terms: { 'parent_types.keyword': types } }
        ],
        minimum_should_match: 1,
      },
    };
    return shouldType;
  }
  return null;
};

export const buildIdsBoolQuery = (ids) => {
  if (!ids || ids.length === 0) {
    return null;
  }
  const idsTermsPerType = [];
  const elementTypes = [internalId.name, standardId.name, xOpenctiStixIds.name, iAliasedIds.name];
  for (let indexType = 0; indexType < elementTypes.length; indexType += 1) {
    const elementType = elementTypes[indexType];
    const terms = { [`${elementType}.keyword`]: ids };
    idsTermsPerType.push({ terms });
  }
  const should = {
    bool: {
      should: idsTermsPerType,
      minimum_should_match: 1,
    },
  };
  return should;
};

// region data restrictions
const buildUserMemberAccessFilter = (user, opts) => {
  const { includeAuthorities = false, excludeEmptyAuthorizedMembers = false } = opts;
  const capabilities = user.capabilities.map((c) => c.name);
  if (includeAuthorities && capabilities.includes(BYPASS)) {
    return [];
  }
  const userAccessIds = computeUserMemberAccessIds(user);
  // if access_users exists, it should have the user access ids
  const emptyAuthorizedMembers = { bool: { must_not: { exists: { field: 'authorized_members' } } } };
  const authorizedFilters = [
    { terms: { 'authorized_members.id.keyword': [MEMBER_ACCESS_ALL, ...userAccessIds] } },
  ];
  if (!excludeEmptyAuthorizedMembers) {
    authorizedFilters.push(emptyAuthorizedMembers);
  }
  if (includeAuthorities) {
    const roleIds = user.roles.map((r) => r.id);
    const owners = [...userAccessIds, ...capabilities, ...roleIds];
    authorizedFilters.push({ terms: { 'authorized_authorities.keyword': owners } });
  }
  return [{ bool: { should: authorizedFilters } }];
};

export const buildDataRestrictions = async (context, user, opts = {}) => {
  const must = [];
  // eslint-disable-next-line camelcase
  const must_not = [];
  // If internal users of the system, we cancel rights checking
  if (INTERNAL_USERS[user.id]) {
    return { must, must_not };
  }
  // check user access
  must.push(...buildUserMemberAccessFilter(user, { includeAuthorities: opts?.includeAuthorities }));
  // If user have bypass, no need to check restrictions
  if (!isBypassUser(user)) {
    // region Handle marking restrictions
    if (user.allowed_marking.length === 0) {
      // If user have no marking, he can only access to data with no markings.
      must_not.push({ exists: { field: buildRefRelationKey(RELATION_OBJECT_MARKING) } });
    } else {
      // Markings should be grouped by types for restriction
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
    // endregion
    // region Handle organization restrictions
    // If user have organization management role, he can bypass this restriction.
    // If platform is for specific organization, only user from this organization can access empty defined
    const settings = await getEntityFromCache(context, user, ENTITY_TYPE_SETTINGS);
    // We want to exlucde a set of entities from organization restrictions while forcing restrictions for an other set of entities
    const excludedEntityMatches = {
      bool: {
        must: [
          {
            bool: { must_not: [{ terms: { 'entity_type.keyword': STIX_ORGANIZATIONS_RESTRICTED } }] }
          },
          {
            bool: {
              should: [
                { terms: { 'parent_types.keyword': STIX_ORGANIZATIONS_UNRESTRICTED } },
                { terms: { 'entity_type.keyword': STIX_ORGANIZATIONS_UNRESTRICTED } }
              ],
              minimum_should_match: 1
            }
          }
        ]
      }
    };
    if (settings.platform_organization) {
      if (user.inside_platform_organization) {
        // Data are visible independently of the organizations
        // Nothing to restrict.
      } else {
        // Data with Empty granted_refs are not visible
        // Data with granted_refs users that participate to at least one
        const should = [excludedEntityMatches];
        const shouldOrgs = user.allowed_organizations
          .map((m) => ({ match: { [buildRefRelationSearchKey(RELATION_GRANTED_TO)]: m.internal_id } }));
        should.push(...shouldOrgs);
        // User individual or data created by this individual must be accessible
        if (user.individual_id) {
          should.push({ match: { 'internal_id.keyword': user.individual_id } });
          should.push({ match: { [buildRefRelationSearchKey(RELATION_CREATED_BY)]: user.individual_id } });
        }
        // For tasks
        should.push({ match: { 'initiator_id.keyword': user.internal_id } });
        // Access to authorized members
        should.push(...buildUserMemberAccessFilter(user, { includeAuthorities: opts?.includeAuthorities, excludeEmptyAuthorizedMembers: true }));
        // Finally build the bool should search
        must.push({ bool: { should, minimum_should_match: 1 } });
      }
    }
    // endregion
  }
  return { must, must_not };
};
// end region

// region search
export const ES_DEFAULT_WILDCARD_PREFIX = booleanConf('elasticsearch:search_wildcard_prefix', false);
export const ES_DEFAULT_FUZZY = booleanConf('elasticsearch:search_fuzzy', false);
// Global search attributes are limited
// Its due to opensearch / elastic limitations
const BASE_SEARCH_CONNECTIONS = [
  // Pounds for connections search
  `connections.${ATTRIBUTE_NAME}^4`,
  // Add all other attributes
  'connections.*',
];
const BASE_SEARCH_ATTRIBUTES = [
  // Pounds for attributes search
  `${ATTRIBUTE_NAME}^5`,
  `${ATTRIBUTE_ABSTRACT}^5`,
  `${ATTRIBUTE_EXPLANATION}^5`,
  `${ID_INTERNAL}^5`,
  `${ID_STANDARD}^5`,
  `${IDS_STIX}^5`,
  `${ATTRIBUTE_DESCRIPTION}^2`,
  `${ATTRIBUTE_DESCRIPTION_OPENCTI}^2`,
  // For activities
  'event_type',
  'event_scope',
  'context_data.message',
  // Add all other attributes
  'aliases',
  'x_opencti_aliases',
  'persona_name',
  'roles',
  'objective',
  'content',
  'content_mapping',
  'explanation',
  'opinion',
  'x_mitre_id',
  'x_opencti_threat_hunting',
  'x_opencti_log_sources',
  'postal_code',
  'street_address',
  'source',
  'context',
  'pattern',
  'path',
  'value',
  'display_name',
  'body',
  'hashes.MD5',
  'hashes.SHA-1',
  'hashes.SHA-256',
  'hashes.SHA-512',
  'hashes.SHA3-256',
  'hashes.SHA3-512',
  'hashes.SSDEEP',
  'hashes.SDHASH',
  'hashes.TLSH',
  'hashes.LZJD',
  'url',
  'subject',
  'payload_bin',
  'x_opencti_additional_names',
  'serial_number',
  'issuer',
  'cwd',
  'command_line',
  'cpe',
  'swid',
  'iban',
  'bic',
  'account_number',
  'card_number',
  'holder_name',
  'title',
  'result_name',
  'phase_name',
  'kill_chain_name',
  'definition',
  'definition_type',
  'user_email',
  'main_entity_name', // deletedOperation
];
export const specialElasticCharsEscape = (query) => {
  return query.replace(/([/+|\-*()^~={}[\]:?!"\\])/g, '\\$1');
};
function processSearch(search, args) {
  const { useWildcardPrefix = ES_DEFAULT_WILDCARD_PREFIX } = args;
  let decodedSearch;
  try {
    decodedSearch = decodeURIComponent(search)
      .trim();
  } catch (e) {
    decodedSearch = search.trim();
  }
  let remainingSearch = decodedSearch;
  const exactSearch = (decodedSearch.match(/"[^"]+"/g) || []) //
    .filter((e) => isNotEmptyField(e.replace(/"/g, '')
      .trim()));
  for (let index = 0; index < exactSearch.length; index += 1) {
    remainingSearch = remainingSearch.replace(exactSearch[index], '');
  }
  const querySearch = [];

  const partialSearch = remainingSearch.replace(/"/g, '')
    .trim()
    .split(' ');

  for (let searchIndex = 0; searchIndex < partialSearch.length; searchIndex += 1) {
    const partialElement = partialSearch[searchIndex];
    const cleanElement = specialElasticCharsEscape(partialElement);
    if (isNotEmptyField(cleanElement)) {
      querySearch.push(`${useWildcardPrefix ? '*' : ''}${cleanElement}*`);
      if (ES_DEFAULT_FUZZY) {
        querySearch.push(`${cleanElement}~`);
      }
    }
  }
  return {
    exactSearch,
    querySearch
  };
}

export const elGenerateFullTextSearchShould = (search, args = {}) => {
  const { exactSearch, querySearch } = processSearch(search, args);
  // Return the elastic search engine expected bool should terms
  // Build the search for all exact match (between double quotes)
  const shouldSearch = [];
  const cleanExactSearch = R.uniq(exactSearch.map((e) => e.replace(/"|http?:/g, '')));
  shouldSearch.push(
    ...cleanExactSearch.map((ex) => [
      {
        multi_match: {
          type: 'phrase',
          query: ex,
          lenient: true,
          fields: BASE_SEARCH_ATTRIBUTES,
        },
      },
      {
        nested: {
          path: 'connections',
          query: {
            bool: {
              must: [
                {
                  multi_match: {
                    type: 'phrase',
                    query: ex,
                    lenient: true,
                    fields: BASE_SEARCH_CONNECTIONS,
                  },
                },
              ],
            },
          },
        },
      },
    ]).flat()
  );
  // Build the search for all other fields
  const searchPhrase = R.uniq(querySearch).join(' ');
  if (searchPhrase) {
    shouldSearch.push(...[
      {
        query_string: {
          query: searchPhrase,
          analyze_wildcard: true,
          fields: BASE_SEARCH_ATTRIBUTES,
        },
      },
      {
        multi_match: {
          type: 'phrase',
          query: searchPhrase,
          lenient: true,
          fields: BASE_SEARCH_ATTRIBUTES,
        },
      },
      {
        nested: {
          path: 'connections',
          query: {
            bool: {
              must: [
                {
                  query_string: {
                    query: searchPhrase,
                    analyze_wildcard: true,
                    fields: BASE_SEARCH_CONNECTIONS,
                  },
                },
              ],
            },
          },
        },
      },
    ]);
  }
  return shouldSearch;
};

export const elGenerateFieldTextSearchShould = (search, arrayKeys, args = {}) => {
  const { exactSearch, querySearch } = processSearch(search, args);
  const cleanExactSearch = R.uniq(exactSearch.map((e) => e.replace(/"|http?:/g, '')));
  const shouldSearch = [];
  shouldSearch.push(
    ...cleanExactSearch.map((ex) => [
      {
        multi_match: {
          type: 'phrase',
          query: ex,
          lenient: true,
          fields: arrayKeys,
        },
      }
    ]).flat()
  );
  // Build the search for all other fields
  const searchPhrase = R.uniq(querySearch).join(' ');
  if (searchPhrase) {
    shouldSearch.push(...[
      {
        query_string: {
          query: searchPhrase,
          analyze_wildcard: true,
          fields: arrayKeys,
        },
      },
      {
        multi_match: {
          type: 'phrase',
          query: searchPhrase,
          lenient: true,
          fields: arrayKeys,
        },
      }
    ]);
  }

  return shouldSearch;
};

export const buildFieldForQuery = (field) => {
  return isDateNumericOrBooleanAttribute(field) || field === '_id' || isObjectFlatAttribute(field)
    ? field
    : `${field}.keyword`;
};

// region filters
const RANGE_OPERATORS = ['gt', 'gte', 'lt', 'lte'];

const buildLocalMustFilter = async (validFilter) => {
  const valuesFiltering = [];
  const noValuesFiltering = [];
  const { key, values, nested, operator = 'eq', mode: localFilterMode = 'or' } = validFilter;
  if (isEmptyField(key)) {
    throw FunctionalError('A filter key must be defined', { key });
  }
  const arrayKeys = Array.isArray(key) ? key : [key];
  const headKey = R.head(arrayKeys);
  const dontHandleMultipleKeys = nested || operator === 'nil' || operator === 'not_nil';
  if (dontHandleMultipleKeys && arrayKeys.length > 1) {
    throw UnsupportedError('Filter must have only one field', { keys: arrayKeys, operator });
  }
  // 01. Handle nested filters
  // TODO IF KEY is PART OF Rule we need to add extra fields search
  // TODO Add connections like filters to have native fromId, toId filters handling.
  // See opencti-front\src\private\components\events\StixSightingRelationships.tsx
  if (nested) {
    const nestedMust = [];
    const nestedMustNot = [];
    for (let nestIndex = 0; nestIndex < nested.length; nestIndex += 1) {
      const nestedElement = nested[nestIndex];
      const parentKey = arrayKeys.at(0);
      const { key: nestedKey, values: nestedValues, operator: nestedOperator = 'eq' } = nestedElement;
      const nestedShould = [];
      const nestedFieldKey = `${parentKey}.${nestedKey}`;
      if (nestedKey === ID_INTERNAL) {
        if (nestedOperator === 'nil') {
          nestedMustNot.push({
            exists: {
              field: nestedFieldKey
            }
          });
        } else if (nestedOperator === 'not_nil') {
          nestedShould.push({
            exists: {
              field: nestedFieldKey
            }
          });
        } else if (nestedOperator === 'not_eq') {
          nestedMustNot.push({ terms: { [`${nestedFieldKey}.keyword`]: nestedValues } });
        } else { // nestedOperator = 'eq'
          nestedShould.push({ terms: { [`${nestedFieldKey}.keyword`]: nestedValues } });
        }
      } else { // nested key !== internal_id
        // eslint-disable-next-line no-lonely-if
        if (nestedOperator === 'nil') {
          nestedMustNot.push({
            exists: {
              field: nestedFieldKey
            }
          });
        } else if (nestedOperator === 'not_nil') {
          nestedShould.push({
            exists: {
              field: nestedFieldKey
            }
          });
        } else {
          for (let i = 0; i < nestedValues.length; i += 1) {
            const nestedSearchValue = nestedValues[i].toString();
            if (nestedOperator === 'wildcard') {
              nestedShould.push({ query_string: { query: `${nestedSearchValue}`, fields: [nestedFieldKey] } });
            } else if (nestedOperator === 'not_eq') {
              nestedMustNot.push({
                multi_match: {
                  fields: buildFieldForQuery(nestedFieldKey),
                  query: nestedSearchValue.toString(),
                }
              });
            } else if (RANGE_OPERATORS.includes(nestedOperator)) {
              nestedShould.push({ range: { [nestedFieldKey]: { [nestedOperator]: nestedSearchValue } } });
            } else { // nestedOperator = 'eq'
              nestedShould.push({
                multi_match: {
                  fields: buildFieldForQuery(nestedFieldKey),
                  query: nestedSearchValue.toString(),
                }
              });
            }
          }
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
      path: headKey,
      query: {
        bool: {
          must: nestedMust,
          must_not: nestedMustNot,
        },
      },
    };
    return { nested: nestedQuery };
  }
  // 02. Handle nil and not_nil operators
  if (operator === 'nil') {
    const filterDefinition = schemaAttributesDefinition.getAttributeByName(headKey);
    let valueFiltering = { // classic filters: field doesn't exist
      bool: {
        must_not: {
          exists: {
            field: headKey
          }
        }
      }
    };
    if (filterDefinition?.type === 'string') {
      if (filterDefinition?.format === 'text') { // text filters: use wildcard
        valueFiltering = {
          bool: {
            must_not: {
              wildcard: {
                [headKey]: '*'
              }
            },
          }
        };
      } else { // string filters: nil <-> (field doesn't exist) OR (field = empty string)
        valueFiltering = {
          bool: {
            should: [
              {
                bool: {
                  must_not: {
                    exists: {
                      field: headKey
                    }
                  }
                }
              },
              {
                term: {
                  [headKey === '_id' ? headKey : `${headKey}.keyword`]: { value: '' },
                },
              },
            ],
            minimum_should_match: 1,
          }
        };
      }
    } else if (filterDefinition?.type === 'date') { // date filters: nil <-> (field doesn't exist) OR (date <= epoch) OR (date >= 5138)
      valueFiltering = {
        bool: {
          should: [
            {
              bool: {
                must_not: {
                  exists: {
                    field: headKey
                  }
                }
              }
            },
            { range: { [headKey]: { lte: '1970-01-01T01:00:00.000Z' } } },
            { range: { [headKey]: { gte: '5138-11-16T09:46:40.000Z' } } }
          ],
          minimum_should_match: 1,
        }
      };
    }
    valuesFiltering.push(valueFiltering);
  } else if (operator === 'not_nil') {
    const filterDefinition = schemaAttributesDefinition.getAttributeByName(headKey);
    let valueFiltering = { // classic filters: field exists
      exists: {
        field: headKey
      }
    };
    if (filterDefinition?.type === 'string') {
      if (filterDefinition?.format === 'text') { // text filters: use wildcard
        valueFiltering = {
          bool: {
            must: {
              wildcard: {
                [headKey]: '*'
              }
            },
          }
        };
      } else { // other filters: not_nil <-> (field exists) AND (field != empty string)
        valueFiltering = {
          bool: {
            must: [
              {
                exists: {
                  field: headKey
                }
              },
              {
                bool: {
                  must_not: {
                    term: {
                      [headKey === '_id' ? headKey : `${headKey}.keyword`]: { value: '' },
                    },
                  },
                }
              }
            ],
          }
        };
      }
    } else if (filterDefinition?.type === 'date') { // date filters: not_nil <-> (field exists) AND (date > epoch) AND (date < 5138)
      valueFiltering = {
        bool: {
          must: [
            {
              exists: {
                field: headKey
              }
            },
            { range: { [headKey]: { gt: '1970-01-01T01:00:00.000Z' } } },
            { range: { [headKey]: { lt: '5138-11-16T09:46:40.000Z' } } }
          ],
        }
      };
    }
    valuesFiltering.push(valueFiltering);
  }
  // 03. Handle values according to the operator
  if (operator !== 'nil' && operator !== 'not_nil') {
    for (let i = 0; i < values.length; i += 1) {
      if (values[i] === 'EXISTS') {
        if (arrayKeys.length > 1) {
          throw UnsupportedError('Filter must have only one field', { keys: arrayKeys });
        }
        valuesFiltering.push({ exists: { field: headKey } });
      } else if (operator === 'eq' || operator === 'not_eq') {
        const targets = operator === 'eq' ? valuesFiltering : noValuesFiltering;
        targets.push({
          multi_match: {
            fields: arrayKeys.map((k) => buildFieldForQuery(k)),
            query: values[i].toString(),
          },
        });
      } else if (operator === 'match') {
        valuesFiltering.push({
          multi_match: {
            fields: arrayKeys,
            query: values[i].toString(),
          },
        });
      } else if (operator === 'wildcard') {
        valuesFiltering.push({
          query_string: {
            query: `"${values[i].toString()}"`,
            fields: arrayKeys,
          },
        });
      } else if (operator === 'contains' || operator === 'not_contains') {
        const targets = operator === 'contains' ? valuesFiltering : noValuesFiltering;
        const val = specialElasticCharsEscape(values[i].toString());
        targets.push({
          query_string: {
            query: `*${val.replace(/\s/g, '\\ ')}*`,
            analyze_wildcard: true,
            fields: arrayKeys.map((k) => `${k}.keyword`),
          },
        });
      } else if (operator === 'starts_with' || operator === 'not_starts_with') {
        const targets = operator === 'starts_with' ? valuesFiltering : noValuesFiltering;
        const val = specialElasticCharsEscape(values[i].toString());
        targets.push({
          query_string: {
            query: `${val.replace(/\s/g, '\\ ')}*`,
            analyze_wildcard: true,
            fields: arrayKeys.map((k) => `${k}.keyword`),
          },
        });
      } else if (operator === 'ends_with' || operator === 'not_ends_with') {
        const targets = operator === 'ends_with' ? valuesFiltering : noValuesFiltering;
        const val = specialElasticCharsEscape(values[i].toString());
        targets.push({
          query_string: {
            query: `*${val.replace(/\s/g, '\\ ')}`,
            analyze_wildcard: true,
            fields: arrayKeys.map((k) => `${k}.keyword`),
          },
        });
      } else if (operator === 'script') {
        valuesFiltering.push({
          script: {
            script: values[i].toString()
          },
        });
      } else if (operator === 'search') {
        const shouldSearch = elGenerateFieldTextSearchShould(values[i].toString(), arrayKeys);
        const bool = {
          bool: {
            should: shouldSearch,
            minimum_should_match: 1,
          },
        };
        valuesFiltering.push(bool);
      } else {
        if (arrayKeys.length > 1) {
          throw UnsupportedError('Filter must have only one field', { keys: arrayKeys });
        }
        valuesFiltering.push({ range: { [headKey]: { [operator]: values[i] } } }); // range operators
      }
    }
  }
  // 04. Push the values
  if (valuesFiltering.length > 0) {
    return {
      bool: {
        should: valuesFiltering,
        minimum_should_match: localFilterMode === 'or' ? 1 : valuesFiltering.length,
      },
    };
  }
  if (noValuesFiltering.length > 0) {
    return {
      bool: {
        should: noValuesFiltering.map((o) => ({
          bool: {
            must_not: [o]
          }
        })),
        minimum_should_match: localFilterMode === 'or' ? 1 : noValuesFiltering.length,
      },
    };
  }
  throw UnsupportedError('Invalid filter configuration', validFilter);
};

export const buildSubQueryForFilterGroup = async (context, user, inputFilters) => {
  const { mode = 'and', filters = [], filterGroups = [] } = inputFilters;
  const localMustFilters = [];
  // Handle filterGroups
  for (let index = 0; index < filterGroups.length; index += 1) {
    const group = filterGroups[index];
    if (isFilterGroupNotEmpty(group)) {
      const subQuery = await buildSubQueryForFilterGroup(context, user, group);
      if (subQuery) { // can be null
        localMustFilters.push(subQuery);
      }
    }
  }
  // Handle filters
  for (let index = 0; index < filters.length; index += 1) {
    const filter = filters[index];
    const isValidFilter = filter?.values || filter?.nested?.length > 0;
    if (isValidFilter) {
      const localMustFilter = await buildLocalMustFilter(filter);
      localMustFilters.push(localMustFilter);
    }
  }
  if (localMustFilters.length > 0) {
    return {
      bool: {
        should: localMustFilters,
        minimum_should_match: mode === 'or' ? 1 : localMustFilters.length,
      }
    };
  }
  return null;
};

export const computeQueryIndices = (indices, typeOrTypes) => {
  const types = (Array.isArray(typeOrTypes) || isEmptyField(typeOrTypes)) ? typeOrTypes : [typeOrTypes];
  // If indices are explicitly defined, just rely on the definition
  if (isEmptyField(indices)) {
    // If not and have no clue about the expected types, ask for all indices.
    // Worst case scenario that need to be avoided.
    if (isEmptyField(types)) {
      return READ_DATA_INDICES;
    }
    // If types are defined we need to infer from them the correct indices
    return R.uniq(types.map((findType) => {
      // If defined types are abstract, try to restrict the indices as much as possible
      if (isAbstract(findType)) {
        // For objects
        if (isBasicObject(findType)) {
          if (isInternalObject(findType)) return [READ_INDEX_INFERRED_ENTITIES, READ_INDEX_INTERNAL_OBJECTS];
          if (isStixMetaObject(findType)) return [READ_INDEX_INFERRED_ENTITIES, READ_INDEX_STIX_META_OBJECTS];
          if (isStixDomainObject(findType)) return [READ_INDEX_INFERRED_ENTITIES, READ_INDEX_STIX_DOMAIN_OBJECTS];
          if (isStixCoreObject(findType)) return [READ_INDEX_INFERRED_ENTITIES, READ_INDEX_STIX_DOMAIN_OBJECTS, READ_INDEX_STIX_CYBER_OBSERVABLES];
          if (isStixObject(findType)) return [READ_INDEX_INFERRED_ENTITIES, READ_INDEX_STIX_META_OBJECTS, READ_INDEX_STIX_DOMAIN_OBJECTS, READ_INDEX_STIX_CYBER_OBSERVABLES];
          return READ_ENTITIES_INDICES;
        }
        // For relationships
        if (isBasicRelationship(findType) || STIX_REF_RELATIONSHIP_TYPES.includes(findType)) {
          if (isInternalRelationship(findType)) return [READ_INDEX_INFERRED_RELATIONSHIPS, READ_INDEX_INTERNAL_RELATIONSHIPS];
          if (isStixSightingRelationship(findType)) return [READ_INDEX_INFERRED_RELATIONSHIPS, READ_INDEX_STIX_SIGHTING_RELATIONSHIPS];
          if (isStixCoreRelationship(findType)) return [READ_INDEX_INFERRED_RELATIONSHIPS, READ_INDEX_STIX_CORE_RELATIONSHIPS];
          if (isStixRefRelationship(findType) || STIX_REF_RELATIONSHIP_TYPES.includes(findType)) {
            return [READ_INDEX_INFERRED_RELATIONSHIPS, READ_INDEX_STIX_META_RELATIONSHIPS, READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS];
          }
          if (isStixRelationship(findType)) {
            return [READ_INDEX_INFERRED_RELATIONSHIPS, READ_INDEX_STIX_CORE_RELATIONSHIPS, READ_INDEX_STIX_SIGHTING_RELATIONSHIPS, READ_INDEX_STIX_META_RELATIONSHIPS,
              READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS];
          }
          return READ_RELATIONSHIPS_INDICES;
        }
        // Fallback
        throw UnsupportedError('Fail to compute indices for unknown type', { type: findType });
      }
      // If concrete type, infer the index from the type
      if (isBasicObject(findType)) {
        return [READ_INDEX_INFERRED_ENTITIES, `${inferIndexFromConceptType(findType)}*`];
      }
      return [READ_INDEX_INFERRED_RELATIONSHIPS, `${inferIndexFromConceptType(findType)}*`];
    }).flat());
  }
  return indices;
};
