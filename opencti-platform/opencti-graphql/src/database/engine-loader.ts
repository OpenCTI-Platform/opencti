import * as R from 'ramda';
import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import { Client as ElkClient } from '@elastic/elasticsearch';
import { Client as OpenClient } from '@opensearch-project/opensearch';
import semver from 'semver';
import {
  buildPagination,
  cursorToOffset,
  isNotEmptyField,
  offsetToCursor, READ_ENTITIES_INDICES, READ_INDEX_INTERNAL_OBJECTS,
  READ_INDEX_STIX_DOMAIN_OBJECTS
} from './utils';
import { ConfigurationError, DatabaseError, EngineShardsError, UnsupportedError } from '../config/errors';
import conf, { booleanConf, loadCert, logApp } from '../config/conf';
import { telemetry } from '../config/tracing';
import {
  BASE_TYPE_RELATION,
  buildRefRelationKey,
  buildRefRelationSearchKey,
  ENTITY_TYPE_IDENTITY,
  ID_INTERNAL,
  ID_STANDARD,
  IDS_STIX, REL_INDEX_PREFIX, RULE_PREFIX
} from '../schema/general';
import {
  ATTRIBUTE_ABSTRACT,
  ATTRIBUTE_DESCRIPTION, ATTRIBUTE_EXPLANATION,
  ATTRIBUTE_NAME,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_SYSTEM, ENTITY_TYPE_LOCATION_COUNTRY,
  STIX_ORGANIZATIONS_UNRESTRICTED
} from '../schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';
import { isDateNumericOrBooleanAttribute } from '../schema/schema-attributes';
import { BYPASS, computeUserMemberAccessIds, INTERNAL_USERS, isBypassUser, MEMBER_ACCESS_ALL } from '../utils/access';
import { RELATION_CREATED_BY, RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';
import { getEntityFromCache } from './cache';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER } from '../schema/internalObject';
import { runtimeFieldObservableValueScript } from '../utils/format';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { isSingleRelationsRef } from '../schema/stixEmbeddedRelationship';
import { convertTypeToStixType } from './stix-converter';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreSettings } from '../types/settings';
import type { BasicStoreCommon } from '../types/store';
import type { ListFilter } from './middleware-loader';

export const ES_MAX_CONCURRENCY = conf.get('elasticsearch:max_concurrency');
export const ES_IGNORE_THROTTLED = conf.get('elasticsearch:search_ignore_throttled');
export const ES_MAX_PAGINATION = conf.get('elasticsearch:max_pagination_result');
export const MAX_SEARCH_SIZE = 5000;
const ES_MAX_SHARDS_FAILURE = conf.get('elasticsearch:max_shards_failure') || 0;
const NO_MAPPING_FOUND_ERROR = 'No mapping found';
const NO_SUCH_INDEX_ERROR = 'no such index';

// region elastic common loader.
export const specialElasticCharsEscape = (query: string) => {
  return query.replace(/([/+|\-*()~={}[\]:?\\])/g, '\\$1');
};

const ca = conf.get('elasticsearch:ssl:ca')
  ? loadCert(conf.get('elasticsearch:ssl:ca'))
  : conf.get('elasticsearch:ssl:ca_plain') || null;

const searchConfiguration = {
  node: conf.get('elasticsearch:url'),
  proxy: conf.get('elasticsearch:proxy') || null,
  auth: {
    username: conf.get('elasticsearch:username') || null,
    password: conf.get('elasticsearch:password') || null,
    apiKey: conf.get('elasticsearch:api_key') || null,
  },
  maxRetries: conf.get('elasticsearch:max_retries') || 3,
  requestTimeout: conf.get('elasticsearch:request_timeout') || 30000,
  sniffOnStart: booleanConf('elasticsearch:sniff_on_start', false),
  ssl: { // For Opensearch 2+ and Elastic 7
    ca,
    rejectUnauthorized: booleanConf('elasticsearch:ssl:reject_unauthorized', true),
  },
  tls: { // For Elastic 8+
    ca,
    rejectUnauthorized: booleanConf('elasticsearch:ssl:reject_unauthorized', true),
  },
};

const ELK_ENGINE = 'elk';
const OPENSEARCH_ENGINE = 'opensearch';
export const BASE_SEARCH_CONNECTIONS = [
  // Pounds for connections search
  `connections.${ATTRIBUTE_NAME}^5`,
  // Add all other attributes
  'connections.*',
];
export const BASE_SEARCH_ATTRIBUTES = [
  // Pounds for attributes search
  `${ATTRIBUTE_NAME}^5`,
  `${ATTRIBUTE_DESCRIPTION}^2`,
  `${ATTRIBUTE_ABSTRACT}^5`,
  `${ATTRIBUTE_EXPLANATION}^5`,
  // Add all other attributes
  '*',
];

const elasticSearchClient = new ElkClient(searchConfiguration);
const openSearchClient = new OpenClient(searchConfiguration);
let isRuntimeSortingEnable = false;
let engine: any = openSearchClient;

export const getEngine = () => engine;

// The OpenSearch/ELK Body Parser (oebp)
// Starting ELK8+, response are no longer inside a body envelop
// Query wrapping is still accepted in ELK8
export const oebp = (queryResult: any) => {
  if (engine instanceof ElkClient) {
    return queryResult;
  }
  return queryResult.body;
};

// Look for the engine version with OpenSearch client
export const searchEngineVersion = async () => {
  const searchInfo = await engine.info()
    .then((info: any) => oebp(info).version)
    .catch(
      /* istanbul ignore next */ (e: Error) => {
        throw ConfigurationError('[SEARCH] Search engine seems down', { error: e.message });
      }
    );
  const searchPlatform = searchInfo.distribution || ELK_ENGINE; // openSearch or elasticSearch
  const searchVersion = searchInfo.number;
  const localEngine = searchPlatform === ELK_ENGINE ? elasticSearchClient : openSearchClient;
  return { platform: searchPlatform, version: searchVersion, engine: localEngine };
};

export const searchEngineInit = async () => {
  // Select the correct engine
  const engineSelector = conf.get('elasticsearch:engine_selector') || 'auto';
  let engineVersion;
  let enginePlatform;
  if (engineSelector === ELK_ENGINE) {
    logApp.info(`[SEARCH] Engine ${ELK_ENGINE} client selected by configuration`);
    engine = elasticSearchClient;
    const searchVersion = await searchEngineVersion();
    if (searchVersion.platform !== ELK_ENGINE) {
      throw ConfigurationError(`[SEARCH] Invalid Search engine selector, configured to ${engineSelector}, detected to ${searchVersion.platform}`);
    }
    enginePlatform = ELK_ENGINE;
    engineVersion = searchVersion.version;
  } else if (engineSelector === OPENSEARCH_ENGINE) {
    logApp.info(`[SEARCH] Engine ${OPENSEARCH_ENGINE} client selected by configuration`);
    engine = openSearchClient;
    const searchVersion = await searchEngineVersion();
    if (searchVersion.platform !== OPENSEARCH_ENGINE) {
      throw ConfigurationError(`[SEARCH] Invalid Search engine selector, configured to ${engineSelector}, detected to ${searchVersion.platform}`);
    }
    enginePlatform = OPENSEARCH_ENGINE;
    engineVersion = searchVersion.version;
  } else {
    logApp.info(`[SEARCH] Engine client not specified, trying to discover it with ${OPENSEARCH_ENGINE} client`);
    engine = openSearchClient;
    const searchVersion = await searchEngineVersion();
    enginePlatform = searchVersion.platform;
    logApp.info(`[SEARCH] Engine detected to ${enginePlatform}`);
    engine = searchVersion.engine;
    engineVersion = searchVersion.version;
  }
  // Setup the platform runtime field option
  isRuntimeSortingEnable = enginePlatform === ELK_ENGINE && semver.satisfies(engineVersion, '>=7.12.x');
  const runtimeStatus = isRuntimeSortingEnable ? 'enabled' : 'disabled';
  logApp.info(`[SEARCH] ${enginePlatform} (${engineVersion}) client selected / runtime sorting ${runtimeStatus}`);
  // Everything is fine, return true
  return true;
};

export const isRuntimeSortEnable = () => isRuntimeSortingEnable;

interface RelationConnection {
  internal_id: string
  role: string
  name: string
  types: string[]
}

const elBuildRelation = (type: 'from' | 'to', connection: RelationConnection) => {
  return {
    [type]: null,
    [`${type}Id`]: connection.internal_id,
    [`${type}Role`]: connection.role,
    [`${type}Name`]: connection.name,
    [`${type}Type`]: R.head(connection.types),
  };
};

const elMergeRelation = (concept: any, fromConnection: RelationConnection, toConnection: RelationConnection) => {
  if (!fromConnection || !toConnection) {
    throw DatabaseError('[SEARCH] Something failed in reconstruction of the relation', concept.internal_id);
  }
  const from: any = elBuildRelation('from', fromConnection);
  from.source_ref = `${convertTypeToStixType(from.fromType)}--temporary`;
  const to: any = elBuildRelation('to', toConnection);
  to.target_ref = `${convertTypeToStixType(to.toType)}--temporary`;
  return R.mergeAll([concept, from, to]);
};

export const elRebuildRelation = (concept: any) => {
  if (concept.base_type === BASE_TYPE_RELATION) {
    const { connections } = concept;
    const entityType = concept.entity_type;
    const fromConnection = R.find((connection: any) => connection.role === `${entityType}_from`, connections);
    const toConnection = R.find((connection: any) => connection.role === `${entityType}_to`, connections);
    const relation: any = elMergeRelation(concept, fromConnection, toConnection);
    relation.relationship_type = relation.entity_type;
    return R.dissoc('connections', relation);
  }
  return concept;
};

export const elDataConverter = (esHit: any, withoutRels = false) => {
  const elementData = esHit._source;
  const data = {
    _index: esHit._index,
    id: elementData.internal_id,
    sort: esHit.sort,
    ...elRebuildRelation(elementData),
  };
  const entries = Object.entries(data);
  const ruleInferences = [];
  for (let index = 0; index < entries.length; index += 1) {
    const [key, val] = entries[index] as any;
    if (key.startsWith(RULE_PREFIX)) {
      const rule = key.substring(RULE_PREFIX.length);
      const ruleDefinitions: any = Object.values(val as any);
      for (let rIndex = 0; rIndex < ruleDefinitions.length; rIndex += 1) {
        const { inferred, explanation } = ruleDefinitions[rIndex];
        const attributes = R.toPairs(inferred).map((s) => ({ field: R.head(s), value: String(R.last(s)) }));
        ruleInferences.push({ rule, explanation, attributes });
      }
      data[key] = val;
    } else if (key.startsWith(REL_INDEX_PREFIX)) {
      // Rebuild rel to stix attributes
      if (withoutRels) {
        delete data[key];
      } else {
        const rel = key.substring(REL_INDEX_PREFIX.length);
        const [relType] = rel.split('.');
        data[relType] = isSingleRelationsRef(data.entity_type, relType) ? R.head(val) : [...(data[relType] ?? []), ...val];
      }
    } else {
      data[key] = val;
    }
  }
  if (ruleInferences.length > 0) {
    data.x_opencti_inferences = ruleInferences;
  }
  if (data.event_data) {
    data.event_data = JSON.stringify(data.event_data);
  }
  return data;
};

export const elGenerateFullTextSearchShould = (search: string, args: any = {}) => {
  const { useWildcardPrefix = false, useWildcardSuffix = true } = args;
  let decodedSearch;
  try {
    decodedSearch = decodeURIComponent(search).trim();
  } catch (e) {
    decodedSearch = search.trim();
  }
  let remainingSearch = decodedSearch;
  const exactSearch = (decodedSearch.match(/"[^"]+"/g) || []) //
    .filter((e) => isNotEmptyField(e.replace(/"/g, '').trim()));
  for (let index = 0; index < exactSearch.length; index += 1) {
    remainingSearch = remainingSearch.replace(exactSearch[index], '');
  }
  const querySearch = [];

  const partialSearch = remainingSearch.replace(/"/g, '').trim().split(' ');

  for (let searchIndex = 0; searchIndex < partialSearch.length; searchIndex += 1) {
    const partialElement = partialSearch[searchIndex];
    const cleanElement = specialElasticCharsEscape(partialElement);
    if (isNotEmptyField(cleanElement)) {
      querySearch.push(`${useWildcardPrefix ? '*' : ''}${cleanElement}${useWildcardSuffix ? '*' : ''}`);
    }
  }
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

export const buildUserMemberAccessFilter = (user: AuthUser, includeAuthorities = false) => {
  const capabilities = user.capabilities.map((c) => c.name);
  if (includeAuthorities && capabilities.includes(BYPASS)) {
    return [];
  }
  const userAccessIds = computeUserMemberAccessIds(user);
  // if access_users exists, it should have the user access ids
  const authorizedFilters: any = [
    { bool: { must_not: { exists: { field: 'authorized_members' } } } },
    { terms: { 'authorized_members.id.keyword': [MEMBER_ACCESS_ALL, ...userAccessIds] } },
  ];
  if (includeAuthorities) {
    const roleIds = user.roles.map((r) => r.id);
    const owners = [...userAccessIds, ...capabilities, ...roleIds];
    authorizedFilters.push({ terms: { 'authorized_authorities.keyword': owners } });
  }
  return [{ bool: { should: authorizedFilters } }];
};

export const elRawSearch = (context: AuthContext, user: AuthUser, types: string[], query: any) => {
  const elRawSearchFn = async () => engine.search(query).then((r: any) => {
    const parsedSearch = oebp(r);
    // If some shards fail
    if (parsedSearch._shards.failed > 0) {
      // We need to filter "No mapping found" errors that are not real problematic shard problems
      // As we do not define all mappings and let elastic create it dynamically at first creation
      // This failure is transient until the first creation of some data
      const failures = (parsedSearch._shards.failures ?? [])
        .filter((f: any) => !f.reason?.reason.includes(NO_MAPPING_FOUND_ERROR));
      if (failures.length > ES_MAX_SHARDS_FAILURE) {
        // We do not support response with shards failure.
        // Result must be always accurate to prevent data duplication and unwanted behaviors
        // If any shard fail during query, engine throw a lock exception with shards information
        throw EngineShardsError({ shards: parsedSearch._shards });
      } else if (failures.length > 0) {
        // At least log the situation
        const message = `[SEARCH] Search meet ${failures.length} shards failure, please check your configuration`;
        logApp.error(message, { shards: parsedSearch._shards });
      }
    }
    // Return result of the search if everything goes well
    return parsedSearch;
  });
  return telemetry(context, user, `SELECT ${Array.isArray(types) ? types.join(', ') : (types || 'None')}`, {
    [SemanticAttributes.DB_NAME]: 'search_engine',
    [SemanticAttributes.DB_OPERATION]: 'read',
    [SemanticAttributes.DB_STATEMENT]: JSON.stringify(query),
  }, elRawSearchFn);
};

export const buildDataRestrictions = async (context: AuthContext, user: AuthUser, opts: any = {}) => {
  const must: any = [];
  // eslint-disable-next-line camelcase
  const must_not: any = [];
  // If internal users of the system, we cancel rights checking
  if (INTERNAL_USERS[user.id]) {
    return { must, must_not };
  }
  // check user access
  must.push(...buildUserMemberAccessFilter(user, opts?.includeAuthorities));
  // If user have bypass, no need to check restrictions
  if (!isBypassUser(user)) {
    // region Handle marking restrictions
    if (user.allowed_marking.length === 0) {
      // If user have no marking, he can only access to data with no markings.
      must_not.push({ exists: { field: buildRefRelationKey(RELATION_OBJECT_MARKING) } });
    } else {
      // Markings should be grouped by types for restriction
      const userGroupedMarkings: any = R.groupBy((m) => m.definition_type, user.allowed_marking);
      const allGroupedMarkings: any = R.groupBy((m) => m.definition_type, user.all_marking);
      const markingGroups = Object.keys(allGroupedMarkings);
      const mustNotHaveOneOf = [];
      for (let index = 0; index < markingGroups.length; index += 1) {
        const markingGroup = markingGroups[index];
        const markingsForGroup = allGroupedMarkings[markingGroup].map((i: any) => i.internal_id);
        const userMarkingsForGroup = (userGroupedMarkings[markingGroup] || []).map((i: any) => i.internal_id);
        // Get all markings the user has no access for this group
        const res = markingsForGroup.filter((m: any) => !userMarkingsForGroup.includes(m));
        if (res.length > 0) {
          mustNotHaveOneOf.push(res);
        }
      }
      // If use have marking, he can access to data with no marking && data with according marking
      const mustNotMarkingTerms = [];
      for (let i = 0; i < mustNotHaveOneOf.length; i += 1) {
        const markings = mustNotHaveOneOf[i];
        const should = markings.map((m: any) => ({ match: { [buildRefRelationSearchKey(RELATION_OBJECT_MARKING)]: m } }));
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
    const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
    const excludedEntityMatches = STIX_ORGANIZATIONS_UNRESTRICTED
      .map((t) => [{ match: { 'parent_types.keyword': t } }, { match_phrase: { 'entity_type.keyword': t } }])
      .flat();
    if (settings.platform_organization) {
      if (user.inside_platform_organization) {
        // Data are visible independently of the organizations
        // Nothing to restrict.
      } else {
        // Data with Empty granted_refs are not visible
        // Data with granted_refs users that participate to at least one
        const should: any = [...excludedEntityMatches];
        const shouldOrgs = user.allowed_organizations
          .map((m) => ({ match: { [buildRefRelationSearchKey(RELATION_GRANTED_TO)]: m.internal_id } }));
        should.push(...shouldOrgs);
        // User individual or data created by this individual must be accessible
        if (user.individual_id) {
          should.push({ match: { 'internal_id.keyword': user.individual_id } });
          should.push({ match: { [buildRefRelationSearchKey(RELATION_CREATED_BY)]: user.individual_id } });
        }
        // Finally build the bool should search
        must.push({ bool: { should, minimum_should_match: 1 } });
      }
    } else {
      // Data with Empty granted_refs are granted to everyone
      const should: any = [...excludedEntityMatches];
      should.push({ bool: { must_not: [{ exists: { field: buildRefRelationSearchKey(RELATION_GRANTED_TO) } }] } });
      // Data with granted_refs users that participate to at least one
      if (user.allowed_organizations.length > 0) {
        const shouldOrgs = user.allowed_organizations
          .map((m) => ({ match: { [buildRefRelationSearchKey(RELATION_GRANTED_TO)]: m.internal_id } }));
        should.push(...shouldOrgs);
      }
      // User individual or data created by this individual must be accessible
      if (user.individual_id) {
        should.push({ match: { 'internal_id.keyword': user.individual_id } });
        should.push({ match: { [buildRefRelationSearchKey(RELATION_CREATED_BY)]: user.individual_id } });
      }
      // Finally build the bool should search
      must.push({ bool: { should, minimum_should_match: 1 } });
    }
    // endregion
  }
  return { must, must_not };
};

export const RUNTIME_ATTRIBUTES: any = {
  observable_value: {
    field: 'observable_value.keyword',
    type: 'keyword',
    getSource: async () => runtimeFieldObservableValueScript(),
    getParams: async () => {
    },
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
    getParams: async (context: AuthContext, user: AuthUser) => {
      // eslint-disable-next-line @typescript-eslint/no-use-before-define
      const identities = await elPaginate(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, {
        types: [ENTITY_TYPE_IDENTITY],
        first: MAX_SEARCH_SIZE,
        connectionFormat: false,
      });
      return R.mergeAll(identities.map((i: any) => ({ [i.internal_id]: i.name })));
    },
  },
  bornIn: {
    field: 'bornIn.keyword',
    type: 'keyword',
    getSource: async () => `
      if (doc.containsKey('rel_born-in.internal_id)) {
        def countryId = doc['rel_born-in.internal_id.keyword'];
        if (countryId.size() == 1) {
          def countryName = params[countryId[0]];
          emit(countryName != null ? creatorName : 'Unknown')
        } else {
          emit('Unknown')
        }
      } else {
        emit('Unknown')
      }
    `,
    getParams: async (context: AuthContext, user: AuthUser) => {
      // eslint-disable-next-line @typescript-eslint/no-use-before-define
      const countries = await elPaginate(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, {
        types: [ENTITY_TYPE_LOCATION_COUNTRY],
        first: MAX_SEARCH_SIZE,
        connectionFormat: false,
      });
      return R.mergeAll(countries.map((country: any) => ({ [country.internal_id]: country.name })));
    },
  },
  ethnicity: {
    field: 'ethnicity.keyword',
    type: 'keyword',
    getSource: async () => `
      if (doc.containsKey('rel_of-ethnicity.internal_id)) {
        def countryId = doc['rel_of-ethnicity.internal_id.keyword'];
        if (countryId.size() == 1) {
          def countryName = params[countryId[0]];
          emit(countryName != null ? creatorName : 'Unknown')
        } else {
          emit('Unknown')
        }
      } else {
        emit('Unknown')
      }
    `,
    getParams: async (context: AuthContext, user: AuthUser) => {
      // eslint-disable-next-line @typescript-eslint/no-use-before-define
      const countries = await elPaginate(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, {
        types: [ENTITY_TYPE_LOCATION_COUNTRY],
        first: MAX_SEARCH_SIZE,
        connectionFormat: false,
      });
      return R.mergeAll(countries.map((country: any) => ({ [country.internal_id]: country.name })));
    },
  },
  creator: {
    field: 'creator.keyword',
    type: 'keyword',
    getSource: async () => `
        if (doc.containsKey('creator_id')) {
          def creatorId = doc['creator_id.keyword'];
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
    getParams: async (context: AuthContext, user: AuthUser) => {
      // eslint-disable-next-line @typescript-eslint/no-use-before-define
      const users = await elPaginate(context, user, READ_INDEX_INTERNAL_OBJECTS, {
        types: [ENTITY_TYPE_USER],
        first: MAX_SEARCH_SIZE,
        connectionFormat: false,
      });
      return R.mergeAll(users.map((i: any) => ({ [i.internal_id]: i.name.replace(/[&/\\#,+[\]()$~%.'":*?<>{}]/g, '') })));
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
    getParams: async (context: AuthContext, user: AuthUser) => {
      // eslint-disable-next-line @typescript-eslint/no-use-before-define
      const identities = await elPaginate(context, user, READ_ENTITIES_INDICES, {
        types: [ENTITY_TYPE_MARKING_DEFINITION],
        first: MAX_SEARCH_SIZE,
        connectionFormat: false,
      });
      return R.mergeAll(identities.map((i: any) => ({ [i.internal_id]: i.definition })));
    },
  },
  assigneeTo: {
    field: 'assigneeTo.keyword',
    type: 'keyword',
    getSource: async () => `
        if (doc.containsKey('rel_object-assignee.internal_id')) {
          def assigneeId = doc['rel_object-assignee.internal_id.keyword'];
          if (assigneeId.size() >= 1) {
            def assigneeName = params[assigneeId[0]].toLowerCase();
            emit(assigneeName != null ? assigneeName : 'unknown')
          } else {
              emit('unknown')
            }
        } else {
          emit('unknown')
        }
    `,
    getParams: async (context: AuthContext, user: AuthUser) => {
      // eslint-disable-next-line @typescript-eslint/no-use-before-define
      const users = await elPaginate(context, user, READ_INDEX_INTERNAL_OBJECTS, {
        types: [ENTITY_TYPE_USER],
        first: MAX_SEARCH_SIZE,
        connectionFormat: false,
      });
      return R.mergeAll(users.map((i: any) => ({ [i.internal_id]: i.name.replace(/[&/\\#,+[\]()$~%.'":*?<>{}]/g, '') })));
    },
  },
  participant: {
    field: 'participant.keyword',
    type: 'keyword',
    getSource: async () => `
        if (doc.containsKey('rel_object-participant.internal_id')) {
          def participantId = doc['rel_object-participant.internal_id.keyword'];
          if (participantId.size() >= 1) {
            def participantName = params[participantId[0]].toLowerCase();
            emit(participantName != null ? participantName : 'unknown')
          } else {
              emit('unknown')
            }
        } else {
          emit('unknown')
        }
    `,
    getParams: async (context: AuthContext, user: AuthUser) => {
      // eslint-disable-next-line @typescript-eslint/no-use-before-define
      const users = await elPaginate(context, user, READ_INDEX_INTERNAL_OBJECTS, {
        types: [ENTITY_TYPE_USER],
        first: MAX_SEARCH_SIZE,
        connectionFormat: false,
      });
      return R.mergeAll(users.map((i: any) => ({ [i.internal_id]: i.name.replace(/[&/\\#,+[\]()$~%.'":*?<>{}]/g, '') })));
    },
  },
};
export const BASE_FIELDS = ['_index', 'internal_id', 'standard_id', 'sort', 'base_type', 'entity_type',
  'connections', 'first_seen', 'last_seen', 'start_time', 'stop_time'];
export const elQueryBodyBuilder = async (context: AuthContext, user: AuthUser, options: any) => {
  // eslint-disable-next-line no-use-before-define
  const { ids = [], first = 200, after, orderBy = null, orderMode = 'asc', noSize = false, noSort = false, intervalInclude = false } = options;
  const { types = null, filters = [], filterMode = 'and', search = null } = options;
  const { startDate = null, endDate = null, dateAttribute = null } = options;
  const dateFilter = [];
  const searchAfter = after ? cursorToOffset(after) : undefined;
  let ordering: any = [];
  const { includeAuthorities = false } = options;
  const markingRestrictions = await buildDataRestrictions(context, user, { includeAuthorities });
  const accessMust = markingRestrictions.must;
  const accessMustNot = markingRestrictions.must_not;
  const mustFilters = [];
  if (ids.length > 0) {
    const idsTermsPerType = [];
    const elementTypes = [ID_INTERNAL, ID_STANDARD, IDS_STIX];
    for (let indexType = 0; indexType < elementTypes.length; indexType += 1) {
      const elementType = elementTypes[indexType];
      const terms = { [`${elementType}.keyword`]: ids };
      idsTermsPerType.push({ terms });
    }
    mustFilters.push({ bool: { should: idsTermsPerType, minimum_should_match: 1 } });
  }
  if (startDate && endDate) {
    dateFilter.push({
      range: {
        [dateAttribute || 'created_at']: {
          format: 'strict_date_optional_time',
          [intervalInclude ? 'gte' : 'gt']: startDate,
          [intervalInclude ? 'lte' : 'lt']: endDate,
        },
      },
    });
  } else if (startDate) {
    dateFilter.push({
      range: {
        [dateAttribute || 'created_at']: {
          format: 'strict_date_optional_time',
          [intervalInclude ? 'gte' : 'gt']: startDate,
        },
      },
    });
  } else if (endDate) {
    dateFilter.push({
      range: {
        [dateAttribute || 'created_at']: {
          format: 'strict_date_optional_time',
          [intervalInclude ? 'lte' : 'lt']: endDate,
        },
      },
    });
  }
  mustFilters.push(...dateFilter);
  if (types !== null && types.length > 0) {
    const should = R.flatten(
      types.map((typeValue: any) => {
        return [
          { match_phrase: { 'entity_type.keyword': typeValue } },
          { match_phrase: { 'parent_types.keyword': typeValue } },
        ];
      })
    );
    mustFilters.push({ bool: { should, minimum_should_match: 1 } });
  }
  const validFilters = R.filter((f: any) => f?.values?.length > 0 || f?.nested?.length > 0, filters || []);
  if (validFilters.length > 0) {
    for (let index = 0; index < validFilters.length; index += 1) {
      const valuesFiltering = [];
      const noValuesFiltering = [];
      const { key, values, nested, operator = 'eq', filterMode: localFilterMode = 'or' } = validFilters[index];
      const arrayKeys = Array.isArray(key) ? key : [key];
      // in case we want to filter by source reliability (reliability of author)
      // we need to find all authors filtered by reliability and filter on these authors
      const sourceReliabilityFilter = arrayKeys.find((k) => k === 'source_reliability');
      if (sourceReliabilityFilter) {
        const authorTypes = [
          ENTITY_TYPE_IDENTITY_INDIVIDUAL,
          ENTITY_TYPE_IDENTITY_ORGANIZATION,
          ENTITY_TYPE_IDENTITY_SYSTEM
        ];
        const reliabilityFilter = { key: ['x_opencti_reliability'], operator, values, localFilterMode };
        const opts = { types: authorTypes, connectionFormat: false, filters: [reliabilityFilter] };
        // eslint-disable-next-line @typescript-eslint/no-use-before-define
        const authors = await elList(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, opts);
        if (authors.length > 0) {
          arrayKeys.splice(0, 1);
          arrayKeys.push('rel_created-by.internal_id');
          values.splice(0, values.length);
          authors.forEach((author: any) => values.push(author.internal_id));
        }
      }
      // In case of entity_type filters, we also look by default in the parent_types property.
      const validKeys = R.uniq(arrayKeys.includes('entity_type') ? [...arrayKeys, 'parent_types'] : arrayKeys);
      // TODO IF KEY is PART OF Rule we need to add extra fields search
      // TODO Add connections like filters to have native fromId, toId filters handling.
      // See opencti-front\src\private\components\events\StixSightingRelationships.tsx
      if (nested) {
        if (validKeys.length > 1) {
          throw UnsupportedError('[SEARCH] Must have only one field', validKeys);
        }
        const nestedMust = [];
        const nestedMustNot = [];
        for (let nestIndex = 0; nestIndex < nested.length; nestIndex += 1) {
          const nestedElement = nested[nestIndex];
          const parentKey = validKeys.at(0);
          const { key: nestedKey, values: nestedValues, operator: nestedOperator = 'eq' } = nestedElement;
          const nestedShould = [];
          for (let i = 0; i < nestedValues.length; i += 1) {
            const nestedFieldKey = `${parentKey}.${nestedKey}`;
            const nestedSearchValues = nestedValues[i].toString();
            if (nestedOperator === 'wildcard') {
              nestedShould.push({ query_string: { query: `${nestedSearchValues}`, fields: [nestedFieldKey] } });
            } else if (nestedOperator === 'not_eq') {
              nestedMustNot.push({ match_phrase: { [nestedFieldKey]: nestedSearchValues } });
            } else {
              nestedShould.push({ match_phrase: { [nestedFieldKey]: nestedSearchValues } });
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
          path: R.head(validKeys),
          query: {
            bool: {
              must: nestedMust,
              must_not: nestedMustNot,
            },
          },
        };
        mustFilters.push({ nested: nestedQuery });
      } else {
        for (let i = 0; i < values.length; i += 1) {
          if (values[i] === null) {
            if (validKeys.length > 1) {
              throw UnsupportedError('[SEARCH] Must have only one field', validKeys);
            }
            if (operator === 'eq') {
              valuesFiltering.push({
                bool: {
                  must_not: {
                    exists: {
                      field: R.head(validKeys)
                    }
                  }
                }
              });
            } else if (operator === 'not_eq') {
              valuesFiltering.push({ exists: { field: R.head(validKeys) } });
            }
          } else if (values[i] === 'EXISTS') {
            if (validKeys.length > 1) {
              throw UnsupportedError('[SEARCH] Must have only one field', validKeys);
            }
            valuesFiltering.push({ exists: { field: R.head(validKeys) } });
          } else if (operator === 'eq') {
            valuesFiltering.push({
              multi_match: {
                fields: validKeys.map((k) => `${isDateNumericOrBooleanAttribute(k) ? k : `${k}.keyword`}`),
                query: values[i].toString(),
              },
            });
          } else if (operator === 'not_eq') {
            noValuesFiltering.push({
              multi_match: {
                fields: validKeys.map((k) => `${isDateNumericOrBooleanAttribute(k) ? k : `${k}.keyword`}`),
                query: values[i].toString(),
              },
            });
          } else if (operator === 'match') {
            valuesFiltering.push({
              multi_match: {
                fields: validKeys,
                query: values[i].toString(),
              },
            });
          } else if (operator === 'wildcard') {
            valuesFiltering.push({
              query_string: {
                query: `"${values[i].toString()}"`,
                fields: validKeys,
              },
            });
          } else if (operator === 'script') {
            valuesFiltering.push({
              script: {
                script: values[i].toString()
              },
            });
          } else {
            if (validKeys.length > 1) {
              throw UnsupportedError('[SEARCH] Must have only one field', validKeys);
            }
            valuesFiltering.push({ range: { [R.head(validKeys)]: { [operator]: values[i] } } });
          }
        }
        if (valuesFiltering.length > 0) {
          mustFilters.push(
            {
              bool: {
                should: valuesFiltering,
                minimum_should_match: localFilterMode === 'or' ? 1 : valuesFiltering.length,
              },
            },
          );
        }
        if (noValuesFiltering.length > 0) {
          mustFilters.push(
            {
              bool: {
                should: noValuesFiltering.map((o) => ({
                  bool: {
                    must_not: [o]
                  }
                })),
                minimum_should_match: localFilterMode === 'or' ? 1 : noValuesFiltering.length,
              },
            }
          );
        }
      }
    }
  }
  if (search !== null && search.length > 0) {
    const shouldSearch = elGenerateFullTextSearchShould(search, options);
    const bool = {
      bool: {
        should: shouldSearch,
        minimum_should_match: 1,
      },
    };
    mustFilters.push(bool);
  }
  // Handle orders
  const runtimeMappings: any = {};
  if (isNotEmptyField(orderBy)) {
    const orderCriterion = Array.isArray(orderBy) ? orderBy : [orderBy];
    for (let index = 0; index < orderCriterion.length; index += 1) {
      const orderCriteria = orderCriterion[index];
      const isDateOrNumber = isDateNumericOrBooleanAttribute(orderCriteria);
      const orderKeyword = isDateOrNumber || orderCriteria.startsWith('_') ? orderCriteria : `${orderCriteria}.keyword`;
      if (orderKeyword === '_score') {
        ordering = R.append({ [orderKeyword]: orderMode }, ordering);
      } else {
        const order = { [orderKeyword]: { order: orderMode, missing: '_last' } };
        ordering = R.append(order, ordering);
      }
    }
    // Add standard_id if not specify to ensure ordering uniqueness
    if (!orderCriterion.includes('standard_id')) {
      ordering.push({ 'standard_id.keyword': 'asc' });
    }
    // Build runtime mappings
    const runtime = RUNTIME_ATTRIBUTES[orderBy];
    if (isNotEmptyField(runtime)) {
      const source = await runtime.getSource();
      const params = await runtime.getParams(context, user);
      runtimeMappings[runtime.field] = {
        type: runtime.type,
        script: { source, params },
      };
    }
  } else { // If not ordering criteria, order by standard_id
    ordering.push({ 'standard_id.keyword': 'asc' });
  }
  // Build query
  const querySize = first || 10;
  let mustFiltersWithOperator = mustFilters;
  if (filterMode === 'or') {
    mustFiltersWithOperator = [{ bool: { should: mustFilters, minimum_should_match: 1 } }];
  }
  const body: any = {
    query: {
      bool: {
        must: [...accessMust, ...mustFiltersWithOperator],
        must_not: accessMustNot,
      },
    },
  };
  if (!noSize) {
    body.size = querySize;
  }
  if (!noSort) {
    body.sort = ordering;
  }
  // Add extra configuration
  if (isNotEmptyField(runtimeMappings)) {
    const isRuntimeSortFeatureEnable = isRuntimeSortEnable();
    if (!isRuntimeSortFeatureEnable) {
      throw UnsupportedError(`[SEARCH] Sorting of field ${orderBy} is only possible with elastic >=7.12`);
    }
    body.runtime_mappings = runtimeMappings;
  }
  if (searchAfter) {
    body.search_after = searchAfter;
  }
  return body;
};

export const elPaginate = async (context: AuthContext, user: AuthUser, indexName: string[] | string, options: any = {}) => {
  // eslint-disable-next-line no-use-before-define
  const { baseData = false, first = 200 } = options;
  const { types = null, connectionFormat = true } = options;
  const body: any = await elQueryBodyBuilder(context, user, options);
  if (body.size > ES_MAX_PAGINATION) {
    const message = `[SEARCH] You cannot ask for more than ${ES_MAX_PAGINATION} results. If you need more, please use pagination`;
    throw DatabaseError(message, { body });
  }
  const query = {
    index: indexName,
    ignore_throttled: ES_IGNORE_THROTTLED,
    track_total_hits: true,
    _source: baseData ? BASE_FIELDS : true,
    body,
  };
  logApp.debug('[SEARCH] paginate', { query });
  return elRawSearch(context, user, types !== null ? types : 'Any', query)
    .then((data: any) => {
      const convertedHits = R.map((n) => elDataConverter(n), data.hits.hits);
      if (connectionFormat) {
        const nodeHits = R.map((n) => ({ node: n, sort: n.sort }), convertedHits);
        return buildPagination(first, body.search_after, nodeHits, data.hits.total.value);
      }
      return convertedHits;
    })
    .catch(
      /* istanbul ignore next */ (err: any) => {
        // Because we create the mapping at element creation
        // We log the error only if its not a mapping not found error
        let isTechnicalError = true;
        if (isNotEmptyField(err.meta?.body)) {
          const errorCauses = err.meta.body?.error?.root_cause ?? [];
          const invalidMappingCauses = errorCauses.map((r: any) => r.reason ?? '')
            .filter((r: any) => R.includes(NO_MAPPING_FOUND_ERROR, r) || R.includes(NO_SUCH_INDEX_ERROR, r));
          const numberOfCauses = errorCauses.length;
          isTechnicalError = numberOfCauses === 0 || numberOfCauses > invalidMappingCauses.length;
        }
        // If uncontrolled error, log and propagate
        if (isTechnicalError) {
          logApp.error('[SEARCH] Paginate fail', { error: err, query });
          throw err;
        } else {
          return connectionFormat ? buildPagination(0, null, [], 0) : [];
        }
      }
    );
};

export const elList = async <T extends BasicStoreCommon>(context: AuthContext, user: AuthUser, indices: string[] | string, options: ListFilter<T> = {}) => {
  const { first = MAX_SEARCH_SIZE, maxSize = undefined } = options;
  let hasNextPage = true;
  let continueProcess = true;
  let emitSize = 0;
  let searchAfter = options.after;
  const listing: Array<T> = [];
  const publish = async (elements: Array<T>) => {
    const { callback } = options;
    if (callback) {
      const callbackResult = await callback(elements);
      continueProcess = callbackResult || callbackResult === undefined;
    } else {
      listing.push(...elements);
    }
  };
  while (continueProcess && hasNextPage) {
    // Force options to prevent connection format and manage search after
    const opts = { ...options, first, after: searchAfter, connectionFormat: false };
    const elements = await elPaginate(context, user, indices, opts);
    emitSize += elements.length;
    const noMoreElements = elements.length === 0 || elements.length < (first ?? MAX_SEARCH_SIZE);
    const moreThanMax = maxSize ? emitSize >= maxSize : false;
    if (noMoreElements || moreThanMax) {
      if (elements.length > 0) {
        await publish(elements);
      }
      hasNextPage = false;
    } else if (elements.length > 0) {
      const { sort } = elements[elements.length - 1];
      searchAfter = offsetToCursor(sort);
      await publish(elements);
    }
  }
  return listing;
};
