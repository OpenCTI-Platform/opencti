import * as R from 'ramda';
import {
  cursorToOffset,
  inferIndexFromConceptType,
  isEmptyField,
  isNotEmptyField,
  READ_DATA_INDICES,
  READ_DATA_INDICES_WITHOUT_INFERRED,
  READ_ENTITIES_INDICES,
  READ_ENTITIES_INDICES_WITHOUT_INFERRED,
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
  READ_RELATIONSHIPS_INDICES,
  READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
} from './utils';
import { FunctionalError, UnsupportedError } from '../config/errors';
import {
  isStixRefRelationship,
  RELATION_BORN_IN,
  RELATION_CREATED_BY,
  RELATION_ETHNICITY,
  RELATION_GRANTED_TO,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT_ASSIGNEE,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
  RELATION_OBJECT_PARTICIPANT,
  STIX_REF_RELATIONSHIP_TYPES,
} from '../schema/stixRefRelationship';
import {
  buildRefRelationKey,
  buildRefRelationSearchKey,
  ENTITY_TYPE_IDENTITY,
  ID_INFERRED,
  ID_INTERNAL,
  ID_STANDARD,
  IDS_STIX,
  isAbstract,
  REL_INDEX_PREFIX,
} from '../schema/general';
import {
  ATTRIBUTE_ABSTRACT,
  ATTRIBUTE_DESCRIPTION,
  ATTRIBUTE_DESCRIPTION_OPENCTI,
  ATTRIBUTE_EXPLANATION,
  ATTRIBUTE_NAME,
  ENTITY_TYPE_LOCATION_COUNTRY,
  isStixDomainObject,
  STIX_ORGANIZATIONS_RESTRICTED,
  STIX_ORGANIZATIONS_UNRESTRICTED,
} from '../schema/stixDomainObject';
import { isBasicObject, isStixCoreObject, isStixObject } from '../schema/stixCoreObject';
import { isBasicRelationship, isStixRelationship } from '../schema/stixRelationship';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { BYPASS, computeUserMemberAccessIds, INTERNAL_USERS, isBypassUser, isServiceAccountUser, isUserHasCapabilities, MEMBER_ACCESS_ALL, SYSTEM_USER } from '../utils/access';
import { runtimeFieldObservableValueScript } from '../utils/format';
import { ENTITY_TYPE_KILL_CHAIN_PHASE, ENTITY_TYPE_MARKING_DEFINITION, isStixMetaObject } from '../schema/stixMetaObject';
import { getEntitiesListFromCache, getEntityFromCache } from './cache';
import { ENTITY_TYPE_ACTIVITY, ENTITY_TYPE_HISTORY, ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER, isInternalObject } from '../schema/internalObject';
import { isDateNumericOrBooleanAttribute, isObjectFlatAttribute, schemaAttributesDefinition } from '../schema/schema-attributes';
import { checkAndConvertFilters, isFilterGroupNotEmpty } from '../utils/filtering/filtering-utils';
import { IDS_FILTER, TYPE_FILTER } from '../utils/filtering/filtering-constants';
import { type FilterGroup, FilterMode, FilterOperator } from '../generated/graphql';
import {
  type AttributeDefinition,
  authorizedMembers,
  baseType,
  entityType as entityTypeAttribute,
  id as idAttribute,
  internalId,
  standardId,
} from '../schema/attribute-definition';
import { connections as connectionsAttribute } from '../modules/attributes/basicRelationship-registrationAttributes';
import { isInternalRelationship, RELATION_IN_PIR, RELATION_PARTICIPATE_TO } from '../schema/internalRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { buildElasticSortingForAttributeCriteria } from '../utils/sorting';
import { buildDraftFilter, type BuildDraftFilterOpts } from './draft-utils';
import { RELATION_SAMPLE } from '../modules/malwareAnalysis/malwareAnalysis-types';
import { RELATION_COVERED } from '../modules/securityCoverage/securityCoverage-types';
import { RELATION_RESULT_OF } from '../modules/securityCoverage/securityCoverageResult/securityCoverageResult-types';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreBase, BasicStoreEntity, BasicStoreEntityMarkingDefinition, BasicStoreObject, StoreMarkingDefinition } from '../types/store';
import type { BasicStoreSettings } from '../types/settings';
import { completeSpecialFilterKeys } from '../utils/filtering/filtering-completeSpecialFilterKeys';
import { IDS_ATTRIBUTES, KEYWORD_TERMS_ATTRIBUTES } from '../domain/attribute-utils';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import type { FiltersWithNested } from './middleware-loader';
import { pushAll } from '../utils/arrayUtil';
import { refang } from '../utils/refang';
import { isEsScriptFilterEnabled } from './engine-config';
import { INNER_HITS_WINDOWS_SIZE } from './engine-data-converter';
import { elFindByIds, elPaginate, ES_DEFAULT_PAGINATION, isRuntimeSortEnable, MAX_RUNTIME_RESOLUTION_SIZE } from './engine';

const buildUserMemberAccessFilter = (user: AuthUser, opts: { includeAuthorities?: boolean | null; excludeEmptyAuthorizedMembers?: boolean }) => {
  const { includeAuthorities = false, excludeEmptyAuthorizedMembers = false } = opts;
  const capabilities = user.capabilities.map((c) => c.name);
  if (includeAuthorities && capabilities.includes(BYPASS)) {
    return [];
  }
  const userAccessIds = computeUserMemberAccessIds(user);
  // if access_users exists, it should have the user access ids
  const emptyAuthorizedMembers = { bool: { must_not: { nested: { path: authorizedMembers.name, query: { match_all: {} } } } } };
  // condition on authorizedMembers id
  const authorizedMembersIdsTerms = { terms: { [`${authorizedMembers.name}.id.keyword`]: [MEMBER_ACCESS_ALL, ...userAccessIds] } };
  // condition on group restriction ids
  const userGroupsIds = user.groups.map((group) => group.internal_id);
  const groupRestrictionCondition = {
    bool: {
      should: [
        { bool: { must_not: [{ exists: { field: `${authorizedMembers.name}.groups_restriction_ids` } }] } },
        {
          terms_set: {
            [`${authorizedMembers.name}.groups_restriction_ids.keyword`]: {
              terms: userGroupsIds,
              minimum_should_match_script: {
                source: `doc['${authorizedMembers.name}.groups_restriction_ids.keyword'].length`,
              },
            },
          },
        },
      ],
    },
  };
  const authorizedFilters = [
    { bool: { must: [authorizedMembersIdsTerms, groupRestrictionCondition] } },
  ];
  const shouldConditions = [];
  if (includeAuthorities) {
    const roleIds = user.roles.map((r) => r.id);
    const owners = [...userAccessIds, ...capabilities, ...roleIds];
    shouldConditions.push({ terms: { 'authorized_authorities.keyword': owners } });
  }
  if (!excludeEmptyAuthorizedMembers) {
    shouldConditions.push(emptyAuthorizedMembers);
  }

  const bypassAuthorizedMembers = isServiceAccountUser(user);
  const nestedQuery = {
    nested: {
      path: authorizedMembers.name,
      query: {
        // For service accounts, bypass authorized members restrictions
        bool: { should: bypassAuthorizedMembers ? [] : authorizedFilters },
      },
    },
  };
  shouldConditions.push(nestedQuery);
  return [{ bool: { should: shouldConditions } }];
};

const buildHistoryRestrictions = (user: AuthUser, historyFiltering?: boolean) => {
  const restrictions = [];
  if (historyFiltering) {
    // Compute forbidden fields for the user
    const forbiddenAttributes: string[] = [];
    const registeredTypes = schemaAttributesDefinition.getRegisteredTypes();
    const refTypes = schemaRelationsRefDefinition.getRegisteredTypes();
    for (let i = 0; i < registeredTypes.length; i += 1) {
      const registeredType = registeredTypes[i];
      const attrs = schemaAttributesDefinition.getAttributes(registeredType);
      const refs = refTypes.includes(registeredType) ? schemaRelationsRefDefinition.getRelationsRef(registeredType) : [];
      const attributes = Array.from(attrs.values());
      pushAll(attributes, refs);
      const invalidAttrs = attributes.filter((a: AttributeDefinition) =>
        !isUserHasCapabilities(user, a.requiredCapabilities));
      pushAll(forbiddenAttributes, invalidAttrs.map((a) => registeredType + '--' + a.name));
    }
    restrictions.push({
      bool: {
        should: [
          {
            bool: {
              must_not: [
                {
                  nested: {
                    path: 'context_data.history_changes',
                    query: {
                      match_all: {},
                    },
                  },
                },
              ],
            },
          },
          {
            nested: {
              path: 'context_data.history_changes',
              inner_hits: {
                size: INNER_HITS_WINDOWS_SIZE, // Mandatory
              },
              query: {
                bool: {
                  must_not: [
                    {
                      terms: {
                        'context_data.history_changes.field.keyword': forbiddenAttributes,
                      },
                    },
                  ],
                },
              },
            },
          },
        ],
        minimum_should_match: 1,
      },
    });
  }
  return restrictions;
};

export const buildDataRestrictions = async (
  context: AuthContext,
  user: AuthUser,
  opts: { includeAuthorities?: boolean | null; historyFiltering?: boolean } | null | undefined = {},
): Promise<{ must: any[]; must_not: any[] }> => {
  const must: any[] = [];
  const must_not: any[] = [];
  // If internal users of the system, we cancel rights checking
  if (INTERNAL_USERS[user.id]) {
    return { must, must_not };
  }
  // check user access
  pushAll(must, buildUserMemberAccessFilter(user, { includeAuthorities: opts?.includeAuthorities }));
  // If user have bypass, no need to check restrictions
  if (!isBypassUser(user)) {
    // region handle history protection
    pushAll(must, buildHistoryRestrictions(user, opts?.historyFiltering));
    // endregion
    // region Handle marking restrictions
    if (user.allowed_marking.length === 0) {
      // If user have no marking, he can only access to data with no markings.
      must_not.push({ exists: { field: buildRefRelationKey(RELATION_OBJECT_MARKING) } });
    } else {
      // Compute all markings that the user doesnt have access to
      const allMarkings = await getEntitiesListFromCache<StoreMarkingDefinition>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
      const mustNotHaveOneOf = [];
      const userMarkingsIds = new Set(user.allowed_marking.map((m) => m.internal_id));
      for (let index = 0; index < allMarkings.length; index += 1) {
        const marking = allMarkings[index];
        const markingId = marking.internal_id;
        if (!userMarkingsIds.has(markingId)) {
          mustNotHaveOneOf.push(markingId);
        }
      }
      // If use have marking, he can access to data with no marking && data with according marking
      const mustNotMarkingTerms = [{
        terms: {
          [buildRefRelationSearchKey(RELATION_OBJECT_MARKING)]: mustNotHaveOneOf,
        },
      }];
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
    // We want to exclude a set of entities from organization restrictions while forcing restrictions for another set of entities
    const excludedEntityMatches = {
      bool: {
        must: [
          {
            bool: { must_not: [{ terms: { 'entity_type.keyword': STIX_ORGANIZATIONS_RESTRICTED } }] },
          },
          {
            bool: {
              should: [
                { terms: { 'parent_types.keyword': STIX_ORGANIZATIONS_UNRESTRICTED } },
                { terms: { 'entity_type.keyword': STIX_ORGANIZATIONS_UNRESTRICTED } },
              ],
              minimum_should_match: 1,
            },
          },
        ],
      },
    };
    if (settings.platform_organization) {
      if (context.user_inside_platform_organization) {
        // Data are visible independently of the organizations
        // Nothing to restrict.
      } else {
        // Data with Empty granted_refs are not visible
        // Data with granted_refs users that participate to at least one
        const should: any[] = [excludedEntityMatches];
        const shouldOrgs = user.organizations
          .map((m) => ({ match: { [buildRefRelationSearchKey(RELATION_GRANTED_TO)]: m.internal_id } }));
        pushAll(should, shouldOrgs);
        // User individual or data created by this individual must be accessible
        if (user.individual_id) {
          should.push({ match: { 'internal_id.keyword': user.individual_id } });
          should.push({ match: { [buildRefRelationSearchKey(RELATION_CREATED_BY)]: user.individual_id } });
        }
        // For tasks
        should.push({ match: { 'initiator_id.keyword': user.internal_id } });
        // Access to authorized members
        pushAll(should, buildUserMemberAccessFilter(user, { includeAuthorities: opts?.includeAuthorities, excludeEmptyAuthorizedMembers: true }));
        // Finally build the bool should search
        must.push({ bool: { should, minimum_should_match: 1 } });
      }
    }
    // endregion
  }
  return { must, must_not };
};

const getRuntimeUsers = async (context: AuthContext, user: AuthUser) => {
  const users = await getEntitiesListFromCache<AuthUser>(context, user, ENTITY_TYPE_USER);
  return R.mergeAll(users.map((i) => ({ [i.internal_id]: i.name.replace(/[&/\\#,+[\]()$~%.'":*?<>{}]/g, '') })));
};
const getRuntimeMarkings = async (context: AuthContext, user: AuthUser) => {
  const identities = await getEntitiesListFromCache<BasicStoreEntityMarkingDefinition>(context, user, ENTITY_TYPE_MARKING_DEFINITION);
  return R.mergeAll(identities.map((i) => ({ [i.internal_id]: i.definition })));
};
const withInferencesEntities = (indices: string[], withInferences: boolean) => {
  return withInferences ? [READ_INDEX_INFERRED_ENTITIES, ...indices] : indices;
};
const withInferencesRels = (indices: string[], withInferences: boolean) => {
  return withInferences ? [READ_INDEX_INFERRED_RELATIONSHIPS, ...indices] : indices;
};
export const computeQueryIndices = (
  indices: string[] | string | undefined | null,
  typeOrTypes: string[] | string | undefined | null,
  withInferences = true,
): string[] | string | undefined | null => {
  const types = (Array.isArray(typeOrTypes) || isEmptyField(typeOrTypes)) ? typeOrTypes : [typeOrTypes] as string[];
  // If indices are explicitly defined, just rely on the definition
  if (isEmptyField(indices)) {
    // If not and have no clue about the expected types, ask for all indices.
    // Worst case scenario that need to be avoided.
    if (isEmptyField(types)) {
      return withInferences ? READ_DATA_INDICES : READ_DATA_INDICES_WITHOUT_INFERRED;
    }
    // If types are defined we need to infer from them the correct indices
    const definedTypes = types as string[];
    return R.uniq(definedTypes.map((findType) => {
      // If defined types are abstract, try to restrict the indices as much as possible
      if (isAbstract(findType)) {
        // For objects
        if (isBasicObject(findType)) {
          if (isInternalObject(findType)) {
            return withInferencesEntities([READ_INDEX_INTERNAL_OBJECTS], withInferences);
          }
          if (isStixMetaObject(findType)) {
            return withInferencesEntities([READ_INDEX_STIX_META_OBJECTS], withInferences);
          }
          if (isStixDomainObject(findType)) {
            return withInferencesEntities([READ_INDEX_STIX_DOMAIN_OBJECTS], withInferences);
          }
          if (isStixCoreObject(findType)) {
            return withInferencesEntities([READ_INDEX_STIX_DOMAIN_OBJECTS, READ_INDEX_STIX_CYBER_OBSERVABLES], withInferences);
          }
          if (isStixObject(findType)) {
            return withInferencesEntities([READ_INDEX_STIX_META_OBJECTS, READ_INDEX_STIX_DOMAIN_OBJECTS, READ_INDEX_STIX_CYBER_OBSERVABLES], withInferences);
          }
          return withInferences ? READ_ENTITIES_INDICES : READ_ENTITIES_INDICES_WITHOUT_INFERRED;
        }
        // For relationships
        if (isBasicRelationship(findType) || STIX_REF_RELATIONSHIP_TYPES.includes(findType)) {
          if (isInternalRelationship(findType)) {
            return withInferencesRels([READ_INDEX_INTERNAL_RELATIONSHIPS], withInferences);
          }
          if (isStixSightingRelationship(findType)) {
            return withInferencesRels([READ_INDEX_STIX_SIGHTING_RELATIONSHIPS], withInferences);
          }
          if (isStixCoreRelationship(findType)) {
            return withInferencesRels([READ_INDEX_STIX_CORE_RELATIONSHIPS], withInferences);
          }
          if (isStixRefRelationship(findType) || STIX_REF_RELATIONSHIP_TYPES.includes(findType)) {
            return withInferencesRels([READ_INDEX_STIX_META_RELATIONSHIPS, READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS], withInferences);
          }
          if (isStixRelationship(findType)) {
            return withInferencesRels([READ_INDEX_STIX_CORE_RELATIONSHIPS, READ_INDEX_STIX_SIGHTING_RELATIONSHIPS, READ_INDEX_STIX_META_RELATIONSHIPS,
              READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS], withInferences);
          }
          return withInferences ? READ_RELATIONSHIPS_INDICES : READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED;
        }
        // Fallback
        throw UnsupportedError('Fail to compute indices for unknown type', { type: findType });
      }
      // If concrete type, infer the index from the type
      if (isBasicObject(findType)) {
        return withInferencesEntities([`${inferIndexFromConceptType(findType)}*`], withInferences);
      }
      return withInferencesRels([`${inferIndexFromConceptType(findType)}*`], withInferences);
    }).flat());
  }
  return indices;
};
// Default fetch used by loadThroughDenormalized
// This rel_ must be low volume
// DO NOT ADD Anything here if you are not sure about that you doing
const REL_DEFAULT_SUFFIX = '*.keyword';
export const REL_DEFAULT_FETCH = [
  // SECURITY
  `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}${REL_DEFAULT_SUFFIX}`,
  `${REL_INDEX_PREFIX}${RELATION_GRANTED_TO}${REL_DEFAULT_SUFFIX}`,
  // DEFAULT (LOW VOLUME)
  `${REL_INDEX_PREFIX}${RELATION_COVERED}${REL_DEFAULT_SUFFIX}`,
  `${REL_INDEX_PREFIX}${RELATION_RESULT_OF}${REL_DEFAULT_SUFFIX}`,
  `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}${REL_DEFAULT_SUFFIX}`,
  `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}${REL_DEFAULT_SUFFIX}`,
  `${REL_INDEX_PREFIX}${RELATION_OBJECT_PARTICIPANT}${REL_DEFAULT_SUFFIX}`,
  `${REL_INDEX_PREFIX}${RELATION_OBJECT_ASSIGNEE}${REL_DEFAULT_SUFFIX}`,
  `${REL_INDEX_PREFIX}${RELATION_KILL_CHAIN_PHASE}${REL_DEFAULT_SUFFIX}`,
  `${REL_INDEX_PREFIX}${RELATION_BORN_IN}${REL_DEFAULT_SUFFIX}`,
  `${REL_INDEX_PREFIX}${RELATION_ETHNICITY}${REL_DEFAULT_SUFFIX}`,
  `${REL_INDEX_PREFIX}${RELATION_SAMPLE}${REL_DEFAULT_SUFFIX}`,
  `${REL_INDEX_PREFIX}${RELATION_PARTICIPATE_TO}${REL_DEFAULT_SUFFIX}`,
  `${REL_INDEX_PREFIX}${RELATION_IN_PIR}${REL_DEFAULT_SUFFIX}`,
];
export const REL_COUNT_SCRIPT_FIELD = {
  script: {
    lang: 'painless',
    source: `
          int totalElements = 0;
          for (String fieldName : params['_source'].keySet()) {
            if (fieldName.startsWith('rel_')) {
              def fieldValue = params['_source'].get(fieldName);
              if (fieldValue != null) {
                if (fieldValue instanceof List) {
                  totalElements += ((List) fieldValue).size();
                } else {
                  totalElements++;
                }
              }
            }
          }
          return totalElements;
        `,
  },
};
export const BASE_FIELDS = [
  '_index',
  idAttribute.name,
  internalId.name,
  standardId.name,
  'sort',
  baseType.name,
  entityTypeAttribute.name,
  connectionsAttribute.name,
  'first_seen',
  'last_seen',
  'start_time',
  'stop_time',
  authorizedMembers.name,
];
export const RANGE_OPERATORS = ['gt', 'gte', 'lt', 'lte'];

export const findElementsDuplicateIds = (elements: BasicStoreBase[]): string[] => {
  const duplicatedIds = new Set<string>();
  const elementIds = new Set<string>();
  const checkCurrentIds = (id: string | undefined | null) => {
    if (!id) return;
    if (elementIds.has(id) && !duplicatedIds.has(id)) {
      duplicatedIds.add(id);
    } else {
      elementIds.add(id);
    }
  };
  for (let i = 0; i < elements.length; i += 1) {
    const element = elements[i];
    const { internal_id, standard_id, x_opencti_stix_ids, i_aliases_ids } = element;
    checkCurrentIds(internal_id);
    checkCurrentIds(standard_id);
    x_opencti_stix_ids?.map((id) => checkCurrentIds(id));
    i_aliases_ids?.map((id) => checkCurrentIds(id));
  }
  return Array.from(duplicatedIds);
};

export const specialElasticCharsEscape = (query: string) => {
  return query.replace(/([/+|\-*()^~={}[\]:?!"\\])/g, '\\$1');
};
const specialElasticCharsEscapeWithLuceneSyntax = (query: string) => {
  return query.replace(/([/+|\-()^={}[\]:?!"\\])/g, '\\$1');
};

// Global search attributes are limited
// Its due to opensearch / elastic limitations
const BASE_SEARCH_CONNECTIONS = [
  // Pounds for connections search
  `connections.${ATTRIBUTE_NAME}^4`,
  // Add all other attributes
  'connections.*',
];
const BASE_SEARCH_HISTORY = [
  // Pounds for history search
  'context_data.history_changes.field^4',
  // Add all other attributes
  'context_data.history_changes.changes_added.raw',
  'context_data.history_changes.changes_removed.raw',
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
  'context_data.search',
  // Add all other attributes
  'aliases',
  'x_opencti_aliases',
  'persona_name',
  'source_name',
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
  'account_login',
  'user_id',
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

type ProcessSearchArgs = {
  useWildcardPrefix?: boolean;
  historyFiltering?: boolean;
};

// Hard cap user-provided search input to limit normalization + query parsing cost
const MAX_SEARCH_LENGTH = 512;

function processSearch(
  search: string,
  args: ProcessSearchArgs,
): { exactSearch: string[]; querySearch: string[] } {
  const { useWildcardPrefix } = args;
  const boundedSearch = search.length > MAX_SEARCH_LENGTH ? search.slice(0, MAX_SEARCH_LENGTH) : search;

  let decodedSearch;
  try {
    decodedSearch = decodeURIComponent(refang(boundedSearch))
      .trim();
  } catch (_e) {
    decodedSearch = refang(boundedSearch).trim();
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
    const cleanElement = specialElasticCharsEscapeWithLuceneSyntax(partialElement);
    if (isNotEmptyField(cleanElement)) {
      querySearch.push(`${useWildcardPrefix ? '*' : ''}${cleanElement}*`);
    }
  }
  return {
    exactSearch,
    querySearch,
  };
}
export const elGenerateFullTextSearchShould = (search: string, args: ProcessSearchArgs = {}) => {
  const { exactSearch, querySearch } = processSearch(search, args);
  // Return the elastic search engine expected bool should terms
  // Build the search for all exact match (between double quotes)
  const shouldSearch: unknown[] = [];
  const searchPhrase = R.uniq(querySearch).join(' ');
  const cleanExactSearch = R.uniq(exactSearch.map((e) => e.replace(/"|https?:/g, '')));
  if (args.historyFiltering) {
    pushAll(shouldSearch, cleanExactSearch.map((ex) => [
      {
        bool: {
          must: [
            { terms: { 'entity_type.keyword': [ENTITY_TYPE_ACTIVITY, ENTITY_TYPE_HISTORY] } },
            {
              multi_match: {
                type: 'phrase',
                query: ex,
                lenient: true,
                fields: BASE_SEARCH_ATTRIBUTES,
              },
            },
          ],
        },
      },
      {
        nested: {
          path: 'context_data.history_changes',
          query: {
            bool: {
              must: [
                {
                  multi_match: {
                    type: 'phrase',
                    query: ex,
                    lenient: true,
                    fields: BASE_SEARCH_HISTORY,
                  },
                },
              ],
            },
          },
        },
      },
    ]).flat());
    if (searchPhrase) {
      shouldSearch.push({
        bool: {
          must: [
            { terms: { 'entity_type.keyword': [ENTITY_TYPE_ACTIVITY, ENTITY_TYPE_HISTORY] } },
            {
              query_string: {
                query: searchPhrase,
                analyze_wildcard: true,
                fields: BASE_SEARCH_ATTRIBUTES,
              },
            },
          ],
        },
      });
      shouldSearch.push({
        nested: {
          path: 'context_data.history_changes',
          query: {
            bool: {
              must: [
                {
                  query_string: {
                    query: searchPhrase,
                    analyze_wildcard: true,
                    fields: BASE_SEARCH_HISTORY,
                  },
                },
              ],
            },
          },
        },
      });
    }
  } else {
    pushAll(shouldSearch, cleanExactSearch.map((ex) => [
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
    ]).flat());
    if (searchPhrase) {
      pushAll(shouldSearch, [
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
  }
  return shouldSearch;
};

export const elGenerateFieldTextSearchShould = (
  search: string,
  arrayKeys: string[],
  args: ProcessSearchArgs = {},
) => {
  const { exactSearch, querySearch } = processSearch(search, args);
  const cleanExactSearch = R.uniq(exactSearch.map((e) => e.replace(/"|http?:/g, '')));
  const shouldSearch: unknown[] = [];
  pushAll(shouldSearch, cleanExactSearch.map((ex) => [
    {
      multi_match: {
        type: 'phrase',
        query: ex,
        lenient: true,
        fields: arrayKeys,
      },
    },
  ]).flat());
  // Build the search for all other fields
  const searchPhrase = R.uniq(querySearch).join(' ');
  if (searchPhrase) {
    pushAll(shouldSearch, [
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
      },
    ]);
  }

  return shouldSearch;
};
export const buildFieldForQuery = (field: string) => {
  return isDateNumericOrBooleanAttribute(field) || field === '_id' || isObjectFlatAttribute(field)
    ? field
    : `${field}.keyword`;
};
const buildFieldForScriptQuery = (field: string) => {
  return buildFieldForQuery(field).replaceAll('*', 'internal_id');
};
export const buildLocalMustFilter = (validFilter: any) => {
  const valuesFiltering = [];
  const noValuesFiltering = [];
  const { key, values, nested, operator = 'eq', mode: localFilterMode = 'or' } = validFilter;
  if (isEmptyField(key)) {
    throw FunctionalError('A filter key must be defined', { key });
  }
  const arrayKeys = Array.isArray(key) ? key : [key];
  const headKey = R.head(arrayKeys);
  const dontHandleMultipleKeys = nested || operator === 'nil' || operator === 'not_nil' || operator === 'only_eq_to' || operator === 'not_only_eq_to';
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
      // nil and not_nil operators
      if (nestedOperator === 'nil') {
        nestedMustNot.push({
          exists: {
            field: nestedFieldKey,
          },
        });
      } else if (nestedOperator === 'not_nil') {
        nestedShould.push({
          exists: {
            field: nestedFieldKey,
          },
        });
      }
      // other operators
      if (nestedKey === ID_INTERNAL) {
        if (nestedOperator === 'not_eq') {
          nestedMustNot.push({ terms: { [`${nestedFieldKey}.keyword`]: nestedValues } });
        } else { // nestedOperator = 'eq'
          nestedShould.push({ terms: { [`${nestedFieldKey}.keyword`]: nestedValues } });
        }
      } else { // nested key !== internal_id
        if (nestedOperator === FilterOperator.Within) {
          nestedShould.push({
            range: {
              [nestedFieldKey]: { gte: nestedValues[0], lte: nestedValues[1] },
            },
          });
        } else if (isNotEmptyField(nestedValues)) {
          for (let i = 0; i < nestedValues.length; i += 1) {
            const nestedSearchValue = nestedValues[i].toString();
            if (nestedOperator === 'wildcard') {
              nestedShould.push({ query_string: { query: `${nestedSearchValue}`, fields: [nestedFieldKey] } });
            } else if (nestedOperator === 'not_eq') {
              nestedMustNot.push({
                multi_match: {
                  fields: buildFieldForQuery(nestedFieldKey),
                  query: nestedSearchValue.toString(),
                },
              });
            } else if (['contains', 'not_contains', 'starts_with', 'not_starts_with', 'ends_with', 'not_ends_with'].includes(nestedOperator)) {
              // Substring/prefix/suffix match on a nested string field, mirroring the non-nested handling:
              // wildcarded query_string on the .keyword sub-field, routed to must (positive) or must_not (negated).
              const target = nestedOperator.startsWith('not_') ? nestedMustNot : nestedShould;
              const val = specialElasticCharsEscape(nestedSearchValue).replace(/\s/g, '\\ ');
              let query;
              if (nestedOperator === 'contains' || nestedOperator === 'not_contains') {
                query = `*${val}*`;
              } else if (nestedOperator === 'starts_with' || nestedOperator === 'not_starts_with') {
                query = `${val}*`;
              } else {
                query = `*${val}`;
              }
              target.push({ query_string: { query, analyze_wildcard: true, fields: [`${nestedFieldKey}.keyword`] } } as any);
            } else if (RANGE_OPERATORS.includes(nestedOperator)) {
              nestedShould.push({
                range: {
                  [nestedFieldKey]: { [nestedOperator]: nestedSearchValue },
                },
              });
            } else { // nestedOperator = 'eq'
              nestedShould.push({
                multi_match: {
                  fields: buildFieldForQuery(nestedFieldKey),
                  query: nestedSearchValue.toString(),
                },
              });
            }
          }
        }
      }
      // Only add a should clause when there is at least one positive condition; a negated-only
      // operator (not_eq / not_contains / nil ...) puts its clause in nestedMustNot and must not
      // be paired with an empty should (minimum_should_match would otherwise match nothing).
      if (nestedShould.length > 0) {
        const should = {
          bool: {
            should: nestedShould,
            minimum_should_match: localFilterMode === 'or' ? 1 : nestedValues.length,
          },
        };
        nestedMust.push(should);
      }
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
    let valueFiltering: any = { // classic filters: field doesn't exist
      bool: {
        must_not: {
          exists: {
            field: headKey,
          },
        },
      },
    };
    if (filterDefinition?.type === 'string') {
      if (filterDefinition?.format === 'text') { // text filters: use wildcard
        valueFiltering = {
          bool: {
            must_not: {
              wildcard: {
                [headKey]: '*',
              },
            },
          },
        };
      } else { // string filters: nil <-> (field doesn't exist) OR (field = empty string)
        valueFiltering = {
          bool: {
            should: [
              {
                bool: {
                  must_not: {
                    exists: {
                      field: headKey,
                    },
                  },
                },
              },
              {
                term: {
                  [headKey === '_id' ? headKey : `${headKey}.keyword`]: { value: '' },
                },
              },
            ],
            minimum_should_match: 1,
          },
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
                    field: headKey,
                  },
                },
              },
            },
            { range: { [headKey]: { lte: '1970-01-01T01:00:00.000Z' } } },
            { range: { [headKey]: { gte: '5138-11-16T09:46:40.000Z' } } },
          ],
          minimum_should_match: 1,
        },
      };
    }
    valuesFiltering.push(valueFiltering);
  } else if (operator === 'not_nil') {
    const filterDefinition = schemaAttributesDefinition.getAttributeByName(headKey);
    let valueFiltering: any = { // classic filters: field exists
      exists: {
        field: headKey,
      },
    };
    if (filterDefinition?.type === 'string') {
      if (filterDefinition?.format === 'text') { // text filters: use wildcard
        valueFiltering = {
          bool: {
            must: {
              wildcard: {
                [headKey]: '*',
              },
            },
          },
        };
      } else { // other filters: not_nil <-> (field exists) AND (field != empty string)
        valueFiltering = {
          bool: {
            must: [
              {
                exists: {
                  field: headKey,
                },
              },
              {
                bool: {
                  must_not: {
                    term: {
                      [headKey === '_id' ? headKey : `${headKey}.keyword`]: { value: '' },
                    },
                  },
                },
              },
            ],
          },
        };
      }
    } else if (filterDefinition?.type === 'date') { // date filters: not_nil <-> (field exists) AND (date > epoch) AND (date < 5138)
      valueFiltering = {
        bool: {
          must: [
            {
              exists: {
                field: headKey,
              },
            },
            { range: { [headKey]: { gt: '1970-01-01T01:00:00.000Z' } } },
            { range: { [headKey]: { lt: '5138-11-16T09:46:40.000Z' } } },
          ],
        },
      };
    }
    valuesFiltering.push(valueFiltering);
  }
  // 03. Handle values according to the operator
  if (operator !== 'nil' && operator !== 'not_nil') {
    if (operator === 'within') {
      if (arrayKeys.length > 1) {
        throw UnsupportedError('Within filter must have only one field', { keys: arrayKeys });
      }
      if (values.length !== 2) {
        throw UnsupportedError('Within filter must have two values', { values });
      }
      valuesFiltering.push({ range: { [headKey]: { gte: values[0], lte: values[1] } } });
    } else {
      // case where we would like to build a terms query
      const isTermsQuery = (operator === 'eq' || operator === 'not_eq') && values.length > 0 && !values.includes('EXISTS')
        && arrayKeys.every((k) => (!k.includes('*') && (k.endsWith(ID_INTERNAL) || k.endsWith(ID_INFERRED))) || IDS_ATTRIBUTES.includes(k) || KEYWORD_TERMS_ATTRIBUTES.includes(k));
      if (isTermsQuery) {
        if (operator === 'eq') {
          for (let i = 0; i < arrayKeys.length; i += 1) {
            valuesFiltering.push({
              terms: { [`${arrayKeys[i]}.keyword`]: values },
            });
          }
        } else {
          valuesFiltering.push({
            bool: {
              must_not: arrayKeys.map((k) => ({
                terms: { [`${k}.keyword`]: values },
              })),
            },
          });
        }
      } else {
        for (let i = 0; i < values.length; i += 1) {
          if (values[i] === 'EXISTS') {
            if (arrayKeys.length > 1) {
              throw UnsupportedError('Filter must have only one field', { keys: arrayKeys });
            }
            if (operator === 'eq') {
              valuesFiltering.push({ exists: { field: headKey } });
            } else {
              noValuesFiltering.push({ exists: { field: headKey } });
            }
          } else if (operator === 'eq' || operator === 'not_eq') {
            const targets = operator === 'eq' ? valuesFiltering : noValuesFiltering;
            targets.push({
              multi_match: {
                fields: arrayKeys.map((k) => buildFieldForQuery(k)),
                query: values[i].toString(),
              },
            });
          } else if (operator === 'only_eq_to' || operator === 'not_only_eq_to') {
            const targets = operator === 'only_eq_to' ? valuesFiltering : noValuesFiltering;
            targets.push({
              script: {
                script: {
                  source: `
                    def fieldValues = doc[params.field];
                    if (fieldValues == null || fieldValues.length == 0) return false;
                    def filterValues = params.values;
                    if (params.mode == 'and') {
                      return fieldValues.length == filterValues.length && fieldValues.every(v -> filterValues.contains(v));
                    } else if (params.mode == 'or') {
                      return fieldValues.length == 1 && filterValues.contains(fieldValues[0]);
                    }
                    return false;
                  `,
                  params: {
                    field: buildFieldForScriptQuery(headKey),
                    values,
                    mode: localFilterMode,
                  },
                },
              },
            });
          } else if (operator === 'match') {
            valuesFiltering.push({
              multi_match: {
                fields: arrayKeys,
                query: values[i].toString(),
              },
            });
          } else if (operator === 'wildcard' || operator === 'not_wildcard') {
            const targets = operator === 'wildcard' ? valuesFiltering : noValuesFiltering;
            const val = specialElasticCharsEscape(values[i].toString());
            targets.push({
              query_string: {
                query: values[i] === '*' ? values[i] : `"${val}"`,
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
            if (!isEsScriptFilterEnabled()) {
              throw UnsupportedError('Filter script is not allowed', { filter: validFilter });
            }
            valuesFiltering.push({
              script: {
                script: values[i].toString(),
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
          } else if (RANGE_OPERATORS.includes(operator)) { // range operators
            if (arrayKeys.length > 1) {
              throw UnsupportedError('Range filter must have only one field', { keys: arrayKeys });
            }
            valuesFiltering.push({
              range: {
                [headKey]: { [operator]: values[i] },
              },
            });
          } else {
            throw UnsupportedError('Not supported filter operator', { filter: validFilter, filterOperator: operator });
          }
        }
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
            must_not: [o],
          },
        })),
        minimum_should_match: localFilterMode === 'or' ? 1 : noValuesFiltering.length,
      },
    };
  }
  throw UnsupportedError('Invalid filter configuration', validFilter);
};

export const POST_FILTER_TAG_SEPARATOR = ';';
export const NAMED_QUERIES_UNIQUENESS_SEPARATOR = ':';
const buildSubQueryForFilterGroup = (
  context: AuthContext,
  user: AuthUser,
  inputFilters: FilterGroup,
  currentSaltCount = 0,
): { subQuery: any; postFiltersTags: Set<string>; resultSaltCount: number } => {
  const { mode = 'and', filters = [], filterGroups = [] } = inputFilters;
  const localSubQueries: { subQuery: any; associatedTags: Set<string> }[] = [];
  const localPostFilterTags = new Set<string>();
  let localSaltCount = currentSaltCount;
  // Handle filterGroups
  for (let index = 0; index < filterGroups.length; index += 1) {
    const group = filterGroups[index];
    if (isFilterGroupNotEmpty(group)) {
      const { subQuery, postFiltersTags, resultSaltCount } = buildSubQueryForFilterGroup(context, user, group, localSaltCount);
      localSaltCount = resultSaltCount;
      if (subQuery) { // can be null
        localSubQueries.push({ subQuery, associatedTags: postFiltersTags });
      }
      postFiltersTags.forEach((t: string) => localPostFilterTags.add(t));
    }
  }
  // Handle filters
  for (let index = 0; index < filters.length; index += 1) {
    const filter = filters[index] as FiltersWithNested & { postFilteringTag?: string };
    const isValidFilter = filter.values || (filter.nested && filter.nested?.length > 0);
    if (isValidFilter) {
      const localMustFilter = buildLocalMustFilter(filter);
      if (filter.postFilteringTag) {
        const associatedTag = filter.postFilteringTag;
        localPostFilterTags.add(associatedTag);
        const associatedTags = new Set<string>([associatedTag]);
        localSubQueries.push({ subQuery: localMustFilter, associatedTags });
      } else {
        localSubQueries.push({ subQuery: localMustFilter, associatedTags: new Set<string>() });
      }
    }
  }

  // Wrap every tagged subquery in a bool must with _name tag
  const localMustFilters = localSubQueries.map(({ subQuery, associatedTags }) => {
    const tagsToApply = mode === 'or' ? [...localPostFilterTags].filter((t: string) => !associatedTags.has(t)) : [];
    if (tagsToApply.length > 0) {
      const nameToApply = tagsToApply.join(POST_FILTER_TAG_SEPARATOR) + NAMED_QUERIES_UNIQUENESS_SEPARATOR + localSaltCount;
      localSaltCount += 1;
      return {
        bool: {
          must: [subQuery],
          ['_name']: nameToApply,
        },
      };
    }
    return subQuery;
  });

  const currentSubQuery = localMustFilters.length > 0
    ? {
        bool: {
          should: localMustFilters,
          minimum_should_match: mode === 'or' ? 1 : localMustFilters.length,
        },
      }
    : null;
  return { subQuery: currentSubQuery, postFiltersTags: localPostFilterTags, resultSaltCount: localSaltCount };
};

const getRuntimeEntities = async (context: AuthContext, user: AuthUser, entityType: string) => {
  const elements = await elPaginate<BasicStoreEntity>(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, {
    types: [entityType],
    first: MAX_RUNTIME_RESOLUTION_SIZE,
    bypassSizeLimit: true, // ensure that max runtime prevent on ES_MAX_PAGINATION
    connectionFormat: false,
  }) as BasicStoreEntity[];
  return R.mergeAll(elements.map((i) => ({ [i.internal_id]: i.name })));
};
/**
 * ⚠️ MAINTENANCE: When adding a new runtime attribute here AND exposing it as a sortable column
 * in the front-end (isSortable: true in dataTableUtils.tsx), you MUST also add it to
 * `RUNTIME_ONLY_SORT_FIELDS` in the front-end:
 * opencti-platform/opencti-front/src/utils/hooks/useRuntimeSortGuard.ts
 *
 * Failing to do so will cause an UnsupportedError on OpenSearch instances.
 */
export const RUNTIME_ATTRIBUTES: Record<string, any> = {
  observable_value: {
    field: 'observable_value.keyword',
    type: 'keyword',
    getSource: async () => runtimeFieldObservableValueScript(),
    getParams: async () => { },
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
    getParams: async (context: AuthContext, user: AuthUser) => getRuntimeEntities(context, user, ENTITY_TYPE_IDENTITY),
  },
  deletedBy: {
    field: 'deletedBy.keyword',
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
    getParams: async (context: AuthContext, user: AuthUser) => getRuntimeUsers(context, user),
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
    getParams: async (context: AuthContext, user: AuthUser) => getRuntimeEntities(context, user, ENTITY_TYPE_LOCATION_COUNTRY),
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
    getParams: async (context: AuthContext, user: AuthUser) => getRuntimeEntities(context, user, ENTITY_TYPE_LOCATION_COUNTRY),
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
    getParams: async (context: AuthContext, user: AuthUser) => getRuntimeUsers(context, user),
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
    getParams: async (context: AuthContext, user: AuthUser) => getRuntimeMarkings(context, user),
  },
  killChainPhases: {
    field: 'killChainPhases.keyword',
    type: 'keyword',
    getSource: async () => `
        if (doc.containsKey('rel_kill-chain-phase.internal_id')) {
          def killChainPhaseId = doc['rel_kill-chain-phase.internal_id.keyword'];
          if (killChainPhaseId.size() >= 1) {
            def killChainPhaseName = params[killChainPhaseId[0]];
            emit(killChainPhaseName != null ? killChainPhaseName : 'Unknown')
          } else {
            emit('Unknown')
          }
        } else {
          emit('Unknown')
        }
    `,
    getParams: async (context: AuthContext, user: AuthUser) => getRuntimeEntities(context, user, ENTITY_TYPE_KILL_CHAIN_PHASE),
  },
  objectAssignee: {
    field: 'objectAssignee.keyword',
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
    getParams: async (context: AuthContext, user: AuthUser) => getRuntimeUsers(context, user),
  },
  objectParticipant: {
    field: 'objectParticipant.keyword',
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
    getParams: async (context: AuthContext, user: AuthUser) => getRuntimeUsers(context, user),
  },
};
export type QueryBodyBuilderOpts = ProcessSearchArgs & BuildDraftFilterOpts & {
  ids?: string[];
  after?: string | null;
  orderBy?: any;
  orderMode?: 'asc' | 'desc' | null;
  pirId?: string | null;
  noSize?: boolean | null;
  noSort?: boolean | null;
  intervalInclude?: boolean | null;
  relCount?: boolean | null;
  first?: number | null;
  types?: string[] | null;
  search?: string | null;
  filters?: FilterGroup | null;
  noFiltersChecking?: boolean;
  noRegardingOfFilterIdsCheck?: boolean;
  historyFiltering?: boolean;
  startDate?: any;
  endDate?: any;
  dateAttribute?: string | null;
  includeAuthorities?: boolean | null;
  /**
   * Trusted, internal-only raw Painless script clauses (ANDed with the rest of the query).
   * MUST NEVER be populated from user/GraphQL/JSON input.
   */
  internalScriptFilters?: string[];
};
export const elQueryBodyBuilder = async (context: AuthContext, user: AuthUser, options: QueryBodyBuilderOpts) => {
  const {
    ids = [],
    after,
    orderBy = null,
    pirId = null,
    orderMode = 'asc',
    noSize = false,
    noSort = false,
    intervalInclude = false,
    relCount = false,
    first = ES_DEFAULT_PAGINATION,
    types = null,
    search = null,
    filters,
    noFiltersChecking,
    startDate = null,
    historyFiltering = false,
    endDate = null,
    dateAttribute = null,
    includeAuthorities = false,
    noRegardingOfFilterIdsCheck = false,
    internalScriptFilters = [],
  } = options;
  const elFindByIdsToMap = async (c: AuthContext, u: AuthUser, i: string[], o: any) => {
    return elFindByIds<BasicStoreObject>(c, u, i, { ...o, toMap: true }) as Promise<Record<string, BasicStoreObject>>;
  };
  const convertedFilters = await checkAndConvertFilters(context, user, filters, user.id, elFindByIdsToMap, { noFiltersChecking });
  const searchAfter = after ? cursorToOffset(after) : undefined;
  let ordering: any[] = [];
  // Handle marking restrictions
  const markingRestrictions = await buildDataRestrictions(context, user, { historyFiltering, includeAuthorities });
  const accessMust = markingRestrictions.must;
  const accessMustNot = markingRestrictions.must_not;
  const mustFilters = [];
  // Trusted, internal-only raw Painless script clauses. These never go through the filter
  // grammar (buildLocalMustFilter / checkAndConvertFilters): they can only be populated by
  // hardcoded backend TS code, never by user/GraphQL/JSON input.
  internalScriptFilters.forEach((source) => {
    mustFilters.push({ script: { script: { source } } });
  });
  // Add special keys to filters
  const specialFiltersContent: any = [];
  if (ids.length > 0 || startDate || endDate || (types !== null && types.length > 0)) {
    if (ids.length > 0) {
      specialFiltersContent.push({ key: IDS_FILTER, values: ids });
    }
    if (startDate) {
      specialFiltersContent.push({ key: dateAttribute || 'created_at', values: [startDate], operator: intervalInclude ? 'gte' : 'gt' });
    }
    if (endDate) {
      specialFiltersContent.push({ key: dateAttribute || 'created_at', values: [endDate], operator: intervalInclude ? 'lte' : 'lt' });
    }
    if (types !== null && types.length > 0) {
      specialFiltersContent.push({ key: TYPE_FILTER, values: R.flatten(types) });
    }
  }
  const completeFilters = specialFiltersContent.length > 0 ? {
    mode: FilterMode.And,
    filters: specialFiltersContent,
    filterGroups: isFilterGroupNotEmpty(convertedFilters) ? [convertedFilters as FilterGroup] : [],
  } : convertedFilters;
  // Handle filters
  if (completeFilters && isFilterGroupNotEmpty(completeFilters)) {
    const finalFilters = await completeSpecialFilterKeys(context, user, completeFilters, { noRegardingOfFilterIdsCheck });
    const { subQuery: filtersSubQuery } = buildSubQueryForFilterGroup(context, user, finalFilters);
    if (filtersSubQuery) {
      mustFilters.push(filtersSubQuery);
    }
  }
  // Handle search
  const orderConfiguration = isEmptyField(orderBy) ? [] : orderBy;
  const orderCriterion = Array.isArray(orderConfiguration) ? orderConfiguration : [orderConfiguration];
  let scoreSearchOrder = orderMode;
  if (search !== null && search.length > 0) {
    const shouldSearch = elGenerateFullTextSearchShould(search, options);
    const bool = {
      bool: {
        should: shouldSearch,
        minimum_should_match: 1,
      },
    };
    mustFilters.push(bool);
    // When using a search, force a score ordering if nothing specified
    if (orderCriterion.length === 0) {
      orderCriterion.unshift('_score');
      scoreSearchOrder = 'desc';
    }
  }
  // Handle orders
  const runtimeMappings: any = {};
  if (isNotEmptyField(orderCriterion)) {
    for (let index = 0; index < orderCriterion.length; index += 1) {
      const orderCriteria = orderCriterion[index];
      if (orderCriteria === '_score') {
        ordering = R.append({ [orderCriteria]: scoreSearchOrder }, ordering);
      } else {
        const sortingForCriteria = await buildElasticSortingForAttributeCriteria(context, user, orderCriteria, orderMode, pirId);
        ordering = R.append(sortingForCriteria, ordering);
      }
    }
    // Add standard_id if not specify to ensure ordering uniqueness
    if (!orderCriterion.includes('standard_id')) {
      ordering.push({ 'standard_id.keyword': 'asc' });
    }
    // Build runtime mappings
    const runtime = RUNTIME_ATTRIBUTES[orderBy as string];
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
  // Handle draft
  const draftMust = buildDraftFilter(context, user, options);
  // Build query
  const body: any = {
    query: {
      bool: {
        must: [...accessMust, ...mustFilters, ...draftMust],
        must_not: accessMustNot,
      },
    },
  };
  if (relCount) {
    body.script_fields = {
      script_field_denormalization_count: REL_COUNT_SCRIPT_FIELD,
    };
  }
  if (!noSize) {
    body.size = first;
  }
  if (!noSort) {
    body.sort = ordering;
  }
  // Add extra configuration
  if (isNotEmptyField(runtimeMappings)) {
    const isRuntimeSortFeatureEnable = isRuntimeSortEnable();
    if (!isRuntimeSortFeatureEnable) {
      throw UnsupportedError('Runtime mapping is only possible with elastic >=7.12', { order: orderBy });
    }
    body.runtime_mappings = runtimeMappings;
  }
  if (searchAfter) {
    body.search_after = searchAfter;
  }
  return body;
};
