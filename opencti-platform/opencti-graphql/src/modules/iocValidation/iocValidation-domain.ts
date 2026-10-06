import { v4 as uuidv4 } from 'uuid';
import { Promise as BluePromise } from 'bluebird';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase, BasicStoreEntity, BasicStoreRelation } from '../../types/store';
import type { StixId } from '../../types/stix-2-1-common';
import conf, { BUS_TOPICS, logApp } from '../../config/conf';
import { ForbiddenAccess, FunctionalError, ValidationError } from '../../config/errors';
import { buildReplaceScriptParams, EL_REPLACE_SCRIPT_SOURCE, elUpdate } from '../../database/engine';
import { createRelation, deleteElementById, patchAttribute, stixLoadByIds } from '../../database/middleware';
import { notify, redisGetManagerEventState, redisSetManagerEventState } from '../../database/redis';
import { isEmptyField, isNotEmptyField, UPDATE_OPERATION_REPLACE } from '../../database/utils';
import { getEntityFromCache } from '../../database/cache';
import type { BasicStoreSettings } from '../../types/settings';
import { isEnterpriseEditionFromSettings } from '../../enterprise-edition/ee';
import { lockResources } from '../../lock/master-lock';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, INPUT_GRANTED_REFS, INPUT_MARKINGS } from '../../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { cleanMarkings } from '../../utils/markingDefinition-utils';
import { fullEntitiesList, fullRelationsList, internalFindByIds, internalLoadById, pageEntitiesConnection, storeLoadById, storeLoadByIds } from '../../database/middleware-loader';
import { connectorsForEnrichment } from '../../database/repository';
import { pushToConnector } from '../../database/rabbitmq';
import { createWork, reportExpectation } from '../../domain/work';
import { createInternalObject, deleteInternalObject } from '../../domain/internalObject';
import { CONNECTOR_INTERNAL_ENRICHMENT } from '../../schema/general';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { isBypassUser, isUserHasCapability, SYSTEM_USER } from '../../utils/access';
import type { BasicStoreEntityConnector } from '../../types/connector';
import { resolveUserByIdFromCache } from '../user/user-domain';
import { addIocValidationPlatformResultCount, addIocValidationRequestCreationCount } from '../../manager/telemetryManager';
import { ENTITY_TYPE_INDICATOR, type BasicStoreEntityIndicator } from '../indicator/indicator-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM, type BasicStoreEntitySecurityPlatform } from '../securityPlatform/securityPlatform-types';
import {
  type BasicStoreRelationDeployedOn,
  LIVE_DEPLOYMENT_STATUSES,
  RELATION_DEPLOYED_ON,
  VALIDATION_STATUS_ERROR,
  VALIDATION_STATUS_MISSED,
  VALIDATION_STATUS_NOT_REQUESTED,
  VALIDATION_STATUS_REQUESTED,
} from '../indicatorDeployment/indicatorDeployment-types';
import { ensureCreatedPairAccess, findDeployedOn, pairLockKey, refreshIndicatorDeploymentCounters } from '../indicatorDeployment/indicatorDeployment-domain';
import { checkEndsWithoutAuthorizedMembers, pairMarkings, pairOrganizations, validationResultSightingStixId } from '../indicatorDeployment/indicatorDeployment-utils';
import { sightingReportContext } from '../indicatorDeployment/indicatorDeployment-sightings';
import type {
  IocValidationRequestStatusInput,
  MutationIndicatorsRequestValidationArgs,
  MutationIocValidationReportResultsArgs,
  QueryIocValidationRequestsArgs,
} from '../../generated/graphql';
import { buildIocValidationRequestForOpenAEV, type IocValidationBundlePair } from './iocValidation-converter';
import {
  type BasicStoreEntityIocValidationRequest,
  ENTITY_TYPE_IOC_VALIDATION_REQUEST,
  FINAL_REQUEST_STATUSES,
  type IocValidationIoc,
  type IocValidationPair,
  type IocValidationRequestStatus,
  type IocValidationSkipped,
  type IocValidationTestKind,
  IOC_VALIDATION_CONNECTOR_SCOPE,
  IOC_VALIDATION_MAX_INDICATORS,
  IOC_VALIDATION_MAX_PLATFORMS,
  OPEN_REQUEST_STATUSES,
  OPENAEV_REPORTABLE_STATUSES,
  REQUEST_STATUS_AWAITING_APPROVAL,
  REQUEST_STATUS_COMPLETED,
  REQUEST_STATUS_EXPIRED,
  REQUEST_STATUS_FAILED,
  REQUEST_STATUS_PARTIAL,
  REQUEST_STATUS_PENDING,
  REQUEST_STATUS_REJECTED,
  REQUEST_STATUS_RUNNING,
  REQUEST_STATUS_SENT,
  type StoreEntityIocValidationRequest,
} from './iocValidation-types';
import {
  emptyResultsSummary,
  extractIocFromIndicator,
  isIocValidationTestKind,
  isSummaryComplete,
  isTrustedDeploymentReporter,
  requestAccessEndsOf,
  requestAccessOf,
  requesterIdOf,
  summarizeValidationResults,
} from './iocValidation-utils';

const toPositiveInteger = (value: unknown, fallback: number) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};
const IOC_VALIDATION_TIMEOUT_MS = toPositiveInteger(conf.get('ioc_validation:timeout_days'), 7) * 24 * 3600 * 1000;
// Completed requests keep their summary refreshed for this window, absorbing late bundle ingestion.
const SUMMARY_REFRESH_WINDOW_MS = 24 * 3600 * 1000;
const CONCURRENCY = 5;
const SKIP_REASON_NOT_DEPLOYED = 'Not deployed on this security platform';
const MAINTENANCE_PAGE_SIZE = 100;
const MAINTENANCE_CURSOR_STATE = 'ioc_validation_requests_maintenance';
const NAME_MAX_LENGTH = 250;
const DESCRIPTION_MAX_LENGTH = 5000;

// region readers
export const findIocValidationRequest = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityIocValidationRequest>(context, user, id, ENTITY_TYPE_IOC_VALIDATION_REQUEST);
};

// Requests store unmarked IOC payloads: only plain attributes are filterable, never a payload subfield, and an
// indicator or platform reference only matches when the reader can access it, so a filter never reveals the
// membership of an entity the reader cannot see.
const REQUEST_FILTER_KEYS = ['entity_type', 'name', 'status', 'test_kinds', 'connector_id', 'creator_id', 'created_at', 'updated_at', 'dispatched_at', 'completed_at'];
const REQUEST_REFERENCE_FILTER_TYPES: Record<string, string> = {
  platform_ids: ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM,
  indicator_ids: ENTITY_TYPE_INDICATOR,
};
const NO_ACCESSIBLE_REFERENCE = 'no-accessible-reference';
const MAX_REFERENCE_FILTER_VALUES = 100;

type RequestFilter = { key: string | string[]; values: unknown[]; operator?: string | null; mode?: string | null };
type RequestFilterGroup = { mode?: string | null; filters?: RequestFilter[] | null; filterGroups?: RequestFilterGroup[] | null };

export const sanitizeIocValidationRequestFilters = async (
  context: AuthContext,
  user: AuthUser,
  group: RequestFilterGroup | null | undefined,
): Promise<RequestFilterGroup | null | undefined> => {
  if (!group) {
    return group;
  }
  const filters = await Promise.all((group.filters ?? []).map(async (filter) => {
    const keys = Array.isArray(filter.key) ? filter.key : [filter.key];
    if (keys.length !== 1) {
      throw ValidationError('IOC validation requests are filtered on one key per filter', 'filters', { keys });
    }
    const [key] = keys;
    const referenceType = REQUEST_REFERENCE_FILTER_TYPES[key];
    if (!referenceType) {
      if (!REQUEST_FILTER_KEYS.includes(key)) {
        throw ValidationError('This filter is not supported on IOC validation requests', 'filters', { key });
      }
      return filter;
    }
    if ((filter.operator ?? 'eq') !== 'eq') {
      throw ValidationError('Only the equality operator is supported on this filter', 'filters', { key, operator: filter.operator });
    }
    if ((filter.values ?? []).length > MAX_REFERENCE_FILTER_VALUES) {
      throw ValidationError(`This filter accepts at most ${MAX_REFERENCE_FILTER_VALUES} values`, 'filters', { key });
    }
    const references = await Promise.all((filter.values ?? []).map((value) => storeLoadById(context, user, String(value), referenceType)));
    const readableIds = references.filter((reference) => !!reference).map((reference) => reference.internal_id);
    return { ...filter, key: [key], values: readableIds.length > 0 ? readableIds : [NO_ACCESSIBLE_REFERENCE] };
  }));
  const filterGroups = await Promise.all((group.filterGroups ?? []).map((child) => sanitizeIocValidationRequestFilters(context, user, child)));
  return { ...group, filters, filterGroups: filterGroups as RequestFilterGroup[] };
};

export const findIocValidationRequestsPaginated = async (context: AuthContext, user: AuthUser, args: QueryIocValidationRequestsArgs) => {
  const filters = await sanitizeIocValidationRequestFilters(context, user, args.filters as RequestFilterGroup | null | undefined);
  return pageEntitiesConnection<BasicStoreEntityIocValidationRequest>(context, user, [ENTITY_TYPE_IOC_VALIDATION_REQUEST], { ...args, filters } as never);
};

/**
 * OpenAEV IOC validation connectors, matched strictly on their declared scope
 * (generic enrichment connectors without scope must never receive validation requests).
 */
export const findIocValidationConnectors = async (context: AuthContext, user: AuthUser, onlyAlive = false) => {
  const candidates = await connectorsForEnrichment(context, user, IOC_VALIDATION_CONNECTOR_SCOPE, onlyAlive);
  return candidates.filter((connector: { connector_scope?: string[] }) => (connector.connector_scope ?? [])
    .map((scope) => scope.toLowerCase())
    .includes(IOC_VALIDATION_CONNECTOR_SCOPE));
};

// Ids of the indicators the user can read, used to never expose IOC values beyond the reader's access.
export const findReadableIndicatorIds = async (context: AuthContext, user: AuthUser, indicatorIds: string[]) => {
  if (indicatorIds.length === 0) return new Set<string>();
  const indicators = await storeLoadByIds<BasicStoreEntityIndicator>(context, user, indicatorIds, ENTITY_TYPE_INDICATOR);
  return new Set(indicators.filter((i) => i).map((i) => i.internal_id));
};
// endregion

// region access
type AccessControlled = { [RELATION_OBJECT_MARKING]?: string[] | null; [RELATION_GRANTED_TO]?: string[] | null; restricted_members?: unknown[] | null };
type AccessControlledRequest = AccessControlled & { internal_id: string; indicator_ids?: string[] | null; platform_ids?: string[] | null };
const ACCESS_REPAIR_PAGE_SIZE = 100;

const sameIds = (current: string[] | null | undefined, expected: string[]) => {
  const ids = current ?? [];
  return ids.length === expected.length && expected.every((id) => ids.includes(id));
};

/** Markings (the highest of each type kept) and organizations a request with these ends carries (see requestAccessOf). */
const expectedRequestAccess = async (context: AuthContext, ends: AccessControlled[]) => {
  checkEndsWithoutAuthorizedMembers(ends);
  const { markingIds, organizationIds } = requestAccessOf(ends);
  const cleaned = await cleanMarkings(context, markingIds);
  return {
    markingIds: [...new Set(cleaned
      .map((marking: { internal_id?: string } | string) => (typeof marking === 'string' ? marking : marking.internal_id))
      .filter((id: string | undefined): id is string => !!id))],
    organizationIds,
  };
};

/**
 * Gives a request the access of its indicators and security platforms as they are now, read as the platform. Sharing is
 * only repaired with the Enterprise Edition, without which it never changes nor restricts reads.
 */
const ensureRequestAccess = async (context: AuthContext, user: AuthUser, request: AccessControlledRequest) => {
  const loadEnds = async (ids: string[] | null | undefined, type: string) => {
    if (isEmptyField(ids)) {
      return [];
    }
    return await internalFindByIds<BasicStoreEntity>(context, SYSTEM_USER, ids as string[], { type }) as BasicStoreEntity[];
  };
  const [indicators, platforms] = await Promise.all([
    loadEnds(request.indicator_ids, ENTITY_TYPE_INDICATOR),
    loadEnds(request.platform_ids, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM),
  ]);
  const referencedCount = new Set(request.indicator_ids ?? []).size + new Set(request.platform_ids ?? []).size;
  const ends = requestAccessEndsOf(request, [...indicators, ...platforms].filter((end) => end) as AccessControlled[], referencedCount);
  const expected = await expectedRequestAccess(context, ends);
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const patch: Record<string, string[]> = {};
  if (!sameIds(request[RELATION_OBJECT_MARKING], expected.markingIds)) {
    patch[INPUT_MARKINGS] = expected.markingIds;
  }
  if (isEnterpriseEditionFromSettings(settings) && !sameIds(request[RELATION_GRANTED_TO], expected.organizationIds)) {
    patch[INPUT_GRANTED_REFS] = expected.organizationIds;
  }
  if (Object.keys(patch).length === 0) {
    return false;
  }
  await patchAttribute(context, user, request.internal_id, ENTITY_TYPE_IOC_VALIDATION_REQUEST, patch, {
    operations: Object.fromEntries(Object.keys(patch).map((key) => [key, UPDATE_OPERATION_REPLACE])),
  });
  return true;
};

/**
 * After a marking or sharing change of indicators or security platforms, every validation request that includes one of
 * them takes the access of all its indicators and security platforms again, one page of requests at a time.
 */
export const repairValidationRequestAccess = async (context: AuthContext, user: AuthUser, changes: { indicatorIds: string[]; platformIds: string[] }) => {
  const filters = [
    ...(changes.indicatorIds.length > 0 ? [{ key: ['indicator_ids'], values: changes.indicatorIds }] : []),
    ...(changes.platformIds.length > 0 ? [{ key: ['platform_ids'], values: changes.platformIds }] : []),
  ];
  if (filters.length === 0) {
    return 0;
  }
  let repaired = 0;
  await fullEntitiesList<BasicStoreEntityIocValidationRequest>(context, SYSTEM_USER, [ENTITY_TYPE_IOC_VALIDATION_REQUEST], {
    filters: { mode: 'or', filters, filterGroups: [] },
    noFiltersChecking: true,
    first: ACCESS_REPAIR_PAGE_SIZE,
    callback: async (requests: BasicStoreEntityIocValidationRequest[]) => {
      const changed = await BluePromise.map(requests, (request) => ensureRequestAccess(context, user, request as AccessControlledRequest), { concurrency: CONCURRENCY });
      repaired += changed.filter((updated) => updated).length;
      return true;
    },
  } as never);
  return repaired;
};
// endregion

// region deployed-on validation markers (side-channel, the result bundle carries the real outcome)
// No stream event nor history, but updated_at moves: incremental readers see every validation status change.
const setPairsValidationStatus = async (
  context: AuthContext,
  relations: Array<BasicStoreRelationDeployedOn & { _index: string }>,
  attributes: Record<string, unknown>,
) => {
  await BluePromise.map(relations, async (relation) => {
    const params = buildReplaceScriptParams({ ...attributes, updated_at: new Date() });
    await elUpdate(context, relation._index, relation.internal_id, { script: { source: EL_REPLACE_SCRIPT_SOURCE, lang: 'painless', params } });
  }, { concurrency: CONCURRENCY });
  await refreshIndicatorDeploymentCounters(context, relations.map((r) => r.fromId));
};

const findRequestDeployments = async (context: AuthContext, requestId: string) => {
  return fullRelationsList<BasicStoreRelationDeployedOn & { _index: string }>(context, SYSTEM_USER, RELATION_DEPLOYED_ON, {
    filters: { mode: 'and' as never, filters: [{ key: ['validation_run_id'], values: [requestId] }], filterGroups: [] },
    noFiltersChecking: true,
  });
};

// Pairs still waiting for an answer from this request are resolved with the given status. Each pair is rechecked
// under the pair lock of the result reports, so a result recorded meanwhile is never overwritten.
// Returns the ids of the deployments resolved.
const resolvePendingPairs = async (context: AuthContext, requestId: string, status: string): Promise<Set<string>> => {
  const deployments = await findRequestDeployments(context, requestId);
  const pending = deployments.filter((d) => d.validation_status === VALIDATION_STATUS_REQUESTED);
  const resolved: Array<BasicStoreRelationDeployedOn & { _index: string }> = [];
  if (pending.length > 0) {
    const attributes = status === VALIDATION_STATUS_NOT_REQUESTED
      ? { validation_status: VALIDATION_STATUS_NOT_REQUESTED, validation_run_id: null }
      : { validation_status: status, last_validation_at: new Date() };
    await BluePromise.map(pending, async (relation) => {
      const lock = await lockResources([pairLockKey(relation.fromId, relation.toId)]);
      try {
        const current = await findDeployedOn(context, SYSTEM_USER, relation.fromId, relation.toId);
        if (current && current.validation_status === VALIDATION_STATUS_REQUESTED && current.validation_run_id === requestId) {
          const params = buildReplaceScriptParams({ ...attributes, updated_at: new Date() });
          await elUpdate(context, current._index, current.internal_id, { script: { source: EL_REPLACE_SCRIPT_SOURCE, lang: 'painless', params } });
          resolved.push(current);
        }
      } finally {
        await lock.unlock();
      }
    }, { concurrency: CONCURRENCY });
    await refreshIndicatorDeploymentCounters(context, resolved.map((r) => r.fromId));
  }
  return new Set(resolved.map((relation) => relation.internal_id));
};
// endregion

// region request creation
const resolveConnector = async (context: AuthContext, user: AuthUser, connectorId?: string | null) => {
  const connectors = await findIocValidationConnectors(context, user);
  if (connectors.length === 0) {
    throw FunctionalError('No OpenAEV IOC validation connector is registered on this platform');
  }
  if (connectorId) {
    const selected = connectors.find((c: BasicStoreBase) => c.internal_id === connectorId || c.id === connectorId);
    if (!selected) {
      throw FunctionalError('The selected connector cannot validate IOCs', { connectorId });
    }
    return selected;
  }
  const active = connectors.filter((c: { active?: boolean }) => c.active === true);
  return active.length > 0 ? active[0] : connectors[0];
};

const resolveConnectorUser = async (context: AuthContext, connector: { connector_user_id?: string | null }) => {
  if (!connector.connector_user_id) {
    throw FunctionalError('The OpenAEV IOC validation connector has no service account');
  }
  const connectorUser = await resolveUserByIdFromCache(context, connector.connector_user_id) as AuthUser | undefined;
  if (!connectorUser) {
    throw FunctionalError('The service account of the OpenAEV IOC validation connector cannot be found');
  }
  return connectorUser;
};

// Capabilities the connector account needs to report results, with their names in the role settings.
const IOC_VALIDATION_CONNECTOR_CAPABILITIES: Array<[string, string]> = [['KNOWLEDGE_KNUPDATE', 'Update knowledge'], ['CONNECTORAPI', 'Connectors API usage']];

export const missingConnectorCapabilities = (connectorUser: AuthUser) => IOC_VALIDATION_CONNECTOR_CAPABILITIES
  .filter(([capability]) => !isUserHasCapability(connectorUser, capability))
  .map(([, label]) => `"${label}"`);

export const requestIndicatorsValidation = async (context: AuthContext, user: AuthUser, args: MutationIndicatorsRequestValidationArgs) => {
  const indicatorIds = [...new Set(args.indicatorIds)];
  const platformIds = [...new Set(args.platformIds)];
  const testKinds = [...new Set(args.testKinds)] as IocValidationTestKind[];
  if (indicatorIds.length === 0 || indicatorIds.length > IOC_VALIDATION_MAX_INDICATORS) {
    throw ValidationError(`A validation request needs between 1 and ${IOC_VALIDATION_MAX_INDICATORS} indicators`, 'indicatorIds', { size: indicatorIds.length });
  }
  if (platformIds.length === 0 || platformIds.length > IOC_VALIDATION_MAX_PLATFORMS) {
    throw ValidationError(`A validation request needs between 1 and ${IOC_VALIDATION_MAX_PLATFORMS} security platforms`, 'platformIds', { size: platformIds.length });
  }
  if (testKinds.length === 0 || !testKinds.every((kind) => isIocValidationTestKind(kind))) {
    throw ValidationError('At least one valid test kind is required', 'testKinds', { testKinds });
  }
  if ((args.name ?? '').length > NAME_MAX_LENGTH) {
    throw ValidationError(`The name cannot exceed ${NAME_MAX_LENGTH} characters`, 'name');
  }
  if ((args.description ?? '').length > DESCRIPTION_MAX_LENGTH) {
    throw ValidationError(`The description cannot exceed ${DESCRIPTION_MAX_LENGTH} characters`, 'description');
  }
  const contextOutOfDraft = { ...context, draft_context: '' };
  // 01. Security platforms must all be readable by the requester
  const platforms = await storeLoadByIds<BasicStoreEntitySecurityPlatform>(contextOutOfDraft, user, platformIds, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM);
  const resolvedPlatforms = platforms.filter((p) => p);
  if (resolvedPlatforms.length !== platformIds.length) {
    throw FunctionalError('Some security platforms cannot be found or are not accessible', { platformIds });
  }
  // 02. Connector and its service account: OpenAEV only receives what its account may read
  const connector = await resolveConnector(contextOutOfDraft, user, args.connectorId);
  const connectorUser = await resolveConnectorUser(contextOutOfDraft, connector);
  const requesterIndicators = (await storeLoadByIds<BasicStoreEntityIndicator>(contextOutOfDraft, user, indicatorIds, ENTITY_TYPE_INDICATOR)).filter((i) => i);
  if (requesterIndicators.length === 0) {
    throw FunctionalError('None of the indicators can be found or accessed');
  }
  const connectorReadable = await findReadableIndicatorIds(contextOutOfDraft, connectorUser, requesterIndicators.map((i) => i.internal_id));
  const skipped: IocValidationSkipped[] = [];
  const iocs: IocValidationIoc[] = [];
  requesterIndicators.forEach((indicator) => {
    if (!connectorReadable.has(indicator.internal_id)) {
      skipped.push({ indicator_id: indicator.internal_id, reason: 'Not accessible to the OpenAEV service account' });
      return;
    }
    const extraction = extractIocFromIndicator(indicator, testKinds);
    if (extraction.ioc) {
      iocs.push(extraction.ioc);
    } else {
      skipped.push({ indicator_id: indicator.internal_id, reason: extraction.reason });
    }
  });
  // 03. Pairs: only (indicator, platform) couples with a known deployment are validated, and only deployments both the
  // requester and the OpenAEV service account can read (a deployment carries the markings of both of its ends)
  const iocIndicatorIds = iocs.map((ioc) => ioc.indicator_id);
  const pairFilter = { fromId: iocIndicatorIds, toId: resolvedPlatforms.map((p) => p.internal_id) };
  const [deployments, requesterDeployments] = iocIndicatorIds.length === 0 ? [[], []] : await Promise.all([
    fullRelationsList<BasicStoreRelationDeployedOn & { _index: string }>(contextOutOfDraft, connectorUser, RELATION_DEPLOYED_ON, pairFilter),
    fullRelationsList<BasicStoreRelationDeployedOn>(contextOutOfDraft, user, RELATION_DEPLOYED_ON, { ...pairFilter, baseData: true } as never),
  ]);
  const requesterReadable = new Set(requesterDeployments.map((d) => d.internal_id));
  const pairs: IocValidationPair[] = [];
  iocs.forEach((ioc) => {
    resolvedPlatforms.forEach((platform) => {
      // A deployment the requester cannot read is reported like a missing one, so its existence is not revealed
      const deployment = deployments.find((d) => d.fromId === ioc.indicator_id && d.toId === platform.internal_id && requesterReadable.has(d.internal_id));
      if (!deployment) {
        skipped.push({ indicator_id: ioc.indicator_id, platform_id: platform.internal_id, reason: SKIP_REASON_NOT_DEPLOYED });
      } else if (!LIVE_DEPLOYMENT_STATUSES.includes(deployment.deployment_status)) {
        skipped.push({ indicator_id: ioc.indicator_id, platform_id: platform.internal_id, reason: 'Not live on this security platform' });
      } else if (deployment.revoked === true) {
        skipped.push({ indicator_id: ioc.indicator_id, platform_id: platform.internal_id, reason: 'Removal requested on this security platform' });
      } else if (deployment.validation_status === VALIDATION_STATUS_REQUESTED && deployment.validation_run_id) {
        // The pair belongs to the run that marked it until that run resolves or is deleted
        skipped.push({ indicator_id: ioc.indicator_id, platform_id: platform.internal_id, reason: 'Already waiting for the results of another validation request' });
      } else {
        pairs.push({ indicator_id: ioc.indicator_id, platform_id: platform.internal_id, deployed_on_id: deployment.internal_id });
      }
    });
  });
  if (pairs.length === 0) {
    const reasons = [...new Set(skipped.map((s) => s.reason))];
    throw FunctionalError(`Nothing to validate: ${reasons.join(', ')}`, { skipped: skipped.length });
  }
  // 04. Claim: the pairs are re-read and marked under the pair locks of the report paths, so two concurrent requests
  // can never both take the same deployment (the keys are sorted, the locks released whatever happens).
  const lock = await lockResources([...new Set(pairs.map((pair) => pairLockKey(pair.indicator_id, pair.platform_id)))].sort());
  let request: StoreEntityIocValidationRequest;
  // Outcome each earlier request got for the pairs taken over here, by request
  const takenOver = new Map<string, Map<string, string>>();
  try {
    const claimed: IocValidationPair[] = [];
    const claimedDeployments: Array<BasicStoreRelationDeployedOn & { _index: string }> = [];
    await BluePromise.map(pairs, async (pair) => {
      const current = await findDeployedOn(contextOutOfDraft, SYSTEM_USER, pair.indicator_id, pair.platform_id) as (BasicStoreRelationDeployedOn & { _index: string }) | undefined;
      const stillEligible = current && current.internal_id === pair.deployed_on_id
        && LIVE_DEPLOYMENT_STATUSES.includes(current.deployment_status) && current.revoked !== true
        && !(current.validation_status === VALIDATION_STATUS_REQUESTED && current.validation_run_id);
      if (stillEligible) {
        claimed.push(pair);
        claimedDeployments.push(current);
        if (current.validation_run_id && current.validation_status) {
          const outcomes = takenOver.get(current.validation_run_id) ?? new Map<string, string>();
          outcomes.set(current.internal_id, current.validation_status);
          takenOver.set(current.validation_run_id, outcomes);
        }
      } else {
        skipped.push({ indicator_id: pair.indicator_id, platform_id: pair.platform_id, reason: 'Already waiting for the results of another validation request' });
      }
    }, { concurrency: CONCURRENCY });
    if (claimed.length === 0) {
      throw FunctionalError('Nothing to validate: Already waiting for the results of another validation request', { skipped: skipped.length });
    }
    const claimedIndicatorIds = new Set(claimed.map((p) => p.indicator_id));
    const name = args.name?.trim() || `Validation of ${claimedIndicatorIds.size} indicator(s) on ${resolvedPlatforms.length} security platform(s)`;
    // Module internal objects are not dated by the data builder: the creation date is part of the request.
    const createdAt = new Date();
    // Created with the markings of its ends (the requester reads all of them) and shared with no organization, so no
    // reader outside the platform organization sees it before it gets the organizations of its ends.
    const access = await expectedRequestAccess(contextOutOfDraft, [
      ...requesterIndicators.filter((indicator) => claimedIndicatorIds.has(indicator.internal_id)),
      ...resolvedPlatforms,
    ]);
    request = await createInternalObject<StoreEntityIocValidationRequest>(contextOutOfDraft, user, {
      name,
      created_at: createdAt,
      updated_at: createdAt,
      description: args.description ?? undefined,
      platform_ids: resolvedPlatforms.map((p) => p.internal_id),
      indicator_ids: [...claimedIndicatorIds],
      test_kinds: testKinds,
      status: REQUEST_STATUS_PENDING,
      connector_id: connector.internal_id,
      results_summary: emptyResultsSummary(claimed.length, skipped.length),
      iocs: iocs.filter((ioc) => claimedIndicatorIds.has(ioc.indicator_id)),
      pairs: claimed,
      skipped,
      [INPUT_MARKINGS]: access.markingIds,
      [INPUT_GRANTED_REFS]: [],
    }, ENTITY_TYPE_IOC_VALIDATION_REQUEST, { grantedRefsFromInput: true });
    // The organizations, and any change of an end since it was read, are applied once the request exists: a change
    // event of an end only repairs the requests existing by then
    const stored = await findIocValidationRequest(contextOutOfDraft, SYSTEM_USER, request.internal_id);
    if (stored) {
      await ensureRequestAccess(contextOutOfDraft, SYSTEM_USER, stored as unknown as AccessControlledRequest);
    }
    await setPairsValidationStatus(contextOutOfDraft, claimedDeployments, {
      validation_status: VALIDATION_STATUS_REQUESTED,
      validation_run_id: request.internal_id,
    });
  } finally {
    await lock.unlock();
  }
  await BluePromise.map([...takenOver.entries()], ([requestId, outcomes]) => {
    return recordTakenOverOutcomes(contextOutOfDraft, requestId, outcomes);
  }, { concurrency: CONCURRENCY });
  await addIocValidationRequestCreationCount();
  return dispatchIocValidationRequest(contextOutOfDraft, request);
};
// endregion

// region dispatch to OpenAEV
// Serializes the writes of the request status (dispatch, OpenAEV lifecycle updates).
// Lock order, everywhere: dispatch claim, then request, then pairs.
const dispatchLockKey = (requestId: string) => `ioc-validation-dispatch-${requestId}`;
const requestLockKey = (requestId: string) => `ioc-validation-request-${requestId}`;

const withRequestLock = async <T>(requestId: string, callback: () => Promise<T>): Promise<T> => {
  const lock = await lockResources([requestLockKey(requestId)]);
  try {
    return await callback();
  } finally {
    await lock.unlock();
  }
};

const patchRequest = async (context: AuthContext, user: AuthUser, id: string, patch: Record<string, unknown>) => {
  const { element } = await patchAttribute<StoreEntityIocValidationRequest>(context, user, id, ENTITY_TYPE_IOC_VALIDATION_REQUEST, patch);
  return element;
};

/**
 * Push the request to the OpenAEV IOC validation connector listen queue.
 * The OpenCTI worker relays the message to the OpenAEV callback, exactly as for security coverage.
 * When the connector is not alive the request stays pending and the manager retries.
 * A request bound to a connector is never rerouted: connectors can target different OpenAEV tenants.
 * The creation and the maintenance can both see the same pending request: the dispatch is claimed under its own lock,
 * and only a caller finding the request still pending and without work creates the work and pushes the scenario.
 */
export const dispatchIocValidationRequest = async (context: AuthContext, request: StoreEntityIocValidationRequest) => {
  const lock = await lockResources([dispatchLockKey(request.internal_id)]);
  try {
    const current = await findIocValidationRequest(context, SYSTEM_USER, request.internal_id) as unknown as StoreEntityIocValidationRequest | undefined;
    if (!current || current.status !== REQUEST_STATUS_PENDING || isNotEmptyField(current.work_id)) {
      return current ?? request;
    }
    return await dispatchClaimedIocValidationRequest(context, current);
  } finally {
    await lock.unlock();
  }
};

/**
 * A request can wait for its connector: before it is sent, each pair is read again under its pair lock, and only the
 * deployments still live, without removal requested and still waiting for this request are kept. A dropped pair still
 * marked by this request is released (not requested again) and listed with its reason in the skipped pairs.
 * Must run under the dispatch claim of the request.
 */
const recheckPairsBeforeDispatch = async (context: AuthContext, request: StoreEntityIocValidationRequest) => {
  const pairs = request.pairs ?? [];
  if (pairs.length === 0) {
    return request;
  }
  const kept: IocValidationPair[] = [];
  const dropped: IocValidationSkipped[] = [];
  const released: Array<BasicStoreRelationDeployedOn & { _index: string }> = [];
  const lock = await lockResources([...new Set(pairs.map((pair) => pairLockKey(pair.indicator_id, pair.platform_id)))].sort());
  try {
    await BluePromise.map(pairs, async (pair) => {
      const current = await findDeployedOn(context, SYSTEM_USER, pair.indicator_id, pair.platform_id) as (BasicStoreRelationDeployedOn & { _index: string }) | undefined;
      const bound = current && current.internal_id === pair.deployed_on_id
        && current.validation_run_id === request.internal_id && current.validation_status === VALIDATION_STATUS_REQUESTED;
      let reason: string | undefined;
      if (!current || !bound) {
        reason = 'No longer waiting for this validation request';
      } else if (!LIVE_DEPLOYMENT_STATUSES.includes(current.deployment_status)) {
        reason = 'Not live on this security platform';
      } else if (current.revoked === true) {
        reason = 'Removal requested on this security platform';
      }
      if (!reason) {
        kept.push(pair);
        return;
      }
      dropped.push({ indicator_id: pair.indicator_id, platform_id: pair.platform_id, reason });
      if (current && bound) {
        const params = buildReplaceScriptParams({ validation_status: VALIDATION_STATUS_NOT_REQUESTED, validation_run_id: null, updated_at: new Date() });
        await elUpdate(context, current._index, current.internal_id, { script: { source: EL_REPLACE_SCRIPT_SOURCE, lang: 'painless', params } });
        released.push(current);
      }
    }, { concurrency: CONCURRENCY });
  } finally {
    await lock.unlock();
  }
  if (dropped.length === 0) {
    return request;
  }
  await refreshIndicatorDeploymentCounters(context, released.map((relation) => relation.fromId));
  const keptIds = new Set(kept.map((pair) => pair.deployed_on_id));
  return recordPairsLeftOut(context, request, (pair) => keptIds.has(pair.deployed_on_id), dropped, 'no longer eligible');
};

// The request keeps the pairs `keep` accepts and lists the others with their reason in its skipped pairs.
const recordPairsLeftOut = async (
  context: AuthContext,
  request: StoreEntityIocValidationRequest,
  keep: (pair: IocValidationPair) => boolean,
  leftOut: IocValidationSkipped[],
  why: string,
) => withRequestLock(request.internal_id, async () => {
  const current = (await findIocValidationRequest(context, SYSTEM_USER, request.internal_id) ?? request) as unknown as StoreEntityIocValidationRequest;
  const remaining = (current.pairs ?? []).filter(keep);
  const skipped = [...(current.skipped ?? []), ...leftOut];
  const attributes = { pairs: remaining, skipped, results_summary: summarizeRequestPairs(remaining, skipped.length) };
  await setRequestAttributes(context, current, attributes);
  logApp.info(`[IOC-VALIDATION] Pairs ${why} left out before dispatch`, { requestId: request.internal_id, dropped: leftOut.length });
  return { ...current, ...attributes } as StoreEntityIocValidationRequest;
});

// Translated in the user interface, like the other skip reasons.
export const IOC_VALIDATION_INACCESSIBLE_REASON = 'No longer accessible to the OpenAEV service account';

/**
 * Pairs the OpenAEV service account can no longer read (an end or the deployment lost its access while the request
 * waited) are left out before the request is sent: each one still marked by this request is released (not requested
 * again) and listed with its reason, so the request never waits for a pair that was not sent. Must run under the
 * dispatch claim of the request.
 */
const leaveInaccessiblePairsOut = async (context: AuthContext, request: StoreEntityIocValidationRequest, inaccessible: IocValidationPair[]) => {
  const released: Array<BasicStoreRelationDeployedOn & { _index: string }> = [];
  const lock = await lockResources([...new Set(inaccessible.map((pair) => pairLockKey(pair.indicator_id, pair.platform_id)))].sort());
  try {
    await BluePromise.map(inaccessible, async (pair) => {
      const current = await findDeployedOn(context, SYSTEM_USER, pair.indicator_id, pair.platform_id) as (BasicStoreRelationDeployedOn & { _index: string }) | undefined;
      if (current && current.internal_id === pair.deployed_on_id && current.validation_run_id === request.internal_id
        && current.validation_status === VALIDATION_STATUS_REQUESTED) {
        const params = buildReplaceScriptParams({ validation_status: VALIDATION_STATUS_NOT_REQUESTED, validation_run_id: null, updated_at: new Date() });
        await elUpdate(context, current._index, current.internal_id, { script: { source: EL_REPLACE_SCRIPT_SOURCE, lang: 'painless', params } });
        released.push(current);
      }
    }, { concurrency: CONCURRENCY });
  } finally {
    await lock.unlock();
  }
  await refreshIndicatorDeploymentCounters(context, released.map((relation) => relation.fromId));
  const leftOutIds = new Set(inaccessible.map((pair) => pair.deployed_on_id));
  const leftOut = inaccessible.map((pair) => ({ indicator_id: pair.indicator_id, platform_id: pair.platform_id, reason: IOC_VALIDATION_INACCESSIBLE_REASON }));
  return recordPairsLeftOut(context, request, (pair) => !leftOutIds.has(pair.deployed_on_id), leftOut, 'no longer accessible to the OpenAEV service account');
};

const dispatchClaimedIocValidationRequest = async (context: AuthContext, claimed: StoreEntityIocValidationRequest) => {
  const connectors = await findIocValidationConnectors(context, SYSTEM_USER, true);
  const connector = claimed.connector_id
    ? connectors.find((c: BasicStoreBase) => c.internal_id === claimed.connector_id)
    : connectors[0];
  if (!connector) {
    if (claimed.status_message !== 'Waiting for an active OpenAEV IOC validation connector') {
      return patchRequest(context, SYSTEM_USER, claimed.internal_id, { status_message: 'Waiting for an active OpenAEV IOC validation connector' });
    }
    return claimed;
  }
  // The connector reports the results with its own account: the request waits while that account cannot.
  const connectorUser = await resolveConnectorUser(context, connector);
  const missingCapabilities = missingConnectorCapabilities(connectorUser);
  if (missingCapabilities.length > 0) {
    const message = `The account of the OpenAEV IOC validation connector needs the ${missingCapabilities.join(' and ')} capabilities (Connector role)`;
    return claimed.status_message === message ? claimed : patchRequest(context, SYSTEM_USER, claimed.internal_id, { status_message: message });
  }
  const request = await recheckPairsBeforeDispatch(context, claimed);
  if (request.pairs.length === 0) {
    return patchRequest(context, SYSTEM_USER, request.internal_id, {
      status: REQUEST_STATUS_FAILED,
      status_message: 'No deployment of the request is still live and waiting for it',
      completed_at: new Date(),
    });
  }
  const requesterId = requesterIdOf(request);
  const requester = requesterId ? await resolveUserByIdFromCache(context, requesterId) as AuthUser | undefined : undefined;
  // The IOC list and the bundle are built from the pairs kept: an indicator or a platform without pair is not sent.
  const pairIndicatorIds = [...new Set(request.pairs.map((pair) => pair.indicator_id))];
  const pairPlatformIds = [...new Set(request.pairs.map((pair) => pair.platform_id))];
  const indicators = await storeLoadByIds<BasicStoreEntityIndicator>(context, connectorUser, pairIndicatorIds, ENTITY_TYPE_INDICATOR);
  const platforms = await storeLoadByIds<BasicStoreEntitySecurityPlatform>(context, connectorUser, pairPlatformIds, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM);
  const indicatorRefs = new Map(indicators.filter((i) => i).map((i) => [i.internal_id, i.standard_id as StixId]));
  const platformRefs = new Map(platforms.filter((p) => p).map((p) => [p.internal_id, p.standard_id as StixId]));
  const deploymentIds = request.pairs.map((pair) => pair.deployed_on_id);
  const stixObjects = await stixLoadByIds(context, connectorUser, [...indicatorRefs.keys(), ...platformRefs.keys(), ...deploymentIds]);
  const deploymentRefs = new Map<string, StixId>();
  stixObjects.forEach((stix) => {
    const internalId = (stix as { extensions?: Record<string, { id?: string }> }).extensions?.['extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba']?.id;
    if (internalId && deploymentIds.includes(internalId)) {
      deploymentRefs.set(internalId, stix.id as StixId);
    }
  });
  const isAccessible = (pair: IocValidationPair) => indicatorRefs.has(pair.indicator_id) && platformRefs.has(pair.platform_id)
    && deploymentRefs.has(pair.deployed_on_id);
  const inaccessible = request.pairs.filter((pair) => !isAccessible(pair));
  if (inaccessible.length === request.pairs.length) {
    await resolvePendingPairs(context, request.internal_id, VALIDATION_STATUS_ERROR);
    const failedPairs = withPairOutcomes(request.pairs, await findRequestDeployments(context, request.internal_id));
    return patchRequest(context, SYSTEM_USER, request.internal_id, {
      status: REQUEST_STATUS_FAILED,
      status_message: 'The indicators or deployments are no longer accessible to the OpenAEV service account',
      pairs: failedPairs,
      results_summary: summarizeRequestPairs(failedPairs, request.skipped?.length ?? 0),
      completed_at: new Date(),
    });
  }
  // Only the pairs sent are kept on the request: it never waits for a pair OpenAEV did not receive.
  const sent = inaccessible.length > 0 ? await leaveInaccessiblePairsOut(context, request, inaccessible) : request;
  const pairs: IocValidationBundlePair[] = sent.pairs.map((pair) => ({
    indicator_ref: indicatorRefs.get(pair.indicator_id) as StixId,
    platform_ref: platformRefs.get(pair.platform_id) as StixId,
    deployed_on_ref: deploymentRefs.get(pair.deployed_on_id) as StixId,
  }));
  const sentIndicatorIds = new Set(sent.pairs.map((pair) => pair.indicator_id));
  const sentPlatformIds = new Set(sent.pairs.map((pair) => pair.platform_id));
  const sentDeploymentIds = new Set(sent.pairs.map((pair) => pair.deployed_on_id));
  const sentRefs = new Set<string>([
    ...[...sentIndicatorIds].map((id) => indicatorRefs.get(id) as string),
    ...[...sentPlatformIds].map((id) => platformRefs.get(id) as string),
    ...[...sentDeploymentIds].map((id) => deploymentRefs.get(id) as string),
  ]);
  const requestObject = buildIocValidationRequestForOpenAEV(sent, {
    requestedBy: requester?.name ?? 'OpenCTI',
    indicatorRefs: [...sentIndicatorIds].map((id) => indicatorRefs.get(id) as StixId),
    platformRefs: [...sentPlatformIds].map((id) => platformRefs.get(id) as StixId),
    iocs: sent.iocs.filter((ioc) => sentIndicatorIds.has(ioc.indicator_id)),
    pairs,
  });
  const bundle = { type: 'bundle', id: `bundle--${uuidv4()}`, objects: [requestObject, ...stixObjects.filter((stix) => sentRefs.has(stix.id))] };
  const workUser = requester ?? SYSTEM_USER;
  const work = await createWork(context, workUser, connector, `IOC validation: ${request.name}`, request.internal_id);
  if (!work) {
    throw FunctionalError('Cannot create the work tracking the IOC validation request', { requestId: request.internal_id });
  }
  const message = {
    internal: {
      work_id: work.id,
      applicant_id: requesterId ?? null,
      draft_id: null,
      mode: 'manual',
      trigger: 'create',
    },
    event: {
      event_type: CONNECTOR_INTERNAL_ENRICHMENT,
      entity_id: request.internal_id,
      entity_type: ENTITY_TYPE_IOC_VALIDATION_REQUEST,
      stix_entity: JSON.stringify(requestObject),
      stix_objects: JSON.stringify(bundle),
    },
  };
  // The work is recorded on the request before the publish: a dispatch interrupted after it is never published again
  // (the request then expires after the timeout). The queue delivers at least once: OpenAEV records a request once, under
  // its id, so a message delivered twice still makes one validation.
  await withRequestLock(request.internal_id, () => patchRequest(context, SYSTEM_USER, request.internal_id, {
    connector_id: connector.internal_id,
    work_id: work.id,
    dispatched_at: new Date(),
  }));
  try {
    await pushToConnector(connector.internal_id, message);
  } catch (error) {
    // The work never reaches the connector: it is closed in error before the request is released for a new dispatch
    try {
      await reportExpectation(context, SYSTEM_USER, work.id, { error: 'The request could not be published to the queue of the connector', source: 'Platform' });
    } catch (reportError) {
      logApp.warn('[IOC-VALIDATION] Cannot close the work of a request that could not be published', { requestId: request.internal_id, workId: work.id, cause: reportError });
    }
    await withRequestLock(request.internal_id, () => patchRequest(context, SYSTEM_USER, request.internal_id, { work_id: null, dispatched_at: null }));
    throw error;
  }
  logApp.info('[IOC-VALIDATION] Request dispatched to OpenAEV', { requestId: request.internal_id, connectorId: connector.internal_id, pairs: pairs.length });
  // OpenAEV can report its lifecycle before this write: an advanced status is never set back to sent.
  return withRequestLock(request.internal_id, async () => {
    const current = await findIocValidationRequest(context, SYSTEM_USER, request.internal_id);
    if (current && current.status !== REQUEST_STATUS_PENDING) {
      return current;
    }
    return patchRequest(context, SYSTEM_USER, request.internal_id, { status: REQUEST_STATUS_SENT, status_message: null });
  });
};
// endregion

// region lifecycle reported by OpenAEV
const isAllowedTransition = (current: IocValidationRequestStatus, next: IocValidationRequestStatus) => {
  if (current === next) return true;
  // Late results are accepted after an OpenCTI side expiration
  if (current === REQUEST_STATUS_EXPIRED) return [REQUEST_STATUS_COMPLETED, REQUEST_STATUS_PARTIAL].includes(next as never);
  if (FINAL_REQUEST_STATUSES.includes(current)) return false;
  if (current === REQUEST_STATUS_RUNNING) return next !== REQUEST_STATUS_AWAITING_APPROVAL;
  return true;
};

const isRequestConnectorUser = async (context: AuthContext, user: AuthUser, request: BasicStoreEntityIocValidationRequest) => {
  if (isBypassUser(user)) {
    return true;
  }
  const connector = request.connector_id
    ? await storeLoadById<BasicStoreEntityConnector>(context, SYSTEM_USER, request.connector_id, ENTITY_TYPE_CONNECTOR)
    : undefined;
  return !!connector && connector.connector_user_id === user.id;
};

// Only the service account of the connector the request was sent to may report its lifecycle.
export const assertRequestConnectorUser = async (context: AuthContext, user: AuthUser, request: BasicStoreEntityIocValidationRequest) => {
  if (!await isRequestConnectorUser(context, user, request)) {
    throw ForbiddenAccess('Only the connector the IOC validation request was sent to can report its status', { id: request.internal_id });
  }
};

export const updateIocValidationRequestStatus = async (context: AuthContext, user: AuthUser, id: string, input: IocValidationRequestStatusInput) => {
  const status = input.status as IocValidationRequestStatus;
  if (!OPENAEV_REPORTABLE_STATUSES.includes(status)) {
    throw ValidationError('This status cannot be reported by OpenAEV', 'status', { status });
  }
  // The request connector is authorized by identity: the access of the request follows its indicators and security
  // platforms, which its account may not all read
  const found = await findIocValidationRequest(context, SYSTEM_USER, id);
  if (!found) {
    throw FunctionalError('IOC validation request not found', { id });
  }
  await assertRequestConnectorUser(context, user, found);
  return withRequestLock(found.internal_id, async () => {
    const request = await findIocValidationRequest(context, SYSTEM_USER, found.internal_id) ?? found;
    if (!isAllowedTransition(request.status, status)) {
      logApp.info('[IOC-VALIDATION] Ignoring out of order status update', { id, current: request.status, next: status });
      return request;
    }
    const patch: Record<string, unknown> = { status };
    if (input.openaev_scenario_id) patch.openaev_scenario_id = input.openaev_scenario_id;
    if (input.openaev_simulation_id) patch.openaev_simulation_id = input.openaev_simulation_id;
    if (input.external_uri) patch.external_uri = input.external_uri;
    if (input.message !== undefined) patch.status_message = input.message;
    if (FINAL_REQUEST_STATUSES.includes(status)) {
      if (status === REQUEST_STATUS_FAILED || status === REQUEST_STATUS_REJECTED) {
        await resolvePendingPairs(context, request.internal_id, VALIDATION_STATUS_ERROR);
      }
      const deployments = await findRequestDeployments(context, request.internal_id);
      const pairs = withPairOutcomes(request.pairs ?? [], deployments);
      patch.pairs = pairs;
      patch.results_summary = summarizeRequestPairs(pairs, request.skipped?.length ?? 0);
      const awaitingResults = deployments.some((d) => d.validation_status === VALIDATION_STATUS_REQUESTED);
      if (awaitingResults && isAllowedTransition(request.status, REQUEST_STATUS_RUNNING)) {
        // The result bundle is ingested separately: the maintenance completes the request once every pair has
        // its result (or expires it after the timeout), so the request never looks final with pending pairs.
        patch.status = REQUEST_STATUS_RUNNING;
        patch.status_message = input.message ?? 'OpenAEV finished the validation, waiting for the results of every pair';
      } else {
        patch.completed_at = new Date();
      }
    }
    return patchRequest(context, SYSTEM_USER, request.internal_id, patch);
  });
};

export const IOC_VALIDATION_RESULTS_MAX_SIZE = 500;
export { validationResultSightingStixId };

const toObservedAt = (value: unknown, now: Date) => {
  if (isEmptyField(value)) return now;
  const date = new Date(value as string);
  if (Number.isNaN(date.getTime())) {
    throw ValidationError('Observation date is invalid', 'observedAt');
  }
  return date;
};

/**
 * Whether an existing sighting carrying the deterministic id of a validation result records that result: the
 * indicator sighted by the platform, negative for a miss only, at least as restricted as both ends and shared with
 * their organizations only. Generic sighting creation accepts a supplied STIX id, so the id alone proves nothing.
 */
const recordsValidationResult = async (
  context: AuthContext,
  sighting: BasicStoreRelation,
  indicator: BasicStoreEntityIndicator,
  platform: BasicStoreEntitySecurityPlatform,
  status: string,
) => {
  const markings = (sighting[RELATION_OBJECT_MARKING] ?? []) as string[];
  const granted = (sighting[RELATION_GRANTED_TO] ?? []) as string[];
  const organizations = new Set(pairOrganizations(indicator, platform));
  const cleaned = await cleanMarkings(context, [...markings, ...pairMarkings(indicator, platform)]);
  return sighting.fromId === indicator.internal_id
    && sighting.toId === platform.internal_id
    && Boolean(sighting.x_opencti_negative) === (status === VALIDATION_STATUS_MISSED)
    && cleaned.every((marking: { internal_id?: string } | string) => markings.includes(typeof marking === 'string' ? marking : marking.internal_id ?? ''))
    && granted.every((id) => organizations.has(id));
};

/**
 * Validation results proven by a security platform from its own data (for example a SIEM that saw the benign test
 * of a request). Only the pairs of the request on that platform still waiting for an answer are updated, so an
 * OpenAEV verdict is never overwritten. Each result is recorded as a sighting of the indicator by the platform
 * (negative for a miss) and refreshes the validated counters and the results summary of the request.
 */
export const reportIocValidationResults = async (context: AuthContext, user: AuthUser, args: MutationIocValidationReportResultsArgs) => {
  if (args.results.length > IOC_VALIDATION_RESULTS_MAX_SIZE) {
    throw ValidationError(`A report cannot exceed ${IOC_VALIDATION_RESULTS_MAX_SIZE} results`, 'results', { size: args.results.length });
  }
  args.results.forEach((result) => {
    if (isNotEmptyField(result.hitCount) && (!Number.isInteger(result.hitCount) || (result.hitCount as number) < 1)) {
      throw ValidationError('Hit count must be a positive integer', 'hitCount', { hitCount: result.hitCount });
    }
  });
  // Authorized by identity below (the request connector, or the account recording the deployments of the platform),
  // whatever the access of the request to its account
  const request = await findIocValidationRequest(context, SYSTEM_USER, args.id);
  if (!request) {
    throw FunctionalError('IOC validation request not found', { id: args.id });
  }
  const platform = await storeLoadById<BasicStoreEntitySecurityPlatform>(context, user, args.platformId, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM);
  if (!platform || !(request.platform_ids ?? []).includes(platform.internal_id)) {
    throw FunctionalError('The security platform is not targeted by this IOC validation request', { id: args.id, platformId: args.platformId });
  }
  // A result is proof attributed to the platform: besides the request connector, only a connector account that
  // recorded the deployment of a pair speaks for the platform, and only for the pairs it recorded.
  const trusted = await isRequestConnectorUser(context, user, request);
  if (!trusted) {
    const platformDeployments = (await findRequestDeployments(context, request.internal_id)).filter((d) => d.toId === platform.internal_id);
    if (!platformDeployments.some((d) => isTrustedDeploymentReporter(d, user))) {
      throw ForbiddenAccess('Only the account reporting the deployments of this security platform can report its validation results', {
        id: request.internal_id,
        platformId: platform.internal_id,
      });
    }
  }
  // Results are written concurrently and a pair keeps its first verdict: two results for one indicator, whatever ids
  // name it, would leave the recorded verdict to the order of the writes, so every indicator is resolved first
  const resolved = await BluePromise.map(args.results, async (result) => {
    const indicator = await storeLoadById<BasicStoreEntityIndicator>(context, user, result.indicatorId, ENTITY_TYPE_INDICATOR);
    return indicator && (request.indicator_ids ?? []).includes(indicator.internal_id) ? { result, indicator } : undefined;
  }, { concurrency: CONCURRENCY });
  const reported = resolved.filter((entry) => entry !== undefined);
  const reportedIndicatorIds = new Set<string>();
  reported.forEach(({ indicator }) => {
    if (reportedIndicatorIds.has(indicator.internal_id)) {
      throw ValidationError('A report gives one result per indicator', 'results', { indicatorId: indicator.internal_id });
    }
    reportedIndicatorIds.add(indicator.internal_id);
  });
  const now = new Date();
  const updatedIndicatorIds: string[] = [];
  const timedOutDeploymentIds = new Set((request.pairs ?? []).filter((pair) => pair.timed_out).map((pair) => pair.deployed_on_id));
  await BluePromise.map(reported, async ({ result, indicator }) => {
    const observedAt = toObservedAt(result.observedAt, now);
    const lock = await lockResources([pairLockKey(indicator.internal_id, platform.internal_id)]);
    try {
      const deployment = await findDeployedOn(context, SYSTEM_USER, indicator.internal_id, platform.internal_id);
      if (!deployment || deployment.validation_run_id !== request.internal_id) {
        return;
      }
      if (!trusted && !isTrustedDeploymentReporter(deployment, user)) {
        logApp.info('[IOC-VALIDATION] Ignoring a result for a pair recorded by another account', { id: request.internal_id, deploymentId: deployment.internal_id });
        return;
      }
      // A late verdict of this request replaces the error the timeout set, never a reported verdict.
      const timedOut = deployment.validation_status === VALIDATION_STATUS_ERROR && timedOutDeploymentIds.has(deployment.internal_id);
      const waiting = deployment.validation_status === VALIDATION_STATUS_REQUESTED || timedOut;
      // A retry of the recorded verdict only repairs its sighting (the verdict is written first).
      if (!waiting && deployment.validation_status !== result.status) {
        return;
      }
      const sightingStixId = validationResultSightingStixId(request.internal_id, indicator.internal_id, platform.internal_id);
      const sighting = await internalLoadById<BasicStoreRelation>(context, SYSTEM_USER, sightingStixId, { type: STIX_SIGHTING_RELATIONSHIP });
      if (sighting && !await recordsValidationResult(context, sighting, indicator, platform, result.status)) {
        throw FunctionalError('A sighting with the identifier of this validation result exists and does not record it', {
          id: request.internal_id,
          sightingId: sighting.internal_id,
        });
      }
      if (waiting) {
        const { element } = await patchAttribute(context, user, deployment.internal_id, RELATION_DEPLOYED_ON, {
          validation_status: result.status,
          last_validation_at: observedAt,
        });
        await notify(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].EDIT_TOPIC, element, user);
      }
      if (!sighting) {
        // The reserved id is the standard id too, so results observed at the same instant never share one
        const created = await createRelation(sightingReportContext(context), user, {
          fromId: indicator.internal_id,
          toId: platform.internal_id,
          relationship_type: STIX_SIGHTING_RELATIONSHIP,
          standard_id: sightingStixId,
          stix_id: sightingStixId,
          [INPUT_MARKINGS]: pairMarkings(indicator, platform),
          [INPUT_GRANTED_REFS]: pairOrganizations(indicator, platform),
          attribute_count: result.hitCount ?? 1,
          first_seen: observedAt,
          last_seen: observedAt,
          x_opencti_negative: result.status === VALIDATION_STATUS_MISSED,
          description: result.evidence || `IOC validation ${result.status} reported by ${platform.name}`,
        }, { grantedRefsFromInput: true });
        await ensureCreatedPairAccess(context, created as unknown as BasicStoreRelation, indicator.internal_id, platform.internal_id);
      }
      if (waiting) {
        updatedIndicatorIds.push(indicator.internal_id);
      }
    } finally {
      await lock.unlock();
    }
  }, { concurrency: CONCURRENCY });
  if (updatedIndicatorIds.length > 0) {
    await addIocValidationPlatformResultCount(updatedIndicatorIds.length);
    await refreshIndicatorDeploymentCounters(context, updatedIndicatorIds);
    await withRequestLock(request.internal_id, async () => {
      const current = await findIocValidationRequest(context, SYSTEM_USER, request.internal_id) ?? request;
      const pairs = withPairOutcomes(current.pairs ?? [], await findRequestDeployments(context, request.internal_id));
      await setRequestAttributes(context, current, { pairs, results_summary: summarizeRequestPairs(pairs, current.skipped?.length ?? 0) });
    });
  }
  // The request connector was sent the whole request; an account trusted for its own deployments only gets the request
  // back as it reads it, which may be not at all
  return findIocValidationRequest(context, trusted ? SYSTEM_USER : user, request.internal_id);
};

export const deleteIocValidationRequest = async (context: AuthContext, user: AuthUser, id: string) => {
  const request = await findIocValidationRequest(context, user, id);
  if (!request) {
    throw FunctionalError('IOC validation request not found', { id });
  }
  // A dispatch in flight finishes first: its pushed scenario is recorded on the request before the request goes.
  const lock = await lockResources([dispatchLockKey(request.internal_id), requestLockKey(request.internal_id)]);
  try {
    const current = await findIocValidationRequest(context, SYSTEM_USER, request.internal_id);
    if (current) {
      // Unanswered pairs return to not requested so they are not left waiting forever
      await resolvePendingPairs(context, current.internal_id, VALIDATION_STATUS_NOT_REQUESTED);
      // The access repair of the result sightings goes through their request: they go with it.
      await BluePromise.map(current.pairs ?? [], async (pair) => {
        const sightingId = validationResultSightingStixId(current.internal_id, pair.indicator_id, pair.platform_id);
        const sighting = await internalLoadById(context, SYSTEM_USER, sightingId, { type: STIX_SIGHTING_RELATIONSHIP });
        if (sighting) {
          await deleteElementById(context, SYSTEM_USER, sighting.internal_id, STIX_SIGHTING_RELATIONSHIP);
        }
      }, { concurrency: CONCURRENCY });
      await deleteInternalObject(context, user, current.internal_id, ENTITY_TYPE_IOC_VALIDATION_REQUEST);
    }
  } finally {
    await lock.unlock();
  }
  return request.internal_id;
};
// endregion

// region scheduled maintenance (indicator deployment manager)
const setRequestAttributes = async (context: AuthContext, request: BasicStoreEntityIocValidationRequest, attributes: Record<string, unknown>) => {
  const params = buildReplaceScriptParams(attributes);
  await elUpdate(context, request._index, request.internal_id, { script: { source: EL_REPLACE_SCRIPT_SOURCE, lang: 'painless', params } });
};

/**
 * The pairs of a request with the outcome each one got for this request: the current status of the deployments still
 * bound to it, the outcome recorded earlier for the pairs a newer request took over since. A timed out pair stays
 * marked as such only while its outcome is still the timeout error.
 */
export const withPairOutcomes = (pairs: IocValidationPair[], boundDeployments: Array<{ internal_id: string; validation_status?: string | null }>) => {
  const bound = new Map(boundDeployments.map((deployment) => [deployment.internal_id, deployment.validation_status]));
  return pairs.map((pair) => {
    if (!bound.has(pair.deployed_on_id)) {
      return pair;
    }
    const { timed_out: timedOut, ...outcome } = { ...pair, validation_status: bound.get(pair.deployed_on_id) ?? undefined };
    return timedOut && outcome.validation_status === VALIDATION_STATUS_ERROR ? { ...outcome, timed_out: true } : outcome;
  });
};

export const summarizeRequestPairs = (pairs: IocValidationPair[], skipped: number) => {
  return summarizeValidationResults(pairs.length, skipped, pairs.map((pair) => pair.validation_status).filter((status): status is string => !!status));
};

// A newer request took these deployments over: the earlier request keeps the outcome it got for them.
const recordTakenOverOutcomes = async (context: AuthContext, requestId: string, outcomes: Map<string, string>) => {
  try {
    await withRequestLock(requestId, async () => {
      const request = await findIocValidationRequest(context, SYSTEM_USER, requestId);
      if (!request) return;
      const pairs = (request.pairs ?? []).map((pair) => {
        return outcomes.has(pair.deployed_on_id) ? { ...pair, validation_status: outcomes.get(pair.deployed_on_id) } : pair;
      });
      await setRequestAttributes(context, request, { pairs, results_summary: summarizeRequestPairs(pairs, request.skipped?.length ?? 0) });
    });
  } catch (error) {
    logApp.error('[IOC-VALIDATION] Cannot record the outcomes of a request taken over by a newer one', { cause: error, requestId });
  }
};

// Must run under the request lock: reads the request again and refreshes its summary, completion and timeout.
const refreshIocValidationRequest = async (context: AuthContext, requestId: string, now: number) => {
  const request = await findIocValidationRequest(context, SYSTEM_USER, requestId);
  if (!request) {
    return false;
  }
  const deployments = await findRequestDeployments(context, request.internal_id);
  const isOpen = OPEN_REQUEST_STATUSES.includes(request.status);
  // Pairs moved to a newer request keep the outcome recorded for this one, so a completed request never looks pending.
  const pairs = withPairOutcomes(request.pairs ?? [], deployments);
  const summary = summarizeRequestPairs(pairs, request.skipped?.length ?? 0);
  const attributes: Record<string, unknown> = {};
  if (JSON.stringify(summary) !== JSON.stringify(request.results_summary)) {
    attributes.results_summary = summary;
  }
  if (JSON.stringify(pairs) !== JSON.stringify(request.pairs ?? [])) {
    attributes.pairs = pairs;
  }
  const dispatchedAt = request.dispatched_at ? new Date(request.dispatched_at).getTime() : new Date(request.created_at as unknown as string).getTime();
  if (isOpen && isSummaryComplete(summary)) {
    attributes.status = summary.error > 0 ? REQUEST_STATUS_PARTIAL : REQUEST_STATUS_COMPLETED;
    attributes.completed_at = new Date();
  } else if (isOpen && now - dispatchedAt > IOC_VALIDATION_TIMEOUT_MS) {
    const timedOut = await resolvePendingPairs(context, request.internal_id, VALIDATION_STATUS_ERROR);
    const expiredPairs = withPairOutcomes(request.pairs ?? [], await findRequestDeployments(context, request.internal_id))
      .map((pair) => (timedOut.has(pair.deployed_on_id) ? { ...pair, timed_out: true } : pair));
    attributes.pairs = expiredPairs;
    attributes.results_summary = summarizeRequestPairs(expiredPairs, request.skipped?.length ?? 0);
    attributes.status = REQUEST_STATUS_EXPIRED;
    attributes.status_message = request.status === REQUEST_STATUS_PENDING
      ? 'The dispatch to OpenAEV was interrupted before it was confirmed: request the validation again'
      : 'No result received from OpenAEV before the timeout';
    attributes.completed_at = new Date();
  }
  if (Object.keys(attributes).length === 0) {
    return false;
  }
  await setRequestAttributes(context, request, { ...attributes, updated_at: new Date() });
  return true;
};

/**
 * - dispatch pending requests when a connector becomes available,
 * - refresh the results summary from the deployed-on relationships (results arrive through bundles),
 * - complete requests whose every pair got an answer, expire the ones without answer after the timeout.
 * One bounded page per run, the cursor kept in Redis, so a backlog never makes a run unbounded and every request is
 * reached in turn; the scan restarts from the beginning once the end is reached.
 */
export const maintainIocValidationRequests = async (context: AuthContext, pageSize = MAINTENANCE_PAGE_SIZE) => {
  const now = Date.now();
  const after = (await redisGetManagerEventState(MAINTENANCE_CURSOR_STATE)) || undefined;
  const page = await pageEntitiesConnection<BasicStoreEntityIocValidationRequest>(context, SYSTEM_USER, [ENTITY_TYPE_IOC_VALIDATION_REQUEST], {
    first: pageSize,
    after,
    orderBy: 'internal_id',
    orderMode: 'asc',
    filters: {
      mode: 'or' as never,
      filters: [
        { key: ['status'], values: OPEN_REQUEST_STATUSES },
        { key: ['completed_at'], values: [new Date(now - SUMMARY_REFRESH_WINDOW_MS).toISOString()], operator: 'gt' as never },
      ],
      filterGroups: [],
    },
    noFiltersChecking: true,
  } as never);
  const done = !page.pageInfo.hasNextPage || !page.pageInfo.endCursor;
  await redisSetManagerEventState(MAINTENANCE_CURSOR_STATE, done ? '' : String(page.pageInfo.endCursor));
  const requests = page.edges.map((edge) => edge.node);
  let processed = 0;
  let failed = 0;
  await BluePromise.map(requests, async (listed) => {
    try {
      // A pending request with a work was claimed by a dispatch that may not have published it: it is never sent
      // again, and expires after the timeout like a request OpenAEV never answered.
      if (listed.status === REQUEST_STATUS_PENDING && isEmptyField(listed.work_id)) {
        const current = await findIocValidationRequest(context, SYSTEM_USER, listed.internal_id);
        if (current?.status === REQUEST_STATUS_PENDING && isEmptyField(current.work_id)) {
          await dispatchIocValidationRequest(context, current as unknown as StoreEntityIocValidationRequest);
          processed += 1;
          return;
        }
      }
      // An OpenAEV lifecycle update can land between the listing and this point: decide on the current request,
      // under the lock of the lifecycle callback, so a final status is never overwritten by a stale decision.
      const updated = await withRequestLock(listed.internal_id, () => refreshIocValidationRequest(context, listed.internal_id, now));
      if (updated) {
        processed += 1;
      }
    } catch (error) {
      // Still open, so a later scan reaches it again
      failed += 1;
      logApp.warn('[IOC-VALIDATION] Request maintenance failed, left to a later scan', { cause: error, requestId: listed.internal_id });
    }
  }, { concurrency: CONCURRENCY });
  if (failed > 0) {
    logApp.warn('[IOC-VALIDATION] Requests left to a later maintenance scan', { errors_count: failed, total_count: requests.length });
  }
  return processed;
};
// endregion

// region resolvers helpers
// Every field of every request of a page goes through the request-scoped batch loader, which applies
// the reader's access like storeLoadByIds: one lookup per resolution tick instead of one per field.
// That loader is bound to the request user, so any other user is loaded directly.
const loadReadableByIds = async <T extends BasicStoreBase>(context: AuthContext, user: AuthUser, ids: string[], type: string): Promise<T[]> => {
  const uniqueIds = [...new Set(ids)];
  if (uniqueIds.length === 0) return [];
  const loader = context.user?.id === user.id ? context.batch?.idsBatchLoader : undefined;
  const loaded: Array<T | undefined> = loader
    ? await Promise.all(uniqueIds.map((id) => loader.load({ id, type })))
    : await storeLoadByIds<T>(context, user, uniqueIds, type);
  return loaded.filter((element): element is T => !!element);
};

const findReaderIndicatorIds = async (context: AuthContext, user: AuthUser, indicatorIds: string[]) => {
  const indicators = await loadReadableByIds<BasicStoreEntityIndicator>(context, user, indicatorIds, ENTITY_TYPE_INDICATOR);
  return new Set(indicators.map((i) => i.internal_id));
};

export const loadRequestPlatforms = (context: AuthContext, user: AuthUser, request: BasicStoreEntityIocValidationRequest) => {
  return loadReadableByIds<BasicStoreEntitySecurityPlatform>(context, user, request.platform_ids ?? [], ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM);
};

// A deployment is read with both of its ends: an end restricted since (authorized members, sharing) hides it.
export const loadRequestDeployments = async (context: AuthContext, user: AuthUser, request: BasicStoreEntityIocValidationRequest) => {
  const ids = (request.pairs ?? []).map((pair) => pair.deployed_on_id);
  const [deployments, readableIndicators, readablePlatforms] = await Promise.all([
    loadReadableByIds<BasicStoreRelationDeployedOn>(context, user, ids, RELATION_DEPLOYED_ON),
    findReaderIndicatorIds(context, user, request.indicator_ids ?? []),
    filterReadablePlatformIds(context, user, request),
  ]);
  const platforms = new Set(readablePlatforms);
  return deployments.filter((deployment) => readableIndicators.has(deployment.fromId) && platforms.has(deployment.toId));
};

// The outcome of each readable pair for this request, never the verdict of a newer request on the same deployment
export const loadRequestPairOutcomes = async (context: AuthContext, user: AuthUser, request: BasicStoreEntityIocValidationRequest) => {
  const deployments = await loadRequestDeployments(context, user, request);
  const readableIds = new Set(deployments.map((deployment) => deployment.internal_id));
  const bound = deployments.filter((deployment) => deployment.validation_run_id === request.internal_id);
  const pairs = (request.pairs ?? []).filter((pair) => readableIds.has(pair.deployed_on_id));
  return withPairOutcomes(pairs, bound).map((pair) => ({ deployed_on_id: pair.deployed_on_id, validation_status: pair.validation_status ?? null }));
};

export const loadRequestConnector = async (context: AuthContext, user: AuthUser, request: BasicStoreEntityIocValidationRequest) => {
  if (!request.connector_id) return null;
  const connectors = await storeLoadByIds(context, user, [request.connector_id], ENTITY_TYPE_CONNECTOR);
  return connectors.find((c) => c) ?? null;
};

export const filterReadableIocs = async (context: AuthContext, user: AuthUser, request: BasicStoreEntityIocValidationRequest) => {
  const readable = await findReaderIndicatorIds(context, user, request.indicator_ids ?? []);
  return {
    iocs: (request.iocs ?? []).filter((ioc) => readable.has(ioc.indicator_id)),
    readable,
  };
};

export const filterReadableIndicatorIds = async (context: AuthContext, user: AuthUser, request: BasicStoreEntityIocValidationRequest) => {
  const readable = await findReaderIndicatorIds(context, user, request.indicator_ids ?? []);
  return (request.indicator_ids ?? []).filter((id) => readable.has(id));
};

export const filterReadablePlatformIds = async (context: AuthContext, user: AuthUser, request: BasicStoreEntityIocValidationRequest) => {
  const platforms = await loadRequestPlatforms(context, user, request);
  const readable = new Set(platforms.map((p) => p.internal_id));
  return (request.platform_ids ?? []).filter((id) => readable.has(id));
};

/**
 * The skipped tests the reader may see. A skip on a security platform tells the state of a deployment: it keeps its
 * reason only while the reader can read a deployment of the pair, otherwise it reads as not deployed, so a deployment
 * the reader cannot read is never told apart from a missing one.
 */
export const filterReadableSkipped = async (context: AuthContext, user: AuthUser, request: BasicStoreEntityIocValidationRequest) => {
  const ids = [...new Set((request.skipped ?? []).map((s) => s.indicator_id))];
  const [readable, readablePlatforms] = await Promise.all([
    findReaderIndicatorIds(context, user, ids),
    filterReadablePlatformIds(context, user, request),
  ]);
  const platforms = new Set(readablePlatforms);
  const visible = (request.skipped ?? []).filter((s) => readable.has(s.indicator_id) && (!s.platform_id || platforms.has(s.platform_id)));
  const onPlatforms = visible.filter((s) => s.platform_id);
  if (onPlatforms.length === 0) {
    return visible;
  }
  const deployments = await fullRelationsList<BasicStoreRelationDeployedOn>(context, user, RELATION_DEPLOYED_ON, {
    fromId: [...new Set(onPlatforms.map((s) => s.indicator_id))],
    toId: [...new Set(onPlatforms.map((s) => s.platform_id as string))],
    baseData: true,
  } as never);
  const readablePairs = new Set(deployments.map((deployment) => `${deployment.fromId}|${deployment.toId}`));
  return visible.map((s) => (!s.platform_id || readablePairs.has(`${s.indicator_id}|${s.platform_id}`) ? s : { ...s, reason: SKIP_REASON_NOT_DEPLOYED }));
};

export const readableResultsSummary = async (context: AuthContext, user: AuthUser, request: BasicStoreEntityIocValidationRequest) => {
  const [readableIndicators, readablePlatforms, skipped] = await Promise.all([
    findReaderIndicatorIds(context, user, request.indicator_ids ?? []),
    filterReadablePlatformIds(context, user, request),
    filterReadableSkipped(context, user, request),
  ]);
  const platforms = new Set(readablePlatforms);
  // A deployment carries the markings of both ends: a reader of the indicator and of the platform may still not read it.
  const readableDeployments = await loadRequestDeployments(context, user, request);
  const readableDeploymentIds = new Set(readableDeployments.map((d) => d.internal_id));
  const fullyReadable = (request.indicator_ids ?? []).every((id) => readableIndicators.has(id))
    && (request.platform_ids ?? []).every((id) => platforms.has(id))
    && (request.pairs ?? []).every((pair) => readableDeploymentIds.has(pair.deployed_on_id))
    && skipped.length === (request.skipped ?? []).length;
  if (fullyReadable) {
    return request.results_summary ?? emptyResultsSummary();
  }
  const pairs = (request.pairs ?? []).filter((pair) => readableIndicators.has(pair.indicator_id)
    && platforms.has(pair.platform_id)
    && readableDeploymentIds.has(pair.deployed_on_id));
  // Outcomes of this request only: a pair taken over by a newer request keeps the outcome recorded for this one
  const bound = readableDeployments.filter((d) => d.validation_run_id === request.internal_id);
  return summarizeRequestPairs(withPairOutcomes(pairs, bound), skipped.length);
};
// endregion
