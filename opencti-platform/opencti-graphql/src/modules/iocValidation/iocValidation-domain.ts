import { v4 as uuidv4, v5 as uuidv5 } from 'uuid';
import { Promise as BluePromise } from 'bluebird';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase } from '../../types/store';
import type { StixId } from '../../types/stix-2-1-common';
import conf, { BUS_TOPICS, logApp } from '../../config/conf';
import { ForbiddenAccess, FunctionalError, ValidationError } from '../../config/errors';
import { buildReplaceScriptParams, EL_REPLACE_SCRIPT_SOURCE, elUpdate } from '../../database/engine';
import { createRelation, patchAttribute, stixLoadByIds } from '../../database/middleware';
import { notify } from '../../database/redis';
import { isEmptyField, isNotEmptyField } from '../../database/utils';
import { lockResources } from '../../lock/master-lock';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, INPUT_MARKINGS, OPENCTI_NAMESPACE } from '../../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { fullEntitiesList, fullRelationsList, internalLoadById, pageEntitiesConnection, storeLoadById, storeLoadByIds } from '../../database/middleware-loader';
import { connectorsForEnrichment } from '../../database/repository';
import { pushToConnector } from '../../database/rabbitmq';
import { createWork } from '../../domain/work';
import { createInternalObject, deleteInternalObject } from '../../domain/internalObject';
import { CONNECTOR_INTERNAL_ENRICHMENT } from '../../schema/general';
import { ENTITY_TYPE_CONNECTOR } from '../../schema/internalObject';
import { isBypassUser, SYSTEM_USER } from '../../utils/access';
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
import { findDeployedOn, pairLockKey, refreshIndicatorDeploymentCounters } from '../indicatorDeployment/indicatorDeployment-domain';
import { pairMarkings } from '../indicatorDeployment/indicatorDeployment-utils';
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
const resolvePendingPairs = async (context: AuthContext, requestId: string, status: string) => {
  const deployments = await findRequestDeployments(context, requestId);
  const pending = deployments.filter((d) => d.validation_status === VALIDATION_STATUS_REQUESTED);
  if (pending.length > 0) {
    const attributes = status === VALIDATION_STATUS_NOT_REQUESTED
      ? { validation_status: VALIDATION_STATUS_NOT_REQUESTED, validation_run_id: null }
      : { validation_status: status, last_validation_at: new Date() };
    const resolved: Array<BasicStoreRelationDeployedOn & { _index: string }> = [];
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
  return deployments;
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
  // 03. Pairs: only (indicator, platform) couples with a known deployment are validated
  const iocIndicatorIds = iocs.map((ioc) => ioc.indicator_id);
  const deployments = iocIndicatorIds.length === 0 ? [] : await fullRelationsList<BasicStoreRelationDeployedOn & { _index: string }>(
    contextOutOfDraft,
    connectorUser,
    RELATION_DEPLOYED_ON,
    { fromId: iocIndicatorIds, toId: resolvedPlatforms.map((p) => p.internal_id) },
  );
  const pairs: IocValidationPair[] = [];
  const pairDeployments: Array<BasicStoreRelationDeployedOn & { _index: string }> = [];
  iocs.forEach((ioc) => {
    resolvedPlatforms.forEach((platform) => {
      const deployment = deployments.find((d) => d.fromId === ioc.indicator_id && d.toId === platform.internal_id);
      if (!deployment) {
        skipped.push({ indicator_id: ioc.indicator_id, platform_id: platform.internal_id, reason: 'Not deployed on this security platform' });
      } else if (!LIVE_DEPLOYMENT_STATUSES.includes(deployment.deployment_status)) {
        skipped.push({ indicator_id: ioc.indicator_id, platform_id: platform.internal_id, reason: 'Not live on this security platform' });
      } else if (deployment.revoked === true) {
        skipped.push({ indicator_id: ioc.indicator_id, platform_id: platform.internal_id, reason: 'Removal requested on this security platform' });
      } else if (deployment.validation_status === VALIDATION_STATUS_REQUESTED && deployment.validation_run_id) {
        // The pair belongs to the run that marked it until that run resolves or is deleted
        skipped.push({ indicator_id: ioc.indicator_id, platform_id: platform.internal_id, reason: 'Already waiting for the results of another validation request' });
      } else {
        pairs.push({ indicator_id: ioc.indicator_id, platform_id: platform.internal_id, deployed_on_id: deployment.internal_id });
        pairDeployments.push(deployment);
      }
    });
  });
  if (pairs.length === 0) {
    const reasons = [...new Set(skipped.map((s) => s.reason))];
    throw FunctionalError(`Nothing to validate: ${reasons.join(', ')}`, { skipped: skipped.length });
  }
  const pairIndicatorIds = new Set(pairs.map((p) => p.indicator_id));
  const validatedIocs = iocs.filter((ioc) => pairIndicatorIds.has(ioc.indicator_id));
  const name = args.name?.trim() || `Validation of ${pairIndicatorIds.size} indicator(s) on ${resolvedPlatforms.length} security platform(s)`;
  const request = await createInternalObject<StoreEntityIocValidationRequest>(contextOutOfDraft, user, {
    name,
    description: args.description ?? undefined,
    platform_ids: resolvedPlatforms.map((p) => p.internal_id),
    indicator_ids: [...pairIndicatorIds],
    test_kinds: testKinds,
    status: REQUEST_STATUS_PENDING,
    connector_id: connector.internal_id,
    results_summary: emptyResultsSummary(pairs.length, skipped.length),
    iocs: validatedIocs,
    pairs,
    skipped,
  }, ENTITY_TYPE_IOC_VALIDATION_REQUEST);
  await setPairsValidationStatus(contextOutOfDraft, pairDeployments, {
    validation_status: VALIDATION_STATUS_REQUESTED,
    validation_run_id: request.internal_id,
  });
  await addIocValidationRequestCreationCount();
  return dispatchIocValidationRequest(contextOutOfDraft, request);
};
// endregion

// region dispatch to OpenAEV
// Serializes the writes of the request status (dispatch, OpenAEV lifecycle updates).
const withRequestLock = async <T>(requestId: string, callback: () => Promise<T>): Promise<T> => {
  const lock = await lockResources([`ioc-validation-request-${requestId}`]);
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
 */
export const dispatchIocValidationRequest = async (context: AuthContext, request: StoreEntityIocValidationRequest) => {
  const connectors = await findIocValidationConnectors(context, SYSTEM_USER, true);
  const connector = request.connector_id
    ? connectors.find((c: BasicStoreBase) => c.internal_id === request.connector_id)
    : connectors[0];
  if (!connector) {
    if (request.status_message !== 'Waiting for an active OpenAEV IOC validation connector') {
      return patchRequest(context, SYSTEM_USER, request.internal_id, { status_message: 'Waiting for an active OpenAEV IOC validation connector' });
    }
    return request;
  }
  const connectorUser = await resolveConnectorUser(context, connector);
  const requesterId = requesterIdOf(request);
  const requester = requesterId ? await resolveUserByIdFromCache(context, requesterId) as AuthUser | undefined : undefined;
  const indicators = await storeLoadByIds<BasicStoreEntityIndicator>(context, connectorUser, request.indicator_ids, ENTITY_TYPE_INDICATOR);
  const platforms = await storeLoadByIds<BasicStoreEntitySecurityPlatform>(context, connectorUser, request.platform_ids, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM);
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
  const pairs: IocValidationBundlePair[] = request.pairs
    .filter((pair) => indicatorRefs.has(pair.indicator_id) && platformRefs.has(pair.platform_id) && deploymentRefs.has(pair.deployed_on_id))
    .map((pair) => ({
      indicator_ref: indicatorRefs.get(pair.indicator_id) as StixId,
      platform_ref: platformRefs.get(pair.platform_id) as StixId,
      deployed_on_ref: deploymentRefs.get(pair.deployed_on_id) as StixId,
    }));
  if (pairs.length === 0) {
    await resolvePendingPairs(context, request.internal_id, VALIDATION_STATUS_ERROR);
    return patchRequest(context, SYSTEM_USER, request.internal_id, {
      status: REQUEST_STATUS_FAILED,
      status_message: 'The indicators or deployments are no longer accessible to the OpenAEV service account',
      completed_at: new Date(),
    });
  }
  const requestObject = buildIocValidationRequestForOpenAEV(request, {
    requestedBy: requester?.name ?? 'OpenCTI',
    indicatorRefs: [...indicatorRefs.values()],
    platformRefs: [...platformRefs.values()],
    iocs: request.iocs.filter((ioc) => indicatorRefs.has(ioc.indicator_id)),
    pairs,
  });
  const bundle = { type: 'bundle', id: `bundle--${uuidv4()}`, objects: [requestObject, ...stixObjects] };
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
  await pushToConnector(connector.internal_id, message);
  logApp.info('[IOC-VALIDATION] Request dispatched to OpenAEV', { requestId: request.internal_id, connectorId: connector.internal_id, pairs: pairs.length });
  // OpenAEV can report its lifecycle before this write: an advanced status is never set back to sent.
  return withRequestLock(request.internal_id, async () => {
    const current = await findIocValidationRequest(context, SYSTEM_USER, request.internal_id);
    const patch: Record<string, unknown> = {
      connector_id: connector.internal_id,
      work_id: work.id,
      dispatched_at: new Date(),
    };
    if (!current || current.status === REQUEST_STATUS_PENDING) {
      patch.status = REQUEST_STATUS_SENT;
      patch.status_message = null;
    }
    return patchRequest(context, SYSTEM_USER, request.internal_id, patch);
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
  const found = await findIocValidationRequest(context, user, id);
  if (!found) {
    throw FunctionalError('IOC validation request not found', { id });
  }
  await assertRequestConnectorUser(context, user, found);
  return withRequestLock(found.internal_id, async () => {
    const request = await findIocValidationRequest(context, user, found.internal_id) ?? found;
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
      patch.results_summary = summarizeValidationResults(request.pairs.length, request.skipped?.length ?? 0, deployments.map((d) => d.validation_status));
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
    return patchRequest(context, user, request.internal_id, patch);
  });
};

export const IOC_VALIDATION_RESULTS_MAX_SIZE = 500;
const VALIDATION_RESULT_SIGHTING_NAMESPACE = uuidv5('opencti-ioc-validation-result', OPENCTI_NAMESPACE);

// One sighting per request and pair: a replayed result never records the outcome twice.
export const validationResultSightingStixId = (requestInternalId: string, indicatorInternalId: string, platformInternalId: string) => {
  return `sighting--${uuidv5(`${requestInternalId}|${indicatorInternalId}|${platformInternalId}`, VALIDATION_RESULT_SIGHTING_NAMESPACE)}`;
};

const toObservedAt = (value: unknown, now: Date) => {
  if (isEmptyField(value)) return now;
  const date = new Date(value as string);
  if (Number.isNaN(date.getTime())) {
    throw ValidationError('Observation date is invalid', 'observedAt');
  }
  return date;
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
  const request = await findIocValidationRequest(context, user, args.id);
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
  const now = new Date();
  const updatedIndicatorIds: string[] = [];
  await BluePromise.map(args.results, async (result) => {
    const indicator = await storeLoadById<BasicStoreEntityIndicator>(context, user, result.indicatorId, ENTITY_TYPE_INDICATOR);
    if (!indicator || !(request.indicator_ids ?? []).includes(indicator.internal_id)) {
      return;
    }
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
      const waiting = deployment.validation_status === VALIDATION_STATUS_REQUESTED;
      // A retry of the recorded verdict only repairs its sighting (the verdict is written first).
      if (!waiting && deployment.validation_status !== result.status) {
        return;
      }
      if (waiting) {
        const { element } = await patchAttribute(context, user, deployment.internal_id, RELATION_DEPLOYED_ON, {
          validation_status: result.status,
          last_validation_at: observedAt,
        });
        await notify(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].EDIT_TOPIC, element, user);
      }
      const sightingStixId = validationResultSightingStixId(request.internal_id, indicator.internal_id, platform.internal_id);
      const sighting = await internalLoadById(context, SYSTEM_USER, sightingStixId, { type: STIX_SIGHTING_RELATIONSHIP });
      if (!sighting) {
        await createRelation(context, user, {
          fromId: indicator.internal_id,
          toId: platform.internal_id,
          relationship_type: STIX_SIGHTING_RELATIONSHIP,
          stix_id: sightingStixId,
          [INPUT_MARKINGS]: pairMarkings(indicator, platform),
          attribute_count: result.hitCount ?? 1,
          first_seen: observedAt,
          last_seen: observedAt,
          x_opencti_negative: result.status === VALIDATION_STATUS_MISSED,
          description: result.evidence || `IOC validation ${result.status} reported by ${platform.name}`,
        });
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
      const deployments = await findRequestDeployments(context, request.internal_id);
      await setRequestAttributes(context, request, {
        results_summary: summarizeValidationResults(request.pairs.length, request.skipped?.length ?? 0, deployments.map((d) => d.validation_status)),
      });
    });
  }
  return findIocValidationRequest(context, user, request.internal_id);
};

export const deleteIocValidationRequest = async (context: AuthContext, user: AuthUser, id: string) => {
  const request = await findIocValidationRequest(context, user, id);
  if (!request) {
    throw FunctionalError('IOC validation request not found', { id });
  }
  // Unanswered pairs return to not requested so they are not left waiting forever
  await resolvePendingPairs(context, request.internal_id, VALIDATION_STATUS_NOT_REQUESTED);
  await deleteInternalObject(context, user, request.internal_id, ENTITY_TYPE_IOC_VALIDATION_REQUEST);
  return request.internal_id;
};
// endregion

// region scheduled maintenance (indicator deployment manager)
const setRequestAttributes = async (context: AuthContext, request: BasicStoreEntityIocValidationRequest, attributes: Record<string, unknown>) => {
  const params = buildReplaceScriptParams(attributes);
  await elUpdate(context, request._index, request.internal_id, { script: { source: EL_REPLACE_SCRIPT_SOURCE, lang: 'painless', params } });
};

// Must run under the request lock: reads the request again and refreshes its summary, completion and timeout.
const refreshIocValidationRequest = async (context: AuthContext, requestId: string, now: number) => {
  const request = await findIocValidationRequest(context, SYSTEM_USER, requestId);
  if (!request) {
    return false;
  }
  const deployments = await findRequestDeployments(context, request.internal_id);
  const summary = summarizeValidationResults(request.pairs?.length ?? 0, request.skipped?.length ?? 0, deployments.map((d) => d.validation_status));
  const attributes: Record<string, unknown> = {};
  if (JSON.stringify(summary) !== JSON.stringify(request.results_summary)) {
    attributes.results_summary = summary;
  }
  const isOpen = OPEN_REQUEST_STATUSES.includes(request.status);
  const dispatchedAt = request.dispatched_at ? new Date(request.dispatched_at).getTime() : new Date(request.created_at as unknown as string).getTime();
  if (isOpen && isSummaryComplete(summary)) {
    attributes.status = summary.error > 0 ? REQUEST_STATUS_PARTIAL : REQUEST_STATUS_COMPLETED;
    attributes.completed_at = new Date();
  } else if (isOpen && now - dispatchedAt > IOC_VALIDATION_TIMEOUT_MS) {
    await resolvePendingPairs(context, request.internal_id, VALIDATION_STATUS_ERROR);
    const expiredDeployments = await findRequestDeployments(context, request.internal_id);
    attributes.results_summary = summarizeValidationResults(request.pairs?.length ?? 0, request.skipped?.length ?? 0, expiredDeployments.map((d) => d.validation_status));
    attributes.status = REQUEST_STATUS_EXPIRED;
    attributes.status_message = 'No result received from OpenAEV before the timeout';
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
 */
export const maintainIocValidationRequests = async (context: AuthContext) => {
  const now = Date.now();
  const requests = await fullEntitiesList<BasicStoreEntityIocValidationRequest>(context, SYSTEM_USER, [ENTITY_TYPE_IOC_VALIDATION_REQUEST], {
    filters: {
      mode: 'or' as never,
      filters: [
        { key: ['status'], values: OPEN_REQUEST_STATUSES },
        { key: ['completed_at'], values: [new Date(now - SUMMARY_REFRESH_WINDOW_MS).toISOString()], operator: 'gt' as never },
      ],
      filterGroups: [],
    },
    noFiltersChecking: true,
  });
  let processed = 0;
  await BluePromise.map(requests, async (listed) => {
    try {
      if (listed.status === REQUEST_STATUS_PENDING) {
        const current = await findIocValidationRequest(context, SYSTEM_USER, listed.internal_id);
        if (current?.status === REQUEST_STATUS_PENDING) {
          await dispatchIocValidationRequest(context, current as unknown as StoreEntityIocValidationRequest);
          processed += 1;
        }
        return;
      }
      // An OpenAEV lifecycle update can land between the listing and this point: decide on the current request,
      // under the lock of the lifecycle callback, so a final status is never overwritten by a stale decision.
      const updated = await withRequestLock(listed.internal_id, () => refreshIocValidationRequest(context, listed.internal_id, now));
      if (updated) {
        processed += 1;
      }
    } catch (error) {
      logApp.error('[IOC-VALIDATION] Request maintenance failed', { cause: error, requestId: listed.internal_id });
    }
  }, { concurrency: CONCURRENCY });
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

export const loadRequestDeployments = (context: AuthContext, user: AuthUser, request: BasicStoreEntityIocValidationRequest) => {
  const ids = (request.pairs ?? []).map((pair) => pair.deployed_on_id);
  return loadReadableByIds<BasicStoreRelationDeployedOn>(context, user, ids, RELATION_DEPLOYED_ON);
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

export const filterReadableSkipped = async (context: AuthContext, user: AuthUser, request: BasicStoreEntityIocValidationRequest) => {
  const ids = [...new Set((request.skipped ?? []).map((s) => s.indicator_id))];
  const [readable, readablePlatforms] = await Promise.all([
    findReaderIndicatorIds(context, user, ids),
    filterReadablePlatformIds(context, user, request),
  ]);
  const platforms = new Set(readablePlatforms);
  return (request.skipped ?? []).filter((s) => readable.has(s.indicator_id) && (!s.platform_id || platforms.has(s.platform_id)));
};

export const readableResultsSummary = async (context: AuthContext, user: AuthUser, request: BasicStoreEntityIocValidationRequest) => {
  const [readableIndicators, readablePlatforms] = await Promise.all([
    findReaderIndicatorIds(context, user, request.indicator_ids ?? []),
    filterReadablePlatformIds(context, user, request),
  ]);
  const platforms = new Set(readablePlatforms);
  const fullyReadable = (request.indicator_ids ?? []).every((id) => readableIndicators.has(id))
    && (request.platform_ids ?? []).every((id) => platforms.has(id));
  if (fullyReadable) {
    return request.results_summary ?? emptyResultsSummary();
  }
  const pairs = (request.pairs ?? []).filter((pair) => readableIndicators.has(pair.indicator_id) && platforms.has(pair.platform_id));
  const skipped = await filterReadableSkipped(context, user, request);
  const pairDeploymentIds = new Set(pairs.map((pair) => pair.deployed_on_id));
  const deployments = (await loadRequestDeployments(context, user, request))
    .filter((d) => pairDeploymentIds.has(d.internal_id) && d.validation_run_id === request.internal_id);
  return summarizeValidationResults(pairs.length, skipped.length, deployments.map((d) => d.validation_status));
};
// endregion
