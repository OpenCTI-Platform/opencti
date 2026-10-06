/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import { Readable } from 'stream';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import type { BasicStoreEntityConnector } from '../../types/connector';
import { createEntity, patchAttribute } from '../../database/middleware';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { getEntitiesListFromCache, getEntitiesMapFromCache } from '../../database/cache';
import { elRawSearch } from '../../database/engine';
import { READ_INDEX_STIX_CYBER_OBSERVABLES, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../../database/utils';
import { notify, publishCacheResetEvent } from '../../database/redis';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { DatabaseError, FORBIDDEN_ACCESS, ForbiddenAccess, FunctionalError, LockTimeoutError, TYPE_LOCK_ERROR } from '../../config/errors';
import { lockResources } from '../../lock/master-lock';
import { publishUserAction } from '../../listener/UserActionListener';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { ENTITY_TYPE_PIR } from '../pir/pir-types';
import { INGESTION_SETINGESTIONS, isUserHasCapability, SETTINGS_SET_ACCESSES, SETTINGS_SETCUSTOMIZATION, SOURCE_INTELLIGENCE_MANAGER_USER, SYSTEM_USER } from '../../utils/access';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_USER } from '../../schema/internalObject';
import { ENTITY_TYPE_LABEL } from '../../schema/stixMetaObject';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { managedConnectorAdd, managedConnectorEdit, updateConnectorRequestedStatus } from '../../domain/connector';
import { addDecayRule, deleteDecayRule } from '../decayRule/decayRule-domain';
import { type BasicStoreEntityDecayRule, ENTITY_TYPE_DECAY_RULE } from '../decayRule/decayRule-types';
import { addExclusionListFile, deleteExclusionList } from '../exclusionList/exclusionList-domain';
import { ENTITY_TYPE_EXCLUSION_LIST } from '../exclusionList/exclusionList-types';
import { openDraftForwarding } from '../draftWorkspace/draftWorkspace-closure';
import { addDraftWorkspace, deleteDraftWorkspace } from '../draftWorkspace/draftWorkspace-domain';
import { userEditField } from '../user/user-domain';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import {
  ENTITY_TYPE_INGESTION_CSV,
  ENTITY_TYPE_INGESTION_JSON,
  ENTITY_TYPE_INGESTION_RSS,
  ENTITY_TYPE_INGESTION_TAXII,
  ENTITY_TYPE_INGESTION_TAXII_COLLECTION,
} from '../ingestion/ingestion-types';
import { ingestionEditField as ingestionRssEditField } from '../ingestion/ingestion-rss-domain';
import { ingestionTaxiiEditField } from '../ingestion/ingestion-taxii-domain';
import { ingestionEditField as ingestionTaxiiCollectionEditField } from '../ingestion/ingestion-taxii-collection-domain';
import { ingestionCsvEditField } from '../ingestion/ingestion-csv-domain';
import { ingestionJsonEditField } from '../ingestion/ingestion-json-domain';
import { ConnectorRequestStatus, type EditInput } from '../../generated/graphql';
import { addSourceRecommendationOutcome } from '../../manager/telemetryManager';
import { MODULES_MODMANAGE, type SourceIntelligenceSettings } from './sourceIntelligence-settings';
import {
  ACTIVE_RECOMMENDATION_STATUSES,
  type BasicStoreEntitySource,
  type BasicStoreEntitySourceRecommendation,
  ENTITY_TYPE_SOURCE,
  ENTITY_TYPE_SOURCE_RECOMMENDATION,
  RECOMMENDATION_ADD_CONNECTOR,
  RECOMMENDATION_ADD_DECAY_RULE,
  RECOMMENDATION_ADD_DENY_LIST,
  RECOMMENDATION_CHANGE_SCHEDULE,
  RECOMMENDATION_LOWER_CONFIDENCE,
  RECOMMENDATION_QUARANTINE,
  RECOMMENDATION_RAISE_CONFIDENCE,
  RECOMMENDATION_RETIRE,
  RECOMMENDATION_STATUS_APPLIED,
  RECOMMENDATION_STATUS_APPLYING,
  RECOMMENDATION_STATUS_DISMISSED,
  RECOMMENDATION_STATUS_FAILED,
  RECOMMENDATION_STATUS_PROPOSED,
  RECOMMENDATION_STATUS_REVERTED,
  RECOMMENDATION_STATUS_REVERTING,
  type RecommendationKindValue,
  REFERENCE_SCORECARD_PERIOD,
  SCORECARD_PERIOD_90D,
  SOURCE_KIND_CONNECTOR,
  SOURCE_KIND_INGESTION_FEED,
} from './sourceIntelligence-types';
import { findLiveScorecards } from './sourceIntelligence-store';
import {
  connectorMatchesCatalogEntry,
  evaluateSourceRules,
  type RecommendationProposal,
  type RuleConnector,
  type RuleFeed,
  type RuleSourceUser,
  SCHEDULE_CONFIGURATION_KEY,
} from './sourceIntelligence-rules';
import { clearDisabledSourcesLiveData, recommendationTransitionLock, recordNamedAuthors } from './sourceIntelligence-domain';
import { buildSourceResolver } from './sourceIntelligence-provenance';
import { releaseQuarantine } from './sourceIntelligence-quarantine';
import type { ContractConfigInput } from '../../generated/graphql';
import { deploymentConfiguration, requiredSettingsOfImage } from './sourceIntelligence-deployment';

export interface RecommendationApplyInput {
  // Connector deployed from the catalog that an add_connector recommendation links
  connector_id?: string | null;
  // Settings of the connector an add_connector recommendation deploys: passed to the deployment, never stored
  configuration?: readonly ContractConfigInput[] | null;
}

const DAY_MS = 24 * 3600 * 1000;
type ManagedConnector = BasicStoreEntityConnector & { manager_requested_status?: string | null; title?: string };
const STOPPED_STATUSES = ['stopping', 'stopped'];
const FEED_EDIT_FUNCTIONS: Record<string, (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => Promise<unknown>> = {
  [ENTITY_TYPE_INGESTION_RSS]: ingestionRssEditField,
  [ENTITY_TYPE_INGESTION_TAXII]: ingestionTaxiiEditField,
  [ENTITY_TYPE_INGESTION_TAXII_COLLECTION]: ingestionTaxiiCollectionEditField,
  [ENTITY_TYPE_INGESTION_CSV]: ingestionCsvEditField,
  [ENTITY_TYPE_INGESTION_JSON]: ingestionJsonEditField,
};

// region helpers
const parseJson = <T>(value: string | null | undefined, fallback: T): T => {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
};

const STALE_RECOMMENDATION = 'STALE_RECOMMENDATION';

/**
 * Applying a recommendation approves the change it previews: a target changed since the proposal (by an operator or
 * another tool) refuses the change before anything is written, and the next computation refreshes the proposal.
 */
export const assertTargetUnchanged = (what: string, previewed: unknown, current: unknown) => {
  if (previewed !== undefined && previewed !== current) {
    throw FunctionalError(
      `The ${what} changed since this recommendation was proposed (${String(previewed)}, now ${String(current)}): nothing was changed, the next computation updates the recommendation`,
      { doc_code: STALE_RECOMMENDATION, previewed, current },
    );
  }
};

const requireCapability = (user: AuthUser, autonomous: boolean, ...capabilities: string[]) => {
  // The autonomy policy acts as the source intelligence manager: a kind enters its allow-list only from a person holding
  // every capability of that kind (RECOMMENDATION_KIND_CAPABILITIES)
  if (autonomous) return;
  const missing = capabilities.filter((capability) => !isUserHasCapability(user, capability));
  if (missing.length > 0) {
    throw ForbiddenAccess('Missing capability to apply this recommendation', { capabilities: missing });
  }
};

// Recommendations of a collection gap carry the name and criteria of their PIR: they follow the access to the PIR
const canAccessRecommendationPir = async (context: AuthContext, user: AuthUser, recommendation: BasicStoreEntitySourceRecommendation) => {
  if (!recommendation.pir_id) {
    return true;
  }
  const pir = await storeLoadById(context, user, recommendation.pir_id, ENTITY_TYPE_PIR);
  return !!pir;
};

const loadRecommendation = async (context: AuthContext, user: AuthUser, id: string) => {
  const recommendation = await storeLoadById<BasicStoreEntitySourceRecommendation>(context, user, id, ENTITY_TYPE_SOURCE_RECOMMENDATION);
  if (!recommendation || !(await canAccessRecommendationPir(context, user, recommendation))) {
    throw FunctionalError('Source recommendation not found', { id });
  }
  return recommendation;
};

const feedEditFunction = (feedType: string) => {
  const fn = FEED_EDIT_FUNCTIONS[feedType];
  if (!fn) {
    throw FunctionalError('Unsupported ingestion feed type', { feedType });
  }
  return fn;
};

const connectorScheduleOf = (connector: BasicStoreEntityConnector): RuleConnector['schedule'] => {
  const configuration = (connector.manager_contract_configuration ?? []) as Array<{ key: string; value: string }>;
  const entry = configuration.find((c) => c.key === SCHEDULE_CONFIGURATION_KEY);
  return entry?.value ? { key: entry.key, value: String(entry.value) } : null;
};
// endregion

// region queries
/**
 * Every PIR the user can access, never a first page: listings scoped to accessible PIRs (gap recommendations,
 * collection gaps) must not hide the PIRs beyond an arbitrary cap. PIRs are few.
 */
export const listAccessiblePirIds = async (context: AuthContext, user: AuthUser): Promise<string[]> => {
  const accessiblePirs = await fullEntitiesList<BasicStoreEntity>(context, user, [ENTITY_TYPE_PIR], { baseData: true } as any);
  return accessiblePirs.map((pir) => pir.internal_id);
};

export const findRecommendationsPaginated = async (context: AuthContext, user: AuthUser, args: Record<string, any>) => {
  await checkEnterpriseEdition(context);
  const { status, sourceId, kind, ...opts } = args;
  const filters: any[] = [];
  if (status && status.length > 0) filters.push({ key: ['recommendation_status'], values: status, operator: 'eq', mode: 'or' });
  if (kind && kind.length > 0) filters.push({ key: ['recommendation_kind'], values: kind, operator: 'eq', mode: 'or' });
  if (sourceId) filters.push({ key: ['source_id'], values: [sourceId], operator: 'eq', mode: 'or' });
  // Only the collection gap recommendations of the PIRs the user can access
  const accessiblePirIds = await listAccessiblePirIds(context, user);
  const pirAccessGroup = {
    mode: 'or',
    filters: [
      { key: ['pir_id'], values: [], operator: 'nil', mode: 'or' },
      ...(accessiblePirIds.length > 0 ? [{ key: ['pir_id'], values: accessiblePirIds, operator: 'eq', mode: 'or' }] : []),
    ],
    filterGroups: [],
  };
  const finalFilters = { mode: 'and', filters, filterGroups: [pirAccessGroup, ...(opts.filters ? [opts.filters] : [])] } as any;
  return pageEntitiesConnection<BasicStoreEntitySourceRecommendation>(context, user, [ENTITY_TYPE_SOURCE_RECOMMENDATION], {
    ...opts,
    filters: finalFilters,
    orderBy: opts.orderBy ?? 'proposed_at',
    orderMode: opts.orderMode ?? 'desc',
  });
};

export const findRecommendationById = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkEnterpriseEdition(context);
  const recommendation = await storeLoadById<BasicStoreEntitySourceRecommendation>(context, user, id, ENTITY_TYPE_SOURCE_RECOMMENDATION);
  if (!recommendation || !(await canAccessRecommendationPir(context, user, recommendation))) {
    return null;
  }
  return recommendation;
};

export const countRecommendations = async (context: AuthContext, user: AuthUser, sourceId: string, status: string[]) => {
  const connection = await pageEntitiesConnection<BasicStoreEntitySourceRecommendation>(context, user, [ENTITY_TYPE_SOURCE_RECOMMENDATION], {
    first: 1,
    filters: {
      mode: 'and',
      filters: [
        { key: ['source_id'], values: [sourceId], operator: 'eq', mode: 'or' },
        { key: ['recommendation_status'], values: status, operator: 'eq', mode: 'or' },
      ],
      filterGroups: [],
    } as any,
  });
  return connection.pageInfo.globalCount ?? 0;
};
// endregion

// region executors
interface ExecutionResult {
  apply_result: string;
  revert_payload: Record<string, unknown>;
}

const collectFalsePositiveValues = async (context: AuthContext, source: BasicStoreEntitySource, settings: SourceIntelligenceSettings, maxValues: number) => {
  const labels = await getEntitiesListFromCache<BasicStoreEntity & { value: string }>(context, SYSTEM_USER, ENTITY_TYPE_LABEL).catch(() => []);
  const fpLabelIds = labels
    .filter((label) => settings.false_positive_labels.includes((label.value ?? '').toLowerCase()))
    .map((label) => label.internal_id);
  if (fpLabelIds.length === 0) {
    return new Map<string, Set<string>>();
  }
  // Same attribution as the scorecard: the author of the false positives, or the users having written them
  const sourceFilter = source.source_kind === 'author'
    ? { terms: { 'rel_created-by.internal_id.keyword': [source.ref_id] } }
    : { terms: { 'creator_id.keyword': source.source_user_ids ?? [] } };
  const data = await elRawSearch(context, SYSTEM_USER, ENTITY_TYPE_SOURCE_RECOMMENDATION, {
    index: [READ_INDEX_STIX_CYBER_OBSERVABLES, READ_INDEX_STIX_DOMAIN_OBJECTS],
    size: Math.min(maxValues, 10000),
    track_total_hits: false,
    body: {
      query: {
        bool: {
          filter: [
            sourceFilter,
            { terms: { 'rel_object-label.internal_id.keyword': fpLabelIds } },
            { bool: { should: [{ exists: { field: 'observable_value' } }, { term: { 'entity_type.keyword': ENTITY_TYPE_INDICATOR } }], minimum_should_match: 1 } },
          ],
        },
      },
      _source: ['entity_type', 'observable_value', 'name', 'x_opencti_main_observable_type'],
    },
  }).catch((err: unknown) => {
    throw DatabaseError('Source intelligence false positives lookup failed', { cause: err });
  });
  const valuesByType = new Map<string, Set<string>>();
  (data.hits?.hits ?? []).forEach((hit: any) => {
    const doc = hit._source;
    const type = isStixCyberObservable(doc.entity_type) ? doc.entity_type : doc.x_opencti_main_observable_type;
    const value = isStixCyberObservable(doc.entity_type) ? doc.observable_value : doc.name;
    if (!type || type === 'Unknown' || !value || String(value).includes('\n')) return;
    const values = valuesByType.get(type) ?? new Set<string>();
    values.add(String(value).trim());
    valuesByType.set(type, values);
  });
  return valuesByType;
};

// Set by an action right before its first write: a failure before it changed nothing and can be retried
interface ApplyProgress {
  writing: boolean;
}

const executeApply = async (
  context: AuthContext,
  user: AuthUser,
  recommendation: BasicStoreEntitySourceRecommendation,
  source: BasicStoreEntitySource | null,
  settings: SourceIntelligenceSettings,
  autonomous: boolean,
  input: RecommendationApplyInput,
  progress: ApplyProgress,
): Promise<ExecutionResult> => {
  const payload = parseJson<Record<string, any>>(recommendation.payload, {});
  switch (recommendation.recommendation_kind) {
    case RECOMMENDATION_LOWER_CONFIDENCE:
    case RECOMMENDATION_RAISE_CONFIDENCE: {
      requireCapability(user, autonomous, SETTINGS_SET_ACCESSES);
      type ConfidenceUser = BasicStoreEntity & { user_confidence_level?: { max_confidence: number; overrides: unknown[] } | null };
      const target = await storeLoadById<ConfidenceUser>(context, SYSTEM_USER, payload.user_id, ENTITY_TYPE_USER);
      if (!target) throw FunctionalError('Source user not found', { user_id: payload.user_id });
      // The proposal compared the effective max confidence of the user (its own level, or the one of its groups)
      const effective = (await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER)).get(payload.user_id);
      assertTargetUnchanged('max confidence of the source user', payload.current_max_confidence, effective?.effective_confidence_level?.max_confidence ?? 100);
      const previous = target.user_confidence_level ?? null;
      const next = { max_confidence: payload.proposed_max_confidence, overrides: previous?.overrides ?? [] };
      progress.writing = true;
      await userEditField(context, user, payload.user_id, [{ key: 'user_confidence_level', value: [next] }]);
      return {
        apply_result: `Max confidence of user ${target.name} set to ${payload.proposed_max_confidence}`,
        revert_payload: { user_id: payload.user_id, previous_user_confidence_level: previous },
      };
    }
    case RECOMMENDATION_QUARANTINE: {
      if (!source) throw FunctionalError('Source not found for the quarantine');
      // Every authorization and target check runs before the draft exists, so a refused quarantine leaves nothing behind
      let connectorUser: (BasicStoreEntity & { draft_context?: string | null }) | undefined;
      if (payload.target === 'connector_user') {
        requireCapability(user, autonomous, SETTINGS_SET_ACCESSES);
        connectorUser = await storeLoadById<BasicStoreEntity & { draft_context?: string | null }>(context, SYSTEM_USER, payload.user_id, ENTITY_TYPE_USER);
        if (!connectorUser) throw FunctionalError('Source user not found', { user_id: payload.user_id });
      } else if (payload.target === 'ingestion_feed') {
        requireCapability(user, autonomous, INGESTION_SETINGESTIONS);
      } else {
        throw FunctionalError('Unsupported quarantine target', { target: payload.target });
      }
      progress.writing = true;
      const draft = await addDraftWorkspace(context, user, {
        name: `Quarantine - ${source.name}`,
        description: `Data routed by Source Intelligence while the source ${source.name} is quarantined (recommendation ${recommendation.internal_id}).`,
      });
      const previousDraftContext = connectorUser?.draft_context ?? null;
      try {
        await openDraftForwarding(draft.id);
        if (connectorUser) {
          await userEditField(context, user, connectorUser.internal_id, [{ key: 'draft_context', value: [draft.id] }]);
        }
        await patchAttribute(context, user, source.internal_id, ENTITY_TYPE_SOURCE, { quarantined: true, quarantine_draft_id: draft.id });
      } catch (err) {
        if (connectorUser) {
          await userEditField(context, user, connectorUser.internal_id, [{ key: 'draft_context', value: [previousDraftContext ?? ''] }])
            .catch((cause: unknown) => logApp.error('[OPENCTI-MODULE] Source intelligence quarantine rollback failed', { cause, user_id: connectorUser?.internal_id }));
        }
        await deleteDraftWorkspace(context, user, draft.id)
          .catch((cause: unknown) => logApp.error('[OPENCTI-MODULE] Source intelligence quarantine draft cleanup failed', { cause, draft_id: draft.id }));
        throw err;
      }
      await publishCacheResetEvent(ENTITY_TYPE_SOURCE);
      return {
        apply_result: `New data of ${source.name} is routed into the draft ${draft.name}`,
        revert_payload: { target: payload.target, user_id: payload.user_id ?? null, previous_draft_context: previousDraftContext, draft_id: draft.id },
      };
    }
    case RECOMMENDATION_ADD_DECAY_RULE: {
      requireCapability(user, autonomous, SETTINGS_SETCUSTOMIZATION);
      progress.writing = true;
      const decayRule = await addDecayRule(context, user, {
        name: payload.name,
        description: payload.description,
        order: payload.order,
        active: true,
        decay_lifetime: payload.decay_lifetime,
        decay_pound: payload.decay_pound,
        decay_points: [...payload.decay_points],
        decay_revoke_score: payload.decay_revoke_score,
        decay_filters: payload.decay_filters,
      });
      return { apply_result: `Decay rule ${payload.name} created`, revert_payload: { decay_rule_id: decayRule.id } };
    }
    case RECOMMENDATION_ADD_DENY_LIST: {
      requireCapability(user, autonomous, SETTINGS_SETCUSTOMIZATION);
      if (!source) throw FunctionalError('Source not found for the deny list');
      const valuesByType = await collectFalsePositiveValues(context, source, settings, payload.max_values ?? settings.tuning.deny_list_max_values);
      const types = Array.from(valuesByType.keys());
      const values = Array.from(new Set(types.flatMap((type) => Array.from(valuesByType.get(type) ?? []))));
      if (values.length === 0) {
        throw FunctionalError('No false positive value found for this source anymore');
      }
      const content = values.join('\n');
      progress.writing = true;
      const exclusionList = await addExclusionListFile(context, user, {
        name: `Source Intelligence - ${source.name} false positives`,
        description: `False positives of the source ${source.name}, created by Source Intelligence (recommendation ${recommendation.internal_id}).`,
        exclusion_list_entity_types: types,
        file: Promise.resolve({ createReadStream: () => Readable.from([content]), filename: 'source-intelligence-deny-list.txt', mimetype: 'text/plain', encoding: '7bit' }),
      });
      return { apply_result: `Exclusion list created with ${values.length} values`, revert_payload: { exclusion_list_id: exclusionList.id } };
    }
    case RECOMMENDATION_RETIRE: {
      if (payload.target === 'ingestion_feed') {
        requireCapability(user, autonomous, INGESTION_SETINGESTIONS);
        const feed = await storeLoadById<BasicStoreEntity & { ingestion_running?: boolean }>(context, SYSTEM_USER, payload.feed_id, payload.feed_type);
        if (!feed) throw FunctionalError('Ingestion feed not found', { feed_id: payload.feed_id });
        progress.writing = true;
        await feedEditFunction(payload.feed_type)(context, user, payload.feed_id, [{ key: 'ingestion_running', value: [false] }]);
        return {
          apply_result: 'Ingestion feed stopped',
          revert_payload: { target: 'ingestion_feed', feed_id: payload.feed_id, feed_type: payload.feed_type, previous_running: feed.ingestion_running === true },
        };
      }
      requireCapability(user, autonomous, MODULES_MODMANAGE);
      const connector = await storeLoadById<ManagedConnector>(context, SYSTEM_USER, payload.connector_id, ENTITY_TYPE_CONNECTOR);
      if (!connector) throw FunctionalError('Connector not found', { connector_id: payload.connector_id });
      if (connector.manager_contract_image) {
        const previousStatus = connector.manager_requested_status ?? ConnectorRequestStatus.Starting;
        progress.writing = true;
        await updateConnectorRequestedStatus(context, user, { id: connector.id, status: ConnectorRequestStatus.Stopping });
        return { apply_result: 'Managed connector stopped through XTM Composer', revert_payload: { target: 'connector', connector_id: connector.id, previous_status: previousStatus } };
      }
      // Externally deployed connectors cannot be stopped by the platform: stop tracking the source and say so
      const previousEnabled = source ? source.enabled !== false : true;
      if (source && previousEnabled) {
        progress.writing = true;
        const { element } = await patchAttribute(context, user, source.internal_id, ENTITY_TYPE_SOURCE, { enabled: false });
        await clearDisabledSourcesLiveData(context, [element as unknown as BasicStoreEntitySource]);
      }
      return {
        apply_result: previousEnabled
          ? 'The connector is not managed by XTM Composer: the source is disabled, stop the connector where it is deployed'
          : 'The connector is not managed by XTM Composer and the source was already disabled: stop the connector where it is deployed',
        revert_payload: { target: 'source', source_id: source?.internal_id ?? null, previous_enabled: previousEnabled },
      };
    }
    case RECOMMENDATION_CHANGE_SCHEDULE: {
      if (payload.target === 'ingestion_feed') {
        requireCapability(user, autonomous, INGESTION_SETINGESTIONS);
        const feed = await storeLoadById<BasicStoreEntity & { scheduling_period?: string | null }>(context, SYSTEM_USER, payload.feed_id, payload.feed_type);
        if (!feed) throw FunctionalError('Ingestion feed not found', { feed_id: payload.feed_id });
        assertTargetUnchanged('schedule of the feed', payload.current_value, feed.scheduling_period ?? null);
        progress.writing = true;
        await feedEditFunction(payload.feed_type)(context, user, payload.feed_id, [{ key: 'scheduling_period', value: [payload.proposed_value] }]);
        return { apply_result: `Feed schedule set to ${payload.proposed_value}`, revert_payload: { ...payload, previous_value: feed.scheduling_period ?? payload.current_value } };
      }
      requireCapability(user, autonomous, MODULES_MODMANAGE);
      const connector = await storeLoadById<BasicStoreEntityConnector & { title?: string }>(context, SYSTEM_USER, payload.connector_id, ENTITY_TYPE_CONNECTOR);
      if (!connector || !connector.manager_contract_image) throw FunctionalError('Managed connector not found', { connector_id: payload.connector_id });
      const current = connectorScheduleOf(connector);
      assertTargetUnchanged('schedule of the connector', payload.current_value, current?.value ?? null);
      progress.writing = true;
      await managedConnectorEdit(context, user, {
        id: connector.id,
        name: connector.name,
        title: connector.title ?? connector.name,
        connector_user_id: connector.connector_user_id as string,
        manager_contract_configuration: [{ key: payload.key, value: payload.proposed_value }],
      });
      return { apply_result: `Connector schedule set to ${payload.proposed_value} through XTM Composer`, revert_payload: { ...payload, previous_value: current?.value ?? payload.current_value } };
    }
    case RECOMMENDATION_ADD_CONNECTOR: {
      requireCapability(user, autonomous, MODULES_MODMANAGE);
      if (input.connector_id) {
        const connector = await storeLoadById<BasicStoreEntityConnector>(context, SYSTEM_USER, input.connector_id, ENTITY_TYPE_CONNECTOR);
        if (!connector) throw FunctionalError('Deployed connector not found', { connector_id: input.connector_id });
        if (!connectorMatchesCatalogEntry(connector, payload)) {
          throw FunctionalError('The connector is not the catalog connector of this recommendation', {
            connector_id: input.connector_id,
            catalog_id: payload.catalog_id ?? null,
          });
        }
        // Linking deploys nothing: the connector already ran before the recommendation, so a revert leaves it running
        return { apply_result: `Connector ${connector.name} linked`, revert_payload: { connector_id: connector.id, linked: true } };
      }
      if (!payload.contract_image) {
        throw FunctionalError('This connector is not available in the local catalog, deploy it from the catalog page');
      }
      // The deployment checks its contract, the connector manager and the name before writing: a refused one can be retried
      const beforeWrite = () => {
        progress.writing = true;
      };
      const created = await managedConnectorAdd(context, user, {
        name: payload.title,
        catalog_id: payload.catalog_id,
        manager_contract_image: payload.contract_image,
        manager_contract_configuration: deploymentConfiguration(input.configuration ?? [], payload.title),
        user_id: `[C] ${payload.title}`,
        automatic_user: true,
        confidence_level: '50',
      }, { beforeWrite });
      return { apply_result: `Connector ${created.name} deployed through XTM Composer`, revert_payload: { connector_id: created.id } };
    }
    default:
      throw FunctionalError('Unknown recommendation kind', { kind: recommendation.recommendation_kind });
  }
};

/**
 * Whether undoing an apply leaves nothing of it behind. A connector the apply deployed is stopped, never removed (its
 * service account and the data it ingested stay): applying the recommendation again would deploy a second connector.
 */
export const undoLeavesNothing = (kind: string) => kind !== RECOMMENDATION_ADD_CONNECTOR;

/**
 * Whether an apply whose outcome could not be recorded gives the recommendation its previous status back, so that it
 * can be applied again: always when nothing was written (whether the action succeeded or failed before writing), and
 * after a write only once it was undone without leaving anything behind. Otherwise it stays applying, which no retry
 * applies again.
 */
export const restoresStatusAfterUnrecordedApply = (wrote: boolean, undone: boolean, kind: string) => !wrote || (undone && undoLeavesNothing(kind));

const executeRevert = async (context: AuthContext, user: AuthUser, recommendation: BasicStoreEntitySourceRecommendation, source: BasicStoreEntitySource | null) => {
  const revert = parseJson<Record<string, any>>(recommendation.revert_payload, {});
  switch (recommendation.recommendation_kind) {
    case RECOMMENDATION_LOWER_CONFIDENCE:
    case RECOMMENDATION_RAISE_CONFIDENCE:
      requireCapability(user, false, SETTINGS_SET_ACCESSES);
      await userEditField(context, user, revert.user_id, [{ key: 'user_confidence_level', value: [revert.previous_user_confidence_level ?? null] }]);
      return 'Previous confidence level restored';
    case RECOMMENDATION_QUARANTINE:
      if (revert.target === 'connector_user') {
        requireCapability(user, false, SETTINGS_SET_ACCESSES);
      } else {
        requireCapability(user, false, INGESTION_SETINGESTIONS);
      }
      await releaseQuarantine(
        context,
        user,
        source?.internal_id,
        revert.target === 'connector_user' && revert.user_id ? { userId: revert.user_id, draftContext: revert.previous_draft_context ?? '' } : undefined,
      );
      return 'Quarantine lifted, the quarantine draft is kept for review';
    case RECOMMENDATION_ADD_DECAY_RULE: {
      requireCapability(user, false, SETTINGS_SETCUSTOMIZATION);
      const rule = await storeLoadById<BasicStoreEntityDecayRule>(context, SYSTEM_USER, revert.decay_rule_id, ENTITY_TYPE_DECAY_RULE);
      if (rule) await deleteDecayRule(context, user, revert.decay_rule_id);
      return 'Decay rule removed';
    }
    case RECOMMENDATION_ADD_DENY_LIST: {
      requireCapability(user, false, SETTINGS_SETCUSTOMIZATION);
      const exclusionList = await storeLoadById<BasicStoreEntity>(context, SYSTEM_USER, revert.exclusion_list_id, ENTITY_TYPE_EXCLUSION_LIST);
      if (exclusionList) await deleteExclusionList(context, user, revert.exclusion_list_id);
      return 'Exclusion list removed';
    }
    case RECOMMENDATION_RETIRE:
      if (revert.target === 'ingestion_feed') {
        requireCapability(user, false, INGESTION_SETINGESTIONS);
        // Recommendations applied before the running state was recorded only ever stopped running feeds
        const running = revert.previous_running ?? true;
        await feedEditFunction(revert.feed_type)(context, user, revert.feed_id, [{ key: 'ingestion_running', value: [running] }]);
        return running ? 'Ingestion feed restarted' : 'Ingestion feed left stopped as before';
      }
      if (revert.target === 'connector') {
        requireCapability(user, false, MODULES_MODMANAGE);
        const status = STOPPED_STATUSES.includes(revert.previous_status) ? ConnectorRequestStatus.Stopping : ConnectorRequestStatus.Starting;
        await updateConnectorRequestedStatus(context, user, { id: revert.connector_id, status });
        return status === ConnectorRequestStatus.Starting ? 'Managed connector restarted' : 'Managed connector left stopped as before';
      }
      // A source is disabled when its connector is not managed by XTM Composer: enabling it again needs the same capability
      requireCapability(user, false, MODULES_MODMANAGE);
      // A source already disabled when the recommendation was applied stays disabled
      if (revert.previous_enabled === false) {
        return 'Source left disabled as before';
      }
      if (revert.source_id) {
        await patchAttribute(context, user, revert.source_id, ENTITY_TYPE_SOURCE, { enabled: true });
        // Stream increments read the cached sources: the re-enabled source is scored again without waiting for a reset
        await publishCacheResetEvent(ENTITY_TYPE_SOURCE);
      }
      return 'Source enabled again';
    case RECOMMENDATION_CHANGE_SCHEDULE:
      if (revert.target === 'ingestion_feed') {
        requireCapability(user, false, INGESTION_SETINGESTIONS);
        await feedEditFunction(revert.feed_type)(context, user, revert.feed_id, [{ key: 'scheduling_period', value: [revert.previous_value] }]);
        return `Feed schedule restored to ${revert.previous_value}`;
      } else {
        requireCapability(user, false, MODULES_MODMANAGE);
        const connector = await storeLoadById<BasicStoreEntityConnector & { title?: string }>(context, SYSTEM_USER, revert.connector_id, ENTITY_TYPE_CONNECTOR);
        if (!connector) throw FunctionalError('Managed connector not found', { connector_id: revert.connector_id });
        await managedConnectorEdit(context, user, {
          id: connector.id,
          name: connector.name,
          title: connector.title ?? connector.name,
          connector_user_id: connector.connector_user_id as string,
          manager_contract_configuration: [{ key: revert.key, value: revert.previous_value }],
        });
        return `Connector schedule restored to ${revert.previous_value}`;
      }
    case RECOMMENDATION_ADD_CONNECTOR:
      requireCapability(user, false, MODULES_MODMANAGE);
      if (revert.linked) {
        return 'Linked connector left running, the recommendation did not deploy it';
      }
      await updateConnectorRequestedStatus(context, user, { id: revert.connector_id, status: ConnectorRequestStatus.Stopping });
      return 'Deployed connector stopped, its data is kept';
    default:
      throw FunctionalError('Unknown recommendation kind', { kind: recommendation.recommendation_kind });
  }
};
// endregion

// region apply / revert / dismiss
// Activity records are read without the masking of restricted authors, whose names a recommendation can quote (name,
// result, error, reason): they name it by id and kind, and keep only the fields that quote no name
const AUDITED_RECOMMENDATION_FIELDS = ['recommendation_status', 'applied_at', 'applied_by_id', 'reverted_at', 'reverted_by_id', 'dismissed_at', 'dismissed_by_id'];
export const recommendationAuditName = (recommendation: Pick<BasicStoreEntitySourceRecommendation, 'internal_id' | 'recommendation_kind'>) => {
  return `\`${recommendation.internal_id}\` (${recommendation.recommendation_kind})`;
};
export const recommendationAuditInput = (recommendation: Pick<BasicStoreEntitySourceRecommendation, 'recommendation_kind'>, patch: Record<string, unknown>) => ({
  kind: recommendation.recommendation_kind,
  ...Object.fromEntries(Object.entries(patch).filter(([key]) => AUDITED_RECOMMENDATION_FIELDS.includes(key))),
});

const loadSourceOf = async (context: AuthContext, recommendation: BasicStoreEntitySourceRecommendation) => {
  return recommendation.source_id ? storeLoadById<BasicStoreEntitySource>(context, SYSTEM_USER, recommendation.source_id, ENTITY_TYPE_SOURCE) : null;
};

/**
 * Status transitions of one recommendation run one at a time, and the recommendation is loaded again once the lock
 * is held: two concurrent applies (or an apply racing a dismiss) can never both see `proposed` and run side effects.
 * The lock key is distinct from the element ids, which the middleware locks itself when patching the status.
 */
const withRecommendationTransition = async <T>(
  context: AuthContext,
  user: AuthUser,
  id: string,
  transition: (recommendation: BasicStoreEntitySourceRecommendation) => Promise<T>,
): Promise<T> => {
  const resolved = await loadRecommendation(context, user, id);
  let lock;
  try {
    lock = await lockResources([recommendationTransitionLock(resolved.internal_id)]);
    const recommendation = await loadRecommendation(context, user, resolved.internal_id);
    return await transition(recommendation);
  } catch (err: any) {
    if (err?.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds: [resolved.internal_id] });
    }
    throw err;
  } finally {
    if (lock) {
      await lock.unlock();
    }
  }
};
const applyLockedRecommendation = async (
  context: AuthContext,
  user: AuthUser,
  recommendation: BasicStoreEntitySourceRecommendation,
  settings: SourceIntelligenceSettings,
  input: RecommendationApplyInput,
  autonomous: boolean,
) => {
  const id = recommendation.internal_id;
  if (recommendation.recommendation_status !== RECOMMENDATION_STATUS_PROPOSED && recommendation.recommendation_status !== RECOMMENDATION_STATUS_FAILED) {
    throw FunctionalError('Only proposed recommendations can be applied', { id, status: recommendation.recommendation_status });
  }
  const source = await loadSourceOf(context, recommendation);
  const now = new Date().toISOString();
  // The side effect only runs once the recommendation is recorded as applying: when its outcome cannot be recorded
  // and cannot be undone, the recommendation stays applying and no retry runs the side effect a second time
  await patchAttribute(context, user, id, ENTITY_TYPE_SOURCE_RECOMMENDATION, { recommendation_status: RECOMMENDATION_STATUS_APPLYING });
  let patch: Record<string, unknown>;
  const progress: ApplyProgress = { writing: false };
  try {
    const result = await executeApply(context, user, recommendation, source, settings, autonomous, input, progress);
    patch = {
      recommendation_status: RECOMMENDATION_STATUS_APPLIED,
      applied_by_id: user.id,
      applied_at: now,
      apply_result: result.apply_result,
      revert_payload: JSON.stringify(result.revert_payload),
      error_message: null,
      autonomous,
    };
  } catch (err: any) {
    // Before the first write, nothing changed: a missing capability refuses the request (the previous status comes
    // back) and any other error fails the recommendation, which can be retried. After it, the outcome is unknown
    // (a service account or a draft may exist): the recommendation stays applying and is never applied again.
    if (!progress.writing && err?.extensions?.code === FORBIDDEN_ACCESS) {
      await patchAttribute(context, user, id, ENTITY_TYPE_SOURCE_RECOMMENDATION, { recommendation_status: recommendation.recommendation_status });
      throw err;
    }
    // A target changed since the proposal: proposed again, so that the next computation refreshes its preview
    if (!progress.writing && err?.extensions?.data?.doc_code === STALE_RECOMMENDATION) {
      await patchAttribute(context, user, id, ENTITY_TYPE_SOURCE_RECOMMENDATION, { recommendation_status: RECOMMENDATION_STATUS_PROPOSED, error_message: null });
      throw err;
    }
    logApp.warn('[OPENCTI-MODULE] Source intelligence recommendation apply failed', { cause: err, id, kind: recommendation.recommendation_kind });
    patch = {
      recommendation_status: progress.writing ? RECOMMENDATION_STATUS_APPLYING : RECOMMENDATION_STATUS_FAILED,
      error_message: err?.message ?? String(err),
      autonomous,
    };
  }
  let element;
  try {
    const namedAuthors = await recordNamedAuthors(context, recommendation, source ? [source] : []);
    ({ element } = await patchAttribute(context, user, id, ENTITY_TYPE_SOURCE_RECOMMENDATION, { ...patch, named_authors: namedAuthors }));
  } catch (persistError) {
    // The outcome could not be recorded. An action that wrote and succeeded is undone (only what this apply wrote: a
    // connector deployed beforehand and only linked is left running); one whose outcome is unknown is left as it is
    const undone = progress.writing && patch.recommendation_status === RECOMMENDATION_STATUS_APPLIED
      ? await executeRevert(context, user, { ...recommendation, revert_payload: patch.revert_payload as string }, source)
          .then(() => true)
          .catch((revertError: unknown) => {
            logApp.error('[OPENCTI-MODULE] Source intelligence could not undo an unrecorded apply, the recommendation stays applying', { cause: revertError, id });
            return false;
          })
      : false;
    if (restoresStatusAfterUnrecordedApply(progress.writing, undone, recommendation.recommendation_kind)) {
      await patchAttribute(context, user, id, ENTITY_TYPE_SOURCE_RECOMMENDATION, { recommendation_status: recommendation.recommendation_status })
        .catch((restoreError: unknown) => logApp.error('[OPENCTI-MODULE] Source intelligence could not restore an unrecorded recommendation', { cause: restoreError, id }));
    } else if (undone) {
      logApp.warn('[OPENCTI-MODULE] Source intelligence stopped the connector of an unrecorded apply, the recommendation stays applying', { id });
    }
    throw persistError;
  }
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: patch.recommendation_status === RECOMMENDATION_STATUS_APPLIED
      ? `applies the source recommendation ${recommendationAuditName(recommendation)}${autonomous ? ' (autonomy policy)' : ''}`
      : `fails to apply the source recommendation ${recommendationAuditName(recommendation)}`,
    context_data: { id, entity_type: ENTITY_TYPE_SOURCE_RECOMMENDATION, input: { ...recommendationAuditInput(recommendation, patch), autonomous } },
  });
  if (patch.recommendation_status === RECOMMENDATION_STATUS_APPLIED) {
    await addSourceRecommendationOutcome(autonomous ? 'autonomous' : 'applied');
  }
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
};

export const applySourceRecommendation = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
  settings: SourceIntelligenceSettings,
  input: RecommendationApplyInput = {},
  autonomous = false,
) => {
  await checkEnterpriseEdition(context);
  return withRecommendationTransition(context, user, id, (recommendation) => applyLockedRecommendation(context, user, recommendation, settings, input, autonomous));
};

const revertLockedRecommendation = async (context: AuthContext, user: AuthUser, recommendation: BasicStoreEntitySourceRecommendation) => {
  const id = recommendation.internal_id;
  const revertable: string[] = [RECOMMENDATION_STATUS_APPLIED, RECOMMENDATION_STATUS_REVERTING];
  if (!revertable.includes(recommendation.recommendation_status)) {
    throw FunctionalError('Only applied recommendations can be reverted', { id, status: recommendation.recommendation_status });
  }
  const source = await loadSourceOf(context, recommendation);
  // The side effect only runs once the recommendation is recorded as reverting: when its outcome cannot be recorded,
  // the recommendation stays reverting and a retry runs the revert again, every revert action being idempotent
  if (recommendation.recommendation_status === RECOMMENDATION_STATUS_APPLIED) {
    await patchAttribute(context, user, id, ENTITY_TYPE_SOURCE_RECOMMENDATION, { recommendation_status: RECOMMENDATION_STATUS_REVERTING });
  }
  let patch: Record<string, unknown>;
  try {
    const result = await executeRevert(context, user, recommendation, source);
    patch = {
      recommendation_status: RECOMMENDATION_STATUS_REVERTED,
      reverted_by_id: user.id,
      reverted_at: new Date().toISOString(),
      apply_result: `${recommendation.apply_result ?? ''}\nReverted: ${result}`.trim(),
      error_message: null,
    };
  } catch (err: any) {
    // A missing capability refuses the request before anything changed: the previous status comes back. Any other
    // failure may have reverted part of the change: the recommendation stays reverting, with the cause, to be retried
    if (err?.extensions?.code === FORBIDDEN_ACCESS) {
      await patchAttribute(context, user, id, ENTITY_TYPE_SOURCE_RECOMMENDATION, { recommendation_status: recommendation.recommendation_status });
      throw err;
    }
    logApp.warn('[OPENCTI-MODULE] Source intelligence recommendation revert failed', { cause: err, id, kind: recommendation.recommendation_kind });
    patch = { recommendation_status: RECOMMENDATION_STATUS_REVERTING, error_message: err?.message ?? String(err) };
  }
  const namedAuthors = await recordNamedAuthors(context, recommendation, source ? [source] : []);
  const { element } = await patchAttribute(context, user, id, ENTITY_TYPE_SOURCE_RECOMMENDATION, { ...patch, named_authors: namedAuthors });
  const reverted = patch.recommendation_status === RECOMMENDATION_STATUS_REVERTED;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: reverted
      ? `reverts the source recommendation ${recommendationAuditName(recommendation)}`
      : `fails to revert the source recommendation ${recommendationAuditName(recommendation)}`,
    context_data: { id, entity_type: ENTITY_TYPE_SOURCE_RECOMMENDATION, input: recommendationAuditInput(recommendation, patch) },
  });
  if (reverted) {
    await addSourceRecommendationOutcome('reverted');
  }
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
};

export const revertSourceRecommendation = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkEnterpriseEdition(context);
  return withRecommendationTransition(context, user, id, (recommendation) => revertLockedRecommendation(context, user, recommendation));
};

const dismissLockedRecommendation = async (context: AuthContext, user: AuthUser, recommendation: BasicStoreEntitySourceRecommendation, reason?: string | null) => {
  const id = recommendation.internal_id;
  // An applying recommendation may have changed its target without a record to undo it: it stays applying
  const dismissable = [RECOMMENDATION_STATUS_PROPOSED, RECOMMENDATION_STATUS_FAILED];
  if (!dismissable.includes(recommendation.recommendation_status)) {
    throw FunctionalError('Only proposed recommendations can be dismissed', { id, status: recommendation.recommendation_status });
  }
  const patch = {
    recommendation_status: RECOMMENDATION_STATUS_DISMISSED,
    dismissed_by_id: user.id,
    dismissed_at: new Date().toISOString(),
    dismiss_reason: reason ?? null,
  };
  const { element } = await patchAttribute(context, user, id, ENTITY_TYPE_SOURCE_RECOMMENDATION, patch);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `dismisses the source recommendation ${recommendationAuditName(recommendation)}`,
    context_data: { id, entity_type: ENTITY_TYPE_SOURCE_RECOMMENDATION, input: recommendationAuditInput(recommendation, patch) },
  });
  await addSourceRecommendationOutcome('dismissed');
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
};

export const dismissSourceRecommendation = async (context: AuthContext, user: AuthUser, id: string, reason?: string | null) => {
  await checkEnterpriseEdition(context);
  if (reason && reason.length > 2000) {
    throw FunctionalError('Dismiss reason too long');
  }
  return withRecommendationTransition(context, user, id, (recommendation) => dismissLockedRecommendation(context, user, recommendation, reason));
};
// endregion

// region engine
const loadAllRecommendations = async (context: AuthContext) => {
  return fullEntitiesList<BasicStoreEntitySourceRecommendation>(context, SYSTEM_USER, [ENTITY_TYPE_SOURCE_RECOMMENDATION]);
};

const createProposal = async (context: AuthContext, proposal: RecommendationProposal, nowIso: string) => {
  const payload = JSON.stringify(proposal.payload);
  const recommendation = await createEntity(context, SOURCE_INTELLIGENCE_MANAGER_USER, {
    name: proposal.name,
    rationale: proposal.rationale,
    payload,
    recommendation_evidence: JSON.stringify(proposal.evidence),
    named_authors: await recordNamedAuthors(context, { source_id: proposal.source_id, payload }),
    recommendation_kind: proposal.kind,
    recommendation_status: RECOMMENDATION_STATUS_PROPOSED,
    source_id: proposal.source_id,
    fingerprint: proposal.fingerprint,
    autonomous: false,
    proposed_at: nowIso,
    collection_gap_id: (proposal.payload.collection_gap_id as string | undefined) ?? null,
    pir_id: (proposal.payload.pir_id as string | undefined) ?? null,
  }, ENTITY_TYPE_SOURCE_RECOMMENDATION);
  return recommendation as BasicStoreEntitySourceRecommendation;
};

export const findRecommendationsByFingerprint = async (context: AuthContext, fingerprint: string, statuses: string[]) => {
  return fullEntitiesList<BasicStoreEntitySourceRecommendation>(context, SYSTEM_USER, [ENTITY_TYPE_SOURCE_RECOMMENDATION], {
    filters: {
      mode: 'and',
      filters: [
        { key: ['fingerprint'], values: [fingerprint], operator: 'eq', mode: 'or' },
        { key: ['recommendation_status'], values: statuses, operator: 'eq', mode: 'or' },
      ],
      filterGroups: [],
    },
  } as any);
};

/**
 * Looking a fingerprint up and creating its recommendation run one at a time per fingerprint: the manager proposing
 * recommendations and a one-click deployment can never create two live recommendations of the same change, each of
 * which could then be applied.
 */
const withFingerprintLock = async <T>(fingerprint: string, action: () => Promise<T>): Promise<T> => {
  let lock;
  try {
    lock = await lockResources([`source-recommendation-fingerprint:${fingerprint}`]);
    return await action();
  } catch (err: any) {
    if (err?.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds: [fingerprint] });
    }
    throw err;
  } finally {
    if (lock) {
      await lock.unlock();
    }
  }
};

/**
 * Live recommendation (proposed, or failed and retryable) of the proposal fingerprint, created when there is none.
 * Unlike upsertProposals, it never withdraws the other proposals of the same kind.
 */
export const findOrCreateProposal = async (context: AuthContext, proposal: RecommendationProposal) => {
  const openStatuses = [RECOMMENDATION_STATUS_PROPOSED, RECOMMENDATION_STATUS_APPLYING, RECOMMENDATION_STATUS_FAILED];
  return withFingerprintLock(proposal.fingerprint, async () => {
    const existing = await findRecommendationsByFingerprint(context, proposal.fingerprint, openStatuses);
    if (existing.length > 0) {
      return existing[0];
    }
    return createProposal(context, proposal, new Date().toISOString());
  });
};

/**
 * Refresh or withdrawal of a proposal by the engine, under the transition lock of the recommendation and only while it
 * is still proposed once loaded again: an apply, revert or dismiss that started since the list was read wins. A
 * transition holding the lock past its timeout leaves the recommendation to the next computation.
 */
const patchStillProposed = async (
  context: AuthContext,
  id: string,
  buildPatch: (recommendation: BasicStoreEntitySourceRecommendation) => Promise<Record<string, unknown>>,
) => {
  let lock;
  try {
    lock = await lockResources([recommendationTransitionLock(id)]);
    const recommendation = await storeLoadById<BasicStoreEntitySourceRecommendation>(context, SYSTEM_USER, id, ENTITY_TYPE_SOURCE_RECOMMENDATION);
    if (!recommendation || recommendation.recommendation_status !== RECOMMENDATION_STATUS_PROPOSED) {
      return false;
    }
    await patchAttribute(context, SOURCE_INTELLIGENCE_MANAGER_USER, id, ENTITY_TYPE_SOURCE_RECOMMENDATION, await buildPatch(recommendation));
    return true;
  } catch (err: any) {
    if (err?.name === TYPE_LOCK_ERROR) {
      logApp.info('[OPENCTI-MODULE] Source intelligence left a recommendation in transition to the next computation', { id });
      return false;
    }
    throw err;
  } finally {
    if (lock) {
      await lock.unlock();
    }
  }
};

/**
 * Persist proposals: one live recommendation per fingerprint, dismissed ones are not proposed again before the
 * cooldown, proposals not produced anymore by the rules are withdrawn (dismissed by the system).
 */
export const upsertProposals = async (
  context: AuthContext,
  proposals: RecommendationProposal[],
  settings: SourceIntelligenceSettings,
  scope: { kinds: RecommendationKindValue[] },
) => {
  const existing = await loadAllRecommendations(context);
  const byFingerprint = new Map<string, BasicStoreEntitySourceRecommendation>();
  existing
    .sort((a, b) => (a.proposed_at ?? '').localeCompare(b.proposed_at ?? ''))
    .forEach((recommendation) => byFingerprint.set(recommendation.fingerprint, recommendation));
  const now = Date.now();
  const nowIso = new Date(now).toISOString();
  const created: BasicStoreEntitySourceRecommendation[] = [];
  const proposedFingerprints = new Set(proposals.map((p) => p.fingerprint));
  for (let i = 0; i < proposals.length; i += 1) {
    const proposal = proposals[i];
    const current = byFingerprint.get(proposal.fingerprint);
    const fields = {
      name: proposal.name,
      rationale: proposal.rationale,
      payload: JSON.stringify(proposal.payload),
      recommendation_evidence: JSON.stringify(proposal.evidence),
    };
    if (current && ACTIVE_RECOMMENDATION_STATUSES.includes(current.recommendation_status as typeof ACTIVE_RECOMMENDATION_STATUSES[number])) {
      if (current.recommendation_status === RECOMMENDATION_STATUS_PROPOSED) {
        await patchStillProposed(context, current.internal_id, async (recommendation) => ({
          ...fields,
          named_authors: await recordNamedAuthors(context, { source_id: recommendation.source_id, payload: fields.payload, named_authors: recommendation.named_authors }),
        }));
      }
      continue;
    }
    if (current && current.recommendation_status === RECOMMENDATION_STATUS_DISMISSED && current.dismissed_at) {
      const cooldownEnd = new Date(current.dismissed_at).getTime() + settings.tuning.dismiss_cooldown_days * DAY_MS;
      if (cooldownEnd > now) continue;
    }
    // A one-click deployment may have created the recommendation of this fingerprint since the list was read
    const recommendation = await withFingerprintLock(proposal.fingerprint, async () => {
      const live = await findRecommendationsByFingerprint(context, proposal.fingerprint, [...ACTIVE_RECOMMENDATION_STATUSES]);
      return live.length > 0 ? null : createProposal(context, proposal, nowIso);
    });
    if (recommendation) {
      created.push(recommendation);
    }
  }
  // Withdraw the proposals the rules do not produce anymore (the situation improved)
  const outdated = existing.filter((recommendation) => recommendation.recommendation_status === RECOMMENDATION_STATUS_PROPOSED
    && scope.kinds.includes(recommendation.recommendation_kind)
    && !proposedFingerprints.has(recommendation.fingerprint));
  let withdrawn = 0;
  for (let i = 0; i < outdated.length; i += 1) {
    const isWithdrawn = await patchStillProposed(context, outdated[i].internal_id, async () => ({
      recommendation_status: RECOMMENDATION_STATUS_DISMISSED,
      dismissed_at: nowIso,
      dismiss_reason: 'Withdrawn: the condition that triggered this recommendation is no longer met',
    }));
    if (isWithdrawn) {
      withdrawn += 1;
    }
  }
  return { created, withdrawn };
};

/**
 * Recommendations the autonomy policy applies in one run: every proposed recommendation of an allowed kind, oldest
 * first, within the per-run cap. Proposals left over by the cap are taken first by the next runs; failed, dismissed
 * and applied ones are never retried automatically. A change someone reverted is never applied again automatically:
 * the proposal of the same fingerprint waits for a person.
 */
export const selectAutonomousCandidates = (recommendations: BasicStoreEntitySourceRecommendation[], settings: SourceIntelligenceSettings) => {
  const allowed = new Set(settings.autonomy.auto_apply_kinds);
  const revertedStatuses: string[] = [RECOMMENDATION_STATUS_REVERTED, RECOMMENDATION_STATUS_REVERTING];
  const revertedFingerprints = new Set(recommendations
    .filter((recommendation) => revertedStatuses.includes(recommendation.recommendation_status))
    .map((recommendation) => recommendation.fingerprint));
  return recommendations
    .filter((recommendation) => recommendation.recommendation_status === RECOMMENDATION_STATUS_PROPOSED && allowed.has(recommendation.recommendation_kind))
    .filter((recommendation) => !revertedFingerprints.has(recommendation.fingerprint))
    .sort((a, b) => (a.proposed_at ?? '').localeCompare(b.proposed_at ?? '') || a.internal_id.localeCompare(b.internal_id))
    .slice(0, Math.max(0, settings.autonomy.max_auto_actions_per_run));
};

/**
 * Autonomy policy (Enterprise Edition), run once per computation after the tuning rules and the collection gaps, so
 * the per-run cap applies once across every kind.
 */
export const applyAutonomousRecommendations = async (context: AuthContext, settings: SourceIntelligenceSettings) => {
  if (settings.autonomy.auto_apply_kinds.length === 0 || settings.autonomy.max_auto_actions_per_run <= 0) {
    return 0;
  }
  const recommendations = await loadAllRecommendations(context);
  // A connector that needs settings waits for a person to provide them when deploying it
  const needsSettings = new Set<string>();
  if (settings.autonomy.auto_apply_kinds.includes(RECOMMENDATION_ADD_CONNECTOR)) {
    const connectorProposals = recommendations.filter((recommendation) => recommendation.recommendation_kind === RECOMMENDATION_ADD_CONNECTOR
      && recommendation.recommendation_status === RECOMMENDATION_STATUS_PROPOSED);
    for (let i = 0; i < connectorProposals.length; i += 1) {
      const image = parseJson<Record<string, unknown>>(connectorProposals[i].payload, {}).contract_image;
      const required = await requiredSettingsOfImage(context, SOURCE_INTELLIGENCE_MANAGER_USER, typeof image === 'string' ? image : null);
      if (required.length > 0) {
        needsSettings.add(connectorProposals[i].internal_id);
      }
    }
  }
  const eligible = selectAutonomousCandidates(recommendations.filter((recommendation) => !needsSettings.has(recommendation.internal_id)), settings);
  for (let i = 0; i < eligible.length; i += 1) {
    try {
      await applySourceRecommendation(context, SOURCE_INTELLIGENCE_MANAGER_USER, eligible[i].internal_id, settings, {}, true);
    } catch (err) {
      logApp.error('[OPENCTI-MODULE] Source intelligence autonomous apply failed', { cause: err, id: eligible[i].internal_id });
    }
  }
  return eligible.length;
};

const buildSourceUser = (
  source: BasicStoreEntitySource,
  usersById: Map<string, AuthUser>,
  usersShared: Map<string, number>,
): RuleSourceUser | null => {
  const userId = (source.source_user_ids ?? [])[0];
  if (!userId) return null;
  const user = usersById.get(userId);
  if (!user) return null;
  return {
    id: user.internal_id,
    name: user.name,
    service_account: user.user_service_account === true,
    shared: (usersShared.get(userId) ?? 0) > 1 || user.user_service_account !== true,
    user_max_confidence: user.user_confidence_level?.max_confidence ?? null,
    effective_max_confidence: user.effective_confidence_level?.max_confidence ?? 100,
  };
};

/**
 * Run the tuning rules over every enabled source with a reference scorecard (Enterprise Edition).
 */
export const generateSourceRecommendations = async (context: AuthContext, sources: BasicStoreEntitySource[], settings: SourceIntelligenceSettings) => {
  const [reference, long] = await Promise.all([
    findLiveScorecards(context, REFERENCE_SCORECARD_PERIOD),
    findLiveScorecards(context, SCORECARD_PERIOD_90D),
  ]);
  const referenceBySource = new Map(reference.map((scorecard) => [scorecard.source_id, scorecard]));
  const longBySource = new Map(long.map((scorecard) => [scorecard.source_id, scorecard]));
  const peerNames = new Map(sources.map((source) => [source.internal_id, source.name]));
  const connectors = await getEntitiesListFromCache<ManagedConnector>(context, SYSTEM_USER, ENTITY_TYPE_CONNECTOR);
  const connectorsById = new Map(connectors.map((connector) => [connector.internal_id, connector]));
  const feedTypes = Object.keys(FEED_EDIT_FUNCTIONS);
  const feeds = await fullEntitiesList<BasicStoreEntity & { scheduling_period?: string; ingestion_running?: boolean }>(context, SYSTEM_USER, feedTypes);
  const feedsById = new Map(feeds.map((feed) => [feed.internal_id, feed]));
  const usersById = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const resolver = buildSourceResolver(sources);
  const usersShared = new Map(Array.from(resolver.byUser.entries()).map(([userId, sourceIds]) => [userId, sourceIds.length]));
  const decayRules = await getEntitiesListFromCache<BasicStoreEntityDecayRule>(context, SYSTEM_USER, ENTITY_TYPE_DECAY_RULE);
  const maxDecayRuleOrder = decayRules.reduce((max, rule) => Math.max(max, rule.order ?? 0), 0);
  const proposals: RecommendationProposal[] = [];
  sources.forEach((source) => {
    const connector = source.source_kind === SOURCE_KIND_CONNECTOR ? connectorsById.get(source.ref_id) : undefined;
    const feed = source.source_kind === SOURCE_KIND_INGESTION_FEED ? feedsById.get(source.ref_id) : undefined;
    const ruleConnector: RuleConnector | null = connector ? {
      id: connector.internal_id,
      managed: !!connector.manager_contract_image,
      schedule: connectorScheduleOf(connector),
      requested_status: connector.manager_requested_status ?? null,
    } : null;
    const ruleFeed: RuleFeed | null = feed ? {
      id: feed.internal_id,
      entity_type: feed.entity_type,
      scheduling_period: feed.scheduling_period ?? null,
      ingestion_running: feed.ingestion_running === true,
    } : null;
    proposals.push(...evaluateSourceRules({
      source,
      scorecard: referenceBySource.get(source.internal_id) ?? null,
      longScorecard: longBySource.get(source.internal_id) ?? null,
      peerScorecards: referenceBySource,
      peerNames,
      settings,
      sourceUser: buildSourceUser(source, usersById, usersShared),
      connector: ruleConnector,
      feed: ruleFeed,
      maxDecayRuleOrder,
    }));
  });
  const tuningKinds: RecommendationKindValue[] = [
    RECOMMENDATION_RAISE_CONFIDENCE,
    RECOMMENDATION_LOWER_CONFIDENCE,
    RECOMMENDATION_ADD_DECAY_RULE,
    RECOMMENDATION_CHANGE_SCHEDULE,
    RECOMMENDATION_ADD_DENY_LIST,
    RECOMMENDATION_QUARANTINE,
    RECOMMENDATION_RETIRE,
  ];
  const { created, withdrawn } = await upsertProposals(context, proposals, settings, { kinds: tuningKinds });
  logApp.info('[OPENCTI-MODULE] Source intelligence recommendations generated', { proposals: proposals.length, created: created.length, withdrawn });
  return { proposals: proposals.length, created: created.length, withdrawn };
};
// endregion
