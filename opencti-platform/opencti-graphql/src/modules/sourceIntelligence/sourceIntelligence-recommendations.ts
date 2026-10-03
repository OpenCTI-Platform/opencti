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
import { DatabaseError, ForbiddenAccess, FunctionalError } from '../../config/errors';
import { publishUserAction } from '../../listener/UserActionListener';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { INGESTION_SETINGESTIONS, isUserHasCapability, SETTINGS_SET_ACCESSES, SETTINGS_SETCUSTOMIZATION, SOURCE_INTELLIGENCE_MANAGER_USER, SYSTEM_USER } from '../../utils/access';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_USER } from '../../schema/internalObject';
import { ENTITY_TYPE_LABEL } from '../../schema/stixMetaObject';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { managedConnectorAdd, managedConnectorEdit, updateConnectorRequestedStatus } from '../../domain/connector';
import { addDecayRule, deleteDecayRule } from '../decayRule/decayRule-domain';
import { type BasicStoreEntityDecayRule, ENTITY_TYPE_DECAY_RULE } from '../decayRule/decayRule-types';
import { addExclusionListFile, deleteExclusionList } from '../exclusionList/exclusionList-domain';
import { addDraftWorkspace } from '../draftWorkspace/draftWorkspace-domain';
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
import type { SourceIntelligenceSettings } from './sourceIntelligence-settings';
import {
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
  RECOMMENDATION_STATUS_DISMISSED,
  RECOMMENDATION_STATUS_FAILED,
  RECOMMENDATION_STATUS_PROPOSED,
  RECOMMENDATION_STATUS_REVERTED,
  type RecommendationKindValue,
  REFERENCE_SCORECARD_PERIOD,
  SCORECARD_PERIOD_90D,
  SOURCE_KIND_CONNECTOR,
  SOURCE_KIND_INGESTION_FEED,
} from './sourceIntelligence-types';
import { findLiveScorecards } from './sourceIntelligence-store';
import { evaluateSourceRules, type RecommendationProposal, type RuleConnector, type RuleFeed, type RuleSourceUser, SCHEDULE_CONFIGURATION_KEY } from './sourceIntelligence-rules';
import { buildResolverFromSources } from './sourceIntelligence-domain';

const DAY_MS = 24 * 3600 * 1000;
const MODULES_MODMANAGE = 'MODULES_MODMANAGE';
type ManagedConnector = BasicStoreEntityConnector & { manager_requested_status?: string | null; title?: string };
const STOPPED_STATUSES = ['stopping', 'stopped'];
const ACTIVE_STATUSES = [RECOMMENDATION_STATUS_PROPOSED, RECOMMENDATION_STATUS_APPLIED];
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

const requireCapability = (user: AuthUser, autonomous: boolean, ...capabilities: string[]) => {
  // The autonomy policy acts as the source intelligence manager, its allow-list has been granted by an administrator
  if (autonomous) return;
  const missing = capabilities.filter((capability) => !isUserHasCapability(user, capability));
  if (missing.length > 0) {
    throw ForbiddenAccess('Missing capability to apply this recommendation', { capabilities: missing });
  }
};

const loadRecommendation = async (context: AuthContext, user: AuthUser, id: string) => {
  const recommendation = await storeLoadById<BasicStoreEntitySourceRecommendation>(context, user, id, ENTITY_TYPE_SOURCE_RECOMMENDATION);
  if (!recommendation) {
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
export const findRecommendationsPaginated = async (context: AuthContext, user: AuthUser, args: Record<string, any>) => {
  await checkEnterpriseEdition(context);
  const { status, sourceId, kind, ...opts } = args;
  const filters: any[] = [];
  if (status && status.length > 0) filters.push({ key: ['recommendation_status'], values: status, operator: 'eq', mode: 'or' });
  if (kind && kind.length > 0) filters.push({ key: ['recommendation_kind'], values: kind, operator: 'eq', mode: 'or' });
  if (sourceId) filters.push({ key: ['source_id'], values: [sourceId], operator: 'eq', mode: 'or' });
  const finalFilters = filters.length > 0
    ? { mode: 'and', filters, filterGroups: opts.filters ? [opts.filters] : [] }
    : opts.filters;
  return pageEntitiesConnection<BasicStoreEntitySourceRecommendation>(context, user, [ENTITY_TYPE_SOURCE_RECOMMENDATION], {
    ...opts,
    filters: finalFilters,
    orderBy: opts.orderBy ?? 'proposed_at',
    orderMode: opts.orderMode ?? 'desc',
  });
};

export const findRecommendationById = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkEnterpriseEdition(context);
  return storeLoadById<BasicStoreEntitySourceRecommendation>(context, user, id, ENTITY_TYPE_SOURCE_RECOMMENDATION);
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

const executeApply = async (
  context: AuthContext,
  user: AuthUser,
  recommendation: BasicStoreEntitySourceRecommendation,
  source: BasicStoreEntitySource | null,
  settings: SourceIntelligenceSettings,
  autonomous: boolean,
  input: { connector_id?: string | null },
): Promise<ExecutionResult> => {
  const payload = parseJson<Record<string, any>>(recommendation.payload, {});
  switch (recommendation.recommendation_kind) {
    case RECOMMENDATION_LOWER_CONFIDENCE:
    case RECOMMENDATION_RAISE_CONFIDENCE: {
      requireCapability(user, autonomous, SETTINGS_SET_ACCESSES);
      type ConfidenceUser = BasicStoreEntity & { user_confidence_level?: { max_confidence: number; overrides: unknown[] } | null };
      const target = await storeLoadById<ConfidenceUser>(context, SYSTEM_USER, payload.user_id, ENTITY_TYPE_USER);
      if (!target) throw FunctionalError('Source user not found', { user_id: payload.user_id });
      const previous = target.user_confidence_level ?? null;
      const next = { max_confidence: payload.proposed_max_confidence, overrides: previous?.overrides ?? [] };
      await userEditField(context, user, payload.user_id, [{ key: 'user_confidence_level', value: [next] }]);
      return {
        apply_result: `Max confidence of user ${target.name} set to ${payload.proposed_max_confidence}`,
        revert_payload: { user_id: payload.user_id, previous_user_confidence_level: previous },
      };
    }
    case RECOMMENDATION_QUARANTINE: {
      if (!source) throw FunctionalError('Source not found for the quarantine');
      const draft = await addDraftWorkspace(context, user, {
        name: `Quarantine - ${source.name}`,
        description: `Data routed by Source Intelligence while the source ${source.name} is quarantined (recommendation ${recommendation.internal_id}).`,
      });
      let previousDraftContext: string | null = null;
      if (payload.target === 'connector_user') {
        requireCapability(user, autonomous, SETTINGS_SET_ACCESSES);
        const target = await storeLoadById<BasicStoreEntity & { draft_context?: string | null }>(context, SYSTEM_USER, payload.user_id, ENTITY_TYPE_USER);
        if (!target) throw FunctionalError('Source user not found', { user_id: payload.user_id });
        previousDraftContext = target.draft_context ?? null;
        await userEditField(context, user, payload.user_id, [{ key: 'draft_context', value: [draft.id] }]);
      }
      await patchAttribute(context, user, source.internal_id, ENTITY_TYPE_SOURCE, { quarantined: true, quarantine_draft_id: draft.id });
      await publishCacheResetEvent(ENTITY_TYPE_SOURCE);
      return {
        apply_result: `New data of ${source.name} is routed into the draft ${draft.name}`,
        revert_payload: { target: payload.target, user_id: payload.user_id ?? null, previous_draft_context: previousDraftContext, draft_id: draft.id },
      };
    }
    case RECOMMENDATION_ADD_DECAY_RULE: {
      requireCapability(user, autonomous, SETTINGS_SETCUSTOMIZATION);
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
        await feedEditFunction(payload.feed_type)(context, user, payload.feed_id, [{ key: 'ingestion_running', value: [false] }]);
        return { apply_result: 'Ingestion feed stopped', revert_payload: { target: 'ingestion_feed', feed_id: payload.feed_id, feed_type: payload.feed_type } };
      }
      requireCapability(user, autonomous, MODULES_MODMANAGE);
      const connector = await storeLoadById<ManagedConnector>(context, SYSTEM_USER, payload.connector_id, ENTITY_TYPE_CONNECTOR);
      if (!connector) throw FunctionalError('Connector not found', { connector_id: payload.connector_id });
      if (connector.manager_contract_image) {
        const previousStatus = connector.manager_requested_status ?? ConnectorRequestStatus.Starting;
        await updateConnectorRequestedStatus(context, user, { id: connector.id, status: ConnectorRequestStatus.Stopping });
        return { apply_result: 'Managed connector stopped through XTM Composer', revert_payload: { target: 'connector', connector_id: connector.id, previous_status: previousStatus } };
      }
      // Externally deployed connectors cannot be stopped by the platform: stop tracking the source and say so
      if (source) await patchAttribute(context, user, source.internal_id, ENTITY_TYPE_SOURCE, { enabled: false });
      return {
        apply_result: 'The connector is not managed by XTM Composer: the source is disabled, stop the connector where it is deployed',
        revert_payload: { target: 'source', source_id: source?.internal_id ?? null },
      };
    }
    case RECOMMENDATION_CHANGE_SCHEDULE: {
      if (payload.target === 'ingestion_feed') {
        requireCapability(user, autonomous, INGESTION_SETINGESTIONS);
        await feedEditFunction(payload.feed_type)(context, user, payload.feed_id, [{ key: 'scheduling_period', value: [payload.proposed_value] }]);
        return { apply_result: `Feed schedule set to ${payload.proposed_value}`, revert_payload: { ...payload, previous_value: payload.current_value } };
      }
      requireCapability(user, autonomous, MODULES_MODMANAGE);
      const connector = await storeLoadById<BasicStoreEntityConnector & { title?: string }>(context, SYSTEM_USER, payload.connector_id, ENTITY_TYPE_CONNECTOR);
      if (!connector || !connector.manager_contract_image) throw FunctionalError('Managed connector not found', { connector_id: payload.connector_id });
      const current = connectorScheduleOf(connector);
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
        return { apply_result: `Connector ${connector.name} deployed`, revert_payload: { connector_id: connector.id } };
      }
      if (!payload.contract_image) {
        throw FunctionalError('This connector is not available in the local catalog, deploy it from the catalog page');
      }
      const created = await managedConnectorAdd(context, user, {
        name: payload.title,
        catalog_id: payload.catalog_id,
        manager_contract_image: payload.contract_image,
        manager_contract_configuration: [],
        user_id: `[C] ${payload.title}`,
        automatic_user: true,
        confidence_level: '50',
      });
      return { apply_result: `Connector ${created.name} deployed through XTM Composer`, revert_payload: { connector_id: created.id } };
    }
    default:
      throw FunctionalError('Unknown recommendation kind', { kind: recommendation.recommendation_kind });
  }
};

const executeRevert = async (context: AuthContext, user: AuthUser, recommendation: BasicStoreEntitySourceRecommendation, source: BasicStoreEntitySource | null) => {
  const revert = parseJson<Record<string, any>>(recommendation.revert_payload, {});
  switch (recommendation.recommendation_kind) {
    case RECOMMENDATION_LOWER_CONFIDENCE:
    case RECOMMENDATION_RAISE_CONFIDENCE:
      requireCapability(user, false, SETTINGS_SET_ACCESSES);
      await userEditField(context, user, revert.user_id, [{ key: 'user_confidence_level', value: [revert.previous_user_confidence_level ?? null] }]);
      return 'Previous confidence level restored';
    case RECOMMENDATION_QUARANTINE:
      if (revert.target === 'connector_user' && revert.user_id) {
        requireCapability(user, false, SETTINGS_SET_ACCESSES);
        await userEditField(context, user, revert.user_id, [{ key: 'draft_context', value: [revert.previous_draft_context ?? ''] }]);
      }
      if (source) {
        await patchAttribute(context, user, source.internal_id, ENTITY_TYPE_SOURCE, { quarantined: false, quarantine_draft_id: null });
        await publishCacheResetEvent(ENTITY_TYPE_SOURCE);
      }
      return 'Quarantine lifted, the quarantine draft is kept for review';
    case RECOMMENDATION_ADD_DECAY_RULE: {
      requireCapability(user, false, SETTINGS_SETCUSTOMIZATION);
      const rule = await storeLoadById<BasicStoreEntityDecayRule>(context, SYSTEM_USER, revert.decay_rule_id, ENTITY_TYPE_DECAY_RULE);
      if (rule) await deleteDecayRule(context, user, revert.decay_rule_id);
      return 'Decay rule removed';
    }
    case RECOMMENDATION_ADD_DENY_LIST:
      requireCapability(user, false, SETTINGS_SETCUSTOMIZATION);
      await deleteExclusionList(context, user, revert.exclusion_list_id);
      return 'Exclusion list removed';
    case RECOMMENDATION_RETIRE:
      if (revert.target === 'ingestion_feed') {
        requireCapability(user, false, INGESTION_SETINGESTIONS);
        await feedEditFunction(revert.feed_type)(context, user, revert.feed_id, [{ key: 'ingestion_running', value: [true] }]);
        return 'Ingestion feed restarted';
      }
      if (revert.target === 'connector') {
        requireCapability(user, false, MODULES_MODMANAGE);
        const status = STOPPED_STATUSES.includes(revert.previous_status) ? ConnectorRequestStatus.Stopping : ConnectorRequestStatus.Starting;
        await updateConnectorRequestedStatus(context, user, { id: revert.connector_id, status });
        return status === ConnectorRequestStatus.Starting ? 'Managed connector restarted' : 'Managed connector left stopped as before';
      }
      if (revert.source_id) await patchAttribute(context, user, revert.source_id, ENTITY_TYPE_SOURCE, { enabled: true });
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
      await updateConnectorRequestedStatus(context, user, { id: revert.connector_id, status: ConnectorRequestStatus.Stopping });
      return 'Deployed connector stopped, its data is kept';
    default:
      throw FunctionalError('Unknown recommendation kind', { kind: recommendation.recommendation_kind });
  }
};
// endregion

// region apply / revert / dismiss
const loadSourceOf = async (context: AuthContext, recommendation: BasicStoreEntitySourceRecommendation) => {
  return recommendation.source_id ? storeLoadById<BasicStoreEntitySource>(context, SYSTEM_USER, recommendation.source_id, ENTITY_TYPE_SOURCE) : null;
};

export const applySourceRecommendation = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
  settings: SourceIntelligenceSettings,
  input: { connector_id?: string | null } = {},
  autonomous = false,
) => {
  await checkEnterpriseEdition(context);
  const recommendation = await loadRecommendation(context, user, id);
  if (recommendation.recommendation_status !== RECOMMENDATION_STATUS_PROPOSED && recommendation.recommendation_status !== RECOMMENDATION_STATUS_FAILED) {
    throw FunctionalError('Only proposed recommendations can be applied', { id, status: recommendation.recommendation_status });
  }
  const source = await loadSourceOf(context, recommendation);
  const now = new Date().toISOString();
  let patch: Record<string, unknown>;
  try {
    const result = await executeApply(context, user, recommendation, source, settings, autonomous, input);
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
    if (err?.name === 'FORBIDDEN_ACCESS') {
      throw err;
    }
    logApp.warn('[OPENCTI-MODULE] Source intelligence recommendation apply failed', { cause: err, id, kind: recommendation.recommendation_kind });
    patch = { recommendation_status: RECOMMENDATION_STATUS_FAILED, error_message: err?.message ?? String(err), autonomous };
  }
  const { element } = await patchAttribute(context, user, id, ENTITY_TYPE_SOURCE_RECOMMENDATION, patch);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: patch.recommendation_status === RECOMMENDATION_STATUS_APPLIED
      ? `applies the source recommendation \`${recommendation.name}\`${autonomous ? ' (autonomy policy)' : ''}`
      : `fails to apply the source recommendation \`${recommendation.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_SOURCE_RECOMMENDATION, input: { kind: recommendation.recommendation_kind, ...patch } },
  });
  if (patch.recommendation_status === RECOMMENDATION_STATUS_APPLIED) {
    await addSourceRecommendationOutcome(autonomous ? 'autonomous' : 'applied');
  }
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
};

export const revertSourceRecommendation = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkEnterpriseEdition(context);
  const recommendation = await loadRecommendation(context, user, id);
  if (recommendation.recommendation_status !== RECOMMENDATION_STATUS_APPLIED) {
    throw FunctionalError('Only applied recommendations can be reverted', { id, status: recommendation.recommendation_status });
  }
  const source = await loadSourceOf(context, recommendation);
  const result = await executeRevert(context, user, recommendation, source);
  const patch = {
    recommendation_status: RECOMMENDATION_STATUS_REVERTED,
    reverted_by_id: user.id,
    reverted_at: new Date().toISOString(),
    apply_result: `${recommendation.apply_result ?? ''}\nReverted: ${result}`.trim(),
  };
  const { element } = await patchAttribute(context, user, id, ENTITY_TYPE_SOURCE_RECOMMENDATION, patch);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `reverts the source recommendation \`${recommendation.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_SOURCE_RECOMMENDATION, input: { kind: recommendation.recommendation_kind, ...patch } },
  });
  await addSourceRecommendationOutcome('reverted');
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
};

export const dismissSourceRecommendation = async (context: AuthContext, user: AuthUser, id: string, reason?: string | null) => {
  await checkEnterpriseEdition(context);
  const recommendation = await loadRecommendation(context, user, id);
  if (recommendation.recommendation_status !== RECOMMENDATION_STATUS_PROPOSED && recommendation.recommendation_status !== RECOMMENDATION_STATUS_FAILED) {
    throw FunctionalError('Only proposed recommendations can be dismissed', { id, status: recommendation.recommendation_status });
  }
  if (reason && reason.length > 2000) {
    throw FunctionalError('Dismiss reason too long');
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
    message: `dismisses the source recommendation \`${recommendation.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_SOURCE_RECOMMENDATION, input: { kind: recommendation.recommendation_kind, ...patch } },
  });
  await addSourceRecommendationOutcome('dismissed');
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
};
// endregion

// region engine
const loadAllRecommendations = async (context: AuthContext) => {
  return fullEntitiesList<BasicStoreEntitySourceRecommendation>(context, SYSTEM_USER, [ENTITY_TYPE_SOURCE_RECOMMENDATION]);
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
      evidence: JSON.stringify(proposal.evidence),
    };
    if (current && ACTIVE_STATUSES.includes(current.recommendation_status as typeof ACTIVE_STATUSES[number])) {
      if (current.recommendation_status === RECOMMENDATION_STATUS_PROPOSED) {
        await patchAttribute(context, SOURCE_INTELLIGENCE_MANAGER_USER, current.internal_id, ENTITY_TYPE_SOURCE_RECOMMENDATION, fields);
      }
      continue;
    }
    if (current && current.recommendation_status === RECOMMENDATION_STATUS_DISMISSED && current.dismissed_at) {
      const cooldownEnd = new Date(current.dismissed_at).getTime() + settings.tuning.dismiss_cooldown_days * DAY_MS;
      if (cooldownEnd > now) continue;
    }
    const recommendation = await createEntity(context, SOURCE_INTELLIGENCE_MANAGER_USER, {
      ...fields,
      recommendation_kind: proposal.kind,
      recommendation_status: RECOMMENDATION_STATUS_PROPOSED,
      source_id: proposal.source_id,
      fingerprint: proposal.fingerprint,
      autonomous: false,
      proposed_at: nowIso,
      collection_gap_id: (proposal.payload.collection_gap_id as string | undefined) ?? null,
      pir_id: (proposal.payload.pir_id as string | undefined) ?? null,
    }, ENTITY_TYPE_SOURCE_RECOMMENDATION);
    created.push(recommendation as BasicStoreEntitySourceRecommendation);
  }
  // Withdraw the proposals the rules do not produce anymore (the situation improved)
  const withdrawn = existing.filter((recommendation) => recommendation.recommendation_status === RECOMMENDATION_STATUS_PROPOSED
    && scope.kinds.includes(recommendation.recommendation_kind)
    && !proposedFingerprints.has(recommendation.fingerprint));
  for (let i = 0; i < withdrawn.length; i += 1) {
    await patchAttribute(context, SOURCE_INTELLIGENCE_MANAGER_USER, withdrawn[i].internal_id, ENTITY_TYPE_SOURCE_RECOMMENDATION, {
      recommendation_status: RECOMMENDATION_STATUS_DISMISSED,
      dismissed_at: nowIso,
      dismiss_reason: 'Withdrawn: the condition that triggered this recommendation is no longer met',
    });
  }
  return { created, withdrawn: withdrawn.length };
};

export const applyAutonomousRecommendations = async (context: AuthContext, created: BasicStoreEntitySourceRecommendation[], settings: SourceIntelligenceSettings) => {
  const allowed = new Set(settings.autonomy.auto_apply_kinds);
  const eligible = created.filter((recommendation) => allowed.has(recommendation.recommendation_kind)).slice(0, settings.autonomy.max_auto_actions_per_run);
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
  const resolver = buildResolverFromSources(sources);
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
  const autonomous = await applyAutonomousRecommendations(context, created, settings);
  logApp.info('[OPENCTI-MODULE] Source intelligence recommendations generated', { proposals: proposals.length, created: created.length, withdrawn, autonomous });
  return { proposals: proposals.length, created: created.length, withdrawn, autonomous };
};
// endregion
