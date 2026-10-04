import conf, { logApp } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { stixLoadByIds } from '../../database/middleware';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { AuthContext, AuthUser } from '../../types/user';
import type { StixObject } from '../../types/stix-2-1-common';
import type { FilterGroup } from '../../generated/graphql';
import { isFilterGroupNotEmpty } from '../../utils/filtering/filtering-utils';
import { computeLandscapeDiff, isLandscapeResultAccessible } from './landscapeDiff-domain';
import type { LandscapeDiffAggregates, LandscapeDiffEntitySummary } from './timeMachine-types';
import {
  type ChangeDigestLocale,
  type ChangeDigestMessageKey,
  DEFAULT_CHANGE_DIGEST_LOCALE,
  formatChangeDigestMessage,
  joinChangeDigestParts,
} from './timeMachine-changeDigest-messages';

export const TRIGGER_TYPE_CHANGE_DIGEST = 'change_digest';
const CHANGE_DIGEST_MAX_ENTITIES: number = conf.get('time_machine:change_digest_max_entities') || 500;
// Maximum number of changed entities listed in a change digest notification
const CHANGE_DIGEST_MAX_LINES = 50;
// A digest whose content changes access during its computation is computed once more, then skipped for the period
const CHANGE_DIGEST_MAX_ATTEMPTS = 2;

export interface ChangeDigestTrigger {
  internal_id: string;
  name: string;
  filters?: string | null;
  scope_entity_types?: string[] | null;
}

export interface ChangeDigestData {
  notification_id: string;
  instance: StixObject;
  type: string;
  message: string;
}

// Malformed filters must fail the digest: falling back to no filter would broaden its scope to every entity
export const parseTriggerFilters = (filters: string | null | undefined): FilterGroup | null => {
  if (!filters) return null;
  let parsed: FilterGroup;
  try {
    parsed = JSON.parse(filters) as FilterGroup;
  } catch {
    throw FunctionalError('Change digest filters are malformed');
  }
  return isFilterGroupNotEmpty(parsed) ? parsed : null;
};

export const buildChangeMessage = (summary: LandscapeDiffEntitySummary, locale: ChangeDigestLocale = DEFAULT_CHANGE_DIGEST_LOCALE): string => {
  const message = (key: ChangeDigestMessageKey, values?: Record<string, number>) => formatChangeDigestMessage(locale, key, values);
  const parts: string[] = [];
  if (summary.created_in_period) parts.push(message('created'));
  if (summary.revoked_in_period) parts.push(message('revoked'));
  if (summary.relationships_added > 0) parts.push(message('relationships_added', { count: summary.relationships_added }));
  if (summary.relationships_removed > 0) parts.push(message('relationships_removed', { count: summary.relationships_removed }));
  if (summary.relationships_revoked > 0) parts.push(message('relationships_revoked', { count: summary.relationships_revoked }));
  if (summary.relationships_confidence_changed > 0) {
    parts.push(message('relationships_confidence_changed', { count: summary.relationships_confidence_changed }));
  }
  if (summary.attributes_changed > 0) parts.push(message('attributes_changed', { count: summary.attributes_changed }));
  const { confidence_before, confidence_after, score_before, score_after } = summary;
  if (confidence_before !== null && confidence_after !== null && confidence_before !== confidence_after) {
    parts.push(message('confidence', { before: confidence_before, after: confidence_after }));
  }
  if (score_before !== null && score_after !== null && score_before !== score_after) {
    parts.push(message('score', { before: score_before, after: score_after }));
  }
  return joinChangeDigestParts(locale, parts);
};

export interface AggregatesMessageOptions {
  // The filter set exceeded the limits of the computation: the figures only cover part of it
  partial?: boolean;
  // Number of changed entities listed in the digest, the others are only counted
  listed?: number;
  locale?: ChangeDigestLocale;
}

export const buildAggregatesMessage = (aggregates: LandscapeDiffAggregates, opts: AggregatesMessageOptions = {}): string => {
  const locale = opts.locale ?? DEFAULT_CHANGE_DIGEST_LOCALE;
  const message = (key: ChangeDigestMessageKey, values?: Record<string, number>) => formatChangeDigestMessage(locale, key, values);
  const parts = [
    message('entities_changed', { changed: aggregates.entities_changed, total: aggregates.entities_in_scope }),
    message('relationships_added', { count: aggregates.new_relationships }),
    message('relationships_removed', { count: aggregates.removed_relationships }),
    message('revocations', { count: aggregates.revocations }),
  ];
  if (aggregates.new_techniques_count > 0) parts.push(message('new_techniques', { count: aggregates.new_techniques_count }));
  if (aggregates.new_malware_count > 0) parts.push(message('new_malware', { count: aggregates.new_malware_count }));
  if (aggregates.new_tools_count > 0) parts.push(message('new_tools', { count: aggregates.new_tools_count }));
  if (aggregates.new_infrastructure_count > 0) parts.push(message('new_infrastructure', { count: aggregates.new_infrastructure_count }));
  if (opts.listed !== undefined && aggregates.entities_changed > opts.listed) {
    parts.push(message('not_listed', { count: aggregates.entities_changed - opts.listed }));
  }
  const summary = joinChangeDigestParts(locale, parts);
  return opts.partial ? `${summary} | ${message('partial')}` : summary;
};

/**
 * Build the content of a change digest for one recipient: the landscape diff of the trigger
 * filter set over the digest period, computed with the rights of the recipient.
 * Each changed entity becomes one notification line, the first emitted line carries the overall summary,
 * all written in the language of the recipient.
 * Right before emission, every element that shaped the digest (counted or named) must still be accessible:
 * when access changed during the computation the digest is computed again, and skipped for this period
 * if access keeps changing, so a reclassified element is never leaked, not even as a count.
 * The digest is counted as sent by the notification manager, once it is stored.
 */
export const buildChangeDigestData = async (
  context: AuthContext,
  user: AuthUser,
  trigger: ChangeDigestTrigger,
  from: string,
  to: string,
  locale: ChangeDigestLocale = DEFAULT_CHANGE_DIGEST_LOCALE,
): Promise<ChangeDigestData[]> => {
  const entityTypes = trigger.scope_entity_types && trigger.scope_entity_types.length > 0 ? trigger.scope_entity_types : [ABSTRACT_STIX_DOMAIN_OBJECT];
  const scope = { filters: parseTriggerFilters(trigger.filters), entityTypes };
  for (let attempt = 1; attempt <= CHANGE_DIGEST_MAX_ATTEMPTS; attempt += 1) {
    const computation = await computeLandscapeDiff(context, user, scope, from, to, 'entity_type', { maxEntities: CHANGE_DIGEST_MAX_ENTITIES });
    const changed = computation.entities.slice(0, CHANGE_DIGEST_MAX_LINES);
    if (changed.length === 0) {
      return [];
    }
    const instances = await stixLoadByIds(context, user, changed.map((summary) => summary.entity_id)) as StixObject[];
    const instancesById = new Map<string, StixObject>();
    instances.forEach((instance) => {
      const internalId = instance.extensions?.[STIX_EXT_OCTI]?.id;
      if (internalId) instancesById.set(internalId, instance);
    });
    const isAccessible = changed.every((summary) => instancesById.has(summary.entity_id))
      && await isLandscapeResultAccessible(context, user, computation.contributors, computation.aggregates, computation.entities);
    if (isAccessible) {
      const data: ChangeDigestData[] = changed.map((summary) => ({
        notification_id: trigger.internal_id,
        instance: instancesById.get(summary.entity_id) as StixObject,
        type: summary.created_in_period ? 'create' : 'update',
        message: buildChangeMessage(summary, locale),
      }));
      const overall = buildAggregatesMessage(computation.aggregates, { partial: computation.truncated, listed: data.length, locale });
      data[0] = { ...data[0], message: `${data[0].message} | ${overall}` };
      logApp.debug('[TIME MACHINE] Change digest built', { trigger: trigger.internal_id, user: user.id, lines: data.length });
      return data;
    }
    logApp.info('[TIME MACHINE] Access to the content of a change digest changed during its computation', { trigger: trigger.internal_id, user: user.id, attempt });
  }
  logApp.warn('[TIME MACHINE] Change digest skipped for this period: access to its content kept changing', { trigger: trigger.internal_id, user: user.id, from, to });
  return [];
};
