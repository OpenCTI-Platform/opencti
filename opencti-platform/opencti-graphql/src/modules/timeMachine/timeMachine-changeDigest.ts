import conf, { logApp } from '../../config/conf';
import { stixLoadByIds } from '../../database/middleware';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { AuthContext, AuthUser } from '../../types/user';
import type { StixObject } from '../../types/stix-2-1-common';
import type { FilterGroup } from '../../generated/graphql';
import { isFilterGroupNotEmpty } from '../../utils/filtering/filtering-utils';
import { addChangeDigestSentCount } from '../../manager/telemetryManager';
import { computeLandscapeDiff } from './landscapeDiff-domain';
import type { LandscapeDiffAggregates, LandscapeDiffEntitySummary } from './timeMachine-types';

export const TRIGGER_TYPE_CHANGE_DIGEST = 'change_digest';
const CHANGE_DIGEST_MAX_ENTITIES: number = conf.get('time_machine:change_digest_max_entities') || 500;
// Maximum number of changed entities listed in a change digest notification
const CHANGE_DIGEST_MAX_LINES = 50;

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

const parseTriggerFilters = (filters: string | null | undefined): FilterGroup | null => {
  if (!filters) return null;
  try {
    const parsed = JSON.parse(filters) as FilterGroup;
    return isFilterGroupNotEmpty(parsed) ? parsed : null;
  } catch {
    return null;
  }
};

const delta = (before: number | null, after: number | null) => (before !== null && after !== null && before !== after ? `\`${before}\` -> \`${after}\`` : null);

export const buildChangeMessage = (summary: LandscapeDiffEntitySummary): string => {
  const parts: string[] = [];
  if (summary.created_in_period) parts.push('created');
  if (summary.revoked_in_period) parts.push('revoked');
  if (summary.relationships_added > 0) parts.push(`\`${summary.relationships_added}\` new relationship(s)`);
  if (summary.relationships_removed > 0) parts.push(`\`${summary.relationships_removed}\` removed relationship(s)`);
  if (summary.relationships_revoked > 0) parts.push(`\`${summary.relationships_revoked}\` revoked relationship(s)`);
  if (summary.attributes_changed > 0) parts.push(`\`${summary.attributes_changed}\` attribute(s) changed`);
  const confidence = delta(summary.confidence_before, summary.confidence_after);
  if (confidence) parts.push(`confidence ${confidence}`);
  const score = delta(summary.score_before, summary.score_after);
  if (score) parts.push(`score ${score}`);
  return parts.join(', ');
};

export const buildAggregatesMessage = (aggregates: LandscapeDiffAggregates): string => {
  const parts = [
    `\`${aggregates.entities_changed}\` of \`${aggregates.entities_in_scope}\` entities changed`,
    `\`${aggregates.new_relationships}\` new relationship(s)`,
    `\`${aggregates.removed_relationships}\` removed`,
    `\`${aggregates.revocations}\` revocation(s)`,
  ];
  if (aggregates.new_techniques.length > 0) parts.push(`\`${aggregates.new_techniques.length}\` new technique(s)`);
  if (aggregates.new_malware.length > 0) parts.push(`\`${aggregates.new_malware.length}\` new malware`);
  if (aggregates.new_tools.length > 0) parts.push(`\`${aggregates.new_tools.length}\` new tool(s)`);
  if (aggregates.new_infrastructure_count > 0) parts.push(`\`${aggregates.new_infrastructure_count}\` new infrastructure`);
  return parts.join(', ');
};

/**
 * Build the content of a change digest for one recipient: the landscape diff of the trigger
 * filter set over the digest period, computed with the rights of the recipient.
 * Each changed entity becomes one notification line, the first line carries the overall summary.
 */
export const buildChangeDigestData = async (
  context: AuthContext,
  user: AuthUser,
  trigger: ChangeDigestTrigger,
  from: string,
  to: string,
): Promise<ChangeDigestData[]> => {
  const entityTypes = trigger.scope_entity_types && trigger.scope_entity_types.length > 0 ? trigger.scope_entity_types : [ABSTRACT_STIX_DOMAIN_OBJECT];
  const scope = { filters: parseTriggerFilters(trigger.filters), entityTypes };
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
  const data: ChangeDigestData[] = [];
  changed.forEach((summary, index) => {
    const instance = instancesById.get(summary.entity_id);
    if (!instance) return;
    const message = buildChangeMessage(summary);
    data.push({
      notification_id: trigger.internal_id,
      instance,
      type: summary.created_in_period ? 'create' : 'update',
      message: index === 0 ? `${message} | ${buildAggregatesMessage(computation.aggregates)}` : message,
    });
  });
  if (data.length > 0) {
    addChangeDigestSentCount();
  }
  logApp.debug('[TIME MACHINE] Change digest built', { trigger: trigger.internal_id, user: user.id, lines: data.length });
  return data;
};
