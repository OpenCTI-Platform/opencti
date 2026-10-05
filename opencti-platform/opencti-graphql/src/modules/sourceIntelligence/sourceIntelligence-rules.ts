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

import moment from 'moment';
import type { SourceIntelligenceSettings } from './sourceIntelligence-settings';
import {
  type BasicStoreEntitySource,
  RECOMMENDATION_ADD_DECAY_RULE,
  RECOMMENDATION_ADD_DENY_LIST,
  RECOMMENDATION_CHANGE_SCHEDULE,
  RECOMMENDATION_LOWER_CONFIDENCE,
  RECOMMENDATION_QUARANTINE,
  RECOMMENDATION_RAISE_CONFIDENCE,
  RECOMMENDATION_RETIRE,
  type RecommendationKindValue,
  SOURCE_KIND_AUTHOR,
  SOURCE_KIND_CONNECTOR,
  SOURCE_KIND_INGESTION_FEED,
  type StoreSourceScorecard,
} from './sourceIntelligence-types';

const HOUR_MS = 3600 * 1000;
export const SCHEDULE_CONFIGURATION_KEY = 'CONNECTOR_DURATION_PERIOD';

export interface RuleSourceUser {
  id: string;
  name: string;
  service_account: boolean;
  // Users shared by several sources (or used by humans) cannot be tuned or routed on behalf of a single source
  shared: boolean;
  user_max_confidence: number | null;
  effective_max_confidence: number;
}

export interface RuleConnector {
  id: string;
  managed: boolean;
  schedule: { key: string; value: string } | null;
  requested_status: string | null;
}

export interface RuleFeed {
  id: string;
  entity_type: string;
  scheduling_period: string | null;
  ingestion_running: boolean;
}

export interface RuleInput {
  source: BasicStoreEntitySource;
  scorecard: StoreSourceScorecard | null;
  longScorecard: StoreSourceScorecard | null;
  peerScorecards: Map<string, StoreSourceScorecard>;
  peerNames: Map<string, string>;
  settings: SourceIntelligenceSettings;
  sourceUser: RuleSourceUser | null;
  connector: RuleConnector | null;
  feed: RuleFeed | null;
  maxDecayRuleOrder: number;
}

export interface RecommendationProposal {
  kind: RecommendationKindValue;
  // Null for the recommendations of a collection gap (connector to deploy), which have no source yet
  source_id: string | null;
  fingerprint: string;
  name: string;
  rationale: string;
  payload: Record<string, unknown>;
  evidence: Record<string, unknown>;
}

export const recommendationFingerprint = (kind: string, ...parts: string[]) => [kind, ...parts].join(':');

/** Image repository without its tag or digest: the versions of one catalog entry differ by their tag only. */
export const imageRepositoryOf = (image: string | null | undefined): string | null => {
  if (!image) {
    return null;
  }
  const [withoutDigest] = image.split('@');
  // A colon before the last slash belongs to the registry port, not to a tag
  const tagSeparator = withoutDigest.lastIndexOf(':');
  return tagSeparator > withoutDigest.lastIndexOf('/') ? withoutDigest.slice(0, tagSeparator) : withoutDigest;
};

/**
 * A connector is the deployment of a catalog entry, whatever the version it was deployed or upgraded to: same catalog
 * and contract slug, or same image repository. The catalog identifier alone names a whole catalog, never one entry.
 * The collection gaps detect deployed connectors with it, and an add_connector recommendation only records such a
 * connector as its outcome, so an unrelated connector is never recorded.
 */
export const connectorMatchesCatalogEntry = (
  connector: { catalog_id?: string | null; manager_contract_image?: string | null; manager_contract?: { slug?: string | null } | null },
  entry: { catalog_id?: string | null; slug?: string | null; contract_image?: string | null },
): boolean => {
  const sameEntry = !!entry.catalog_id && !!entry.slug && connector.catalog_id === entry.catalog_id && connector.manager_contract?.slug === entry.slug;
  const repository = imageRepositoryOf(entry.contract_image);
  const sameRepository = repository !== null && imageRepositoryOf(connector.manager_contract_image) === repository;
  return sameEntry || sameRepository;
};

const percent = (value: number | null | undefined) => `${Math.round((value ?? 0) * 100)}%`;

export const parseIsoDurationMs = (value: string | null | undefined): number | null => {
  if (!value) {
    return null;
  }
  const duration = moment.duration(value);
  const ms = duration.asMilliseconds();
  return Number.isFinite(ms) && ms > 0 ? ms : null;
};

export const toIsoDuration = (ms: number): string => {
  const totalMinutes = Math.max(1, Math.round(ms / 60000));
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  if (hours > 0 && minutes > 0) return `PT${hours}H${minutes}M`;
  if (hours > 0) return `PT${hours}H`;
  return `PT${minutes}M`;
};

/**
 * Filter targeting the indicators written by a source, used by the decay rule recommendation. Decay rules are matched
 * once, against the indicator being created and its creator: the creator (or author) is the only attribution a rule
 * can act on, the later assertions of other sources never select a decay rule.
 */
export const buildSourceIndicatorFilters = (source: BasicStoreEntitySource): string | null => {
  if (source.source_kind === SOURCE_KIND_AUTHOR) {
    return JSON.stringify({
      mode: 'and',
      filters: [{ key: ['createdBy'], values: [source.ref_id], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    });
  }
  const userIds = source.source_user_ids ?? [];
  if (userIds.length === 0) {
    return null;
  }
  return JSON.stringify({
    mode: 'and',
    filters: [{ key: ['creator_id'], values: userIds, operator: 'eq', mode: 'or' }],
    filterGroups: [],
  });
};

const evidenceOf = (scorecard: StoreSourceScorecard) => ({
  period: scorecard.scorecard_period,
  computed_at: scorecard.computed_at,
  volume_total: scorecard.volume_total,
  volume_indicators: scorecard.volume_indicators,
  accuracy: scorecard.accuracy,
  evaluated_count: scorecard.evaluated_count,
  revoked_count: scorecard.revoked_count,
  negative_sightings_count: scorecard.negative_sightings_count,
  false_positive_count: scorecard.false_positive_count,
  noise: scorecard.noise,
  unique_contribution: scorecard.unique_contribution,
  corroboration_rate: scorecard.corroboration_rate,
  lead_time_hours: scorecard.lead_time_hours,
  freshness_hours: scorecard.freshness_hours,
  value_score: scorecard.value_score,
});

const confidenceRules = (input: RuleInput, proposals: RecommendationProposal[], quarantined: boolean) => {
  const { source, scorecard, settings, sourceUser } = input;
  if (!scorecard || scorecard.accuracy === null || !sourceUser || sourceUser.shared || source.source_kind === SOURCE_KIND_AUTHOR) {
    return;
  }
  const { thresholds, tuning } = settings;
  const current = sourceUser.effective_max_confidence;
  if (!quarantined && scorecard.accuracy < thresholds.low_accuracy && current > tuning.min_confidence) {
    const proposed = Math.max(tuning.min_confidence, current - tuning.confidence_step);
    proposals.push({
      kind: RECOMMENDATION_LOWER_CONFIDENCE,
      source_id: source.internal_id,
      fingerprint: recommendationFingerprint(RECOMMENDATION_LOWER_CONFIDENCE, source.internal_id),
      name: `Lower the confidence of ${source.name}`,
      rationale: `Accuracy of ${percent(scorecard.accuracy)} over ${scorecard.evaluated_count} objects is below the ${percent(thresholds.low_accuracy)} threshold `
        + `(${scorecard.revoked_count} revoked, ${scorecard.negative_sightings_count} negative sightings, ${scorecard.false_positive_count} false positives). `
        + `Lowering the max confidence of its user from ${current} to ${proposed} lets better sources win upserts.`,
      payload: { target: 'user', user_id: sourceUser.id, current_max_confidence: current, proposed_max_confidence: proposed },
      evidence: evidenceOf(scorecard),
    });
  }
  if (scorecard.accuracy >= thresholds.high_accuracy && scorecard.corroboration_rate >= thresholds.raise_confidence_corroboration && current < 100) {
    const proposed = Math.min(100, current + tuning.confidence_step);
    proposals.push({
      kind: RECOMMENDATION_RAISE_CONFIDENCE,
      source_id: source.internal_id,
      fingerprint: recommendationFingerprint(RECOMMENDATION_RAISE_CONFIDENCE, source.internal_id),
      name: `Raise the confidence of ${source.name}`,
      rationale: `Accuracy of ${percent(scorecard.accuracy)} and ${percent(scorecard.corroboration_rate)} of its objects corroborated by other sources. `
        + `Raising the max confidence of its user from ${current} to ${proposed} lets it win upserts against less reliable sources.`,
      payload: { target: 'user', user_id: sourceUser.id, current_max_confidence: current, proposed_max_confidence: proposed },
      evidence: evidenceOf(scorecard),
    });
  }
};

const quarantineRule = (input: RuleInput, proposals: RecommendationProposal[]): boolean => {
  const { source, scorecard, settings, sourceUser, feed } = input;
  if (!scorecard || scorecard.accuracy === null || source.quarantined || scorecard.accuracy >= settings.thresholds.quarantine_accuracy) {
    return false;
  }
  let payload: Record<string, unknown> | null = null;
  if (source.source_kind === SOURCE_KIND_INGESTION_FEED && feed) {
    payload = { target: 'ingestion_feed', feed_id: feed.id, feed_type: feed.entity_type };
  } else if (source.source_kind === SOURCE_KIND_CONNECTOR && sourceUser && sourceUser.service_account && !sourceUser.shared) {
    payload = { target: 'connector_user', user_id: sourceUser.id };
  }
  if (!payload) {
    return false;
  }
  proposals.push({
    kind: RECOMMENDATION_QUARANTINE,
    source_id: source.internal_id,
    fingerprint: recommendationFingerprint(RECOMMENDATION_QUARANTINE, source.internal_id),
    name: `Quarantine ${source.name} into a draft`,
    rationale: `Accuracy of ${percent(scorecard.accuracy)} is below the quarantine threshold of ${percent(settings.thresholds.quarantine_accuracy)}. `
      + 'New data from this source is routed into a draft for review instead of the live knowledge. Nothing already ingested is removed.',
    payload,
    evidence: evidenceOf(scorecard),
  });
  return true;
};

const decayRuleRule = (input: RuleInput, proposals: RecommendationProposal[]) => {
  const { source, scorecard, settings, maxDecayRuleOrder } = input;
  if (!scorecard || scorecard.noise === null || scorecard.noise < settings.thresholds.high_noise || scorecard.volume_indicators <= 0) {
    return;
  }
  const filters = buildSourceIndicatorFilters(source);
  if (!filters) {
    return;
  }
  const lifetime = settings.tuning.noisy_decay_lifetime_days;
  proposals.push({
    kind: RECOMMENDATION_ADD_DECAY_RULE,
    source_id: source.internal_id,
    fingerprint: recommendationFingerprint(RECOMMENDATION_ADD_DECAY_RULE, source.internal_id),
    name: `Add a ${lifetime} days decay rule for ${source.name}`,
    rationale: `${percent(scorecard.noise)} of its objects are noise (never referenced, never sighted or expired). `
      + `A dedicated decay rule makes the indicators it creates from now on expire after ${lifetime} days instead of the default lifetime `
      + '(a decay rule is chosen when an indicator is created).',
    payload: {
      name: `Source Intelligence - ${source.name}`,
      description: `Created by Source Intelligence for the noisy source ${source.name}`,
      decay_lifetime: lifetime,
      decay_pound: 0.5,
      decay_points: [80, 50],
      decay_revoke_score: 20,
      decay_filters: filters,
      order: maxDecayRuleOrder + 1,
    },
    evidence: evidenceOf(scorecard),
  });
};

const denyListRule = (input: RuleInput, proposals: RecommendationProposal[]) => {
  const { source, scorecard, settings } = input;
  if (!scorecard || scorecard.false_positive_count < settings.thresholds.deny_list_min_false_positives) {
    return;
  }
  proposals.push({
    kind: RECOMMENDATION_ADD_DENY_LIST,
    source_id: source.internal_id,
    fingerprint: recommendationFingerprint(RECOMMENDATION_ADD_DENY_LIST, source.internal_id),
    name: `Deny the false positives of ${source.name}`,
    rationale: `${scorecard.false_positive_count} objects of this source are labelled as false positives. `
      + 'An exclusion list built from their values prevents them from being created again as indicators, whatever the source.',
    payload: { max_values: settings.tuning.deny_list_max_values },
    evidence: evidenceOf(scorecard),
  });
};

const retireRule = (input: RuleInput, proposals: RecommendationProposal[]) => {
  const { source, scorecard, settings, peerScorecards, peerNames, connector, feed } = input;
  if (!scorecard || scorecard.volume_total <= 0 || scorecard.unique_contribution > settings.thresholds.retire_max_unique_contribution) {
    return;
  }
  if (source.source_kind !== SOURCE_KIND_CONNECTOR && source.source_kind !== SOURCE_KIND_INGESTION_FEED) {
    return;
  }
  // A feed already stopped has nothing to retire
  if (source.source_kind === SOURCE_KIND_INGESTION_FEED && feed && !feed.ingestion_running) {
    return;
  }
  const ownLead = scorecard.lead_time_hours;
  const redundantWith = scorecard.overlap.find((overlap) => {
    if (overlap.share < settings.thresholds.redundant_overlap) return false;
    const peer = peerScorecards.get(overlap.source_id);
    // The peer must not be slower: the source being retired comes later on the shared objects
    return ownLead === null || ownLead < 0 || (peer?.lead_time_hours !== null && peer?.lead_time_hours !== undefined && peer.lead_time_hours >= ownLead);
  });
  if (!redundantWith) {
    return;
  }
  const target = source.source_kind === SOURCE_KIND_INGESTION_FEED && feed
    ? { target: 'ingestion_feed', feed_id: feed.id, feed_type: feed.entity_type }
    : { target: 'connector', connector_id: connector?.id ?? source.ref_id, managed: connector?.managed ?? false };
  const peerName = peerNames.get(redundantWith.source_id) ?? redundantWith.source_id;
  proposals.push({
    kind: RECOMMENDATION_RETIRE,
    source_id: source.internal_id,
    fingerprint: recommendationFingerprint(RECOMMENDATION_RETIRE, source.internal_id),
    name: `Retire ${source.name}`,
    rationale: `${percent(redundantWith.share)} of its objects are also asserted by ${peerName}, it contributes only ${percent(scorecard.unique_contribution)} unique objects`
      + `${ownLead !== null ? ` and its median lead time is ${ownLead} hours` : ''}. Stopping it keeps the knowledge already ingested.`,
    payload: { ...target, peer_source_id: redundantWith.source_id, overlap_share: redundantWith.share },
    evidence: { ...evidenceOf(scorecard), peer_source_id: redundantWith.source_id, overlap_share: redundantWith.share },
  });
};

const scheduleRule = (input: RuleInput, proposals: RecommendationProposal[]) => {
  const { source, longScorecard, settings, connector, feed } = input;
  if (!longScorecard || longScorecard.volume_total <= 0 || longScorecard.freshness_hours === null) {
    return;
  }
  const staleHours = settings.thresholds.stale_feed_hours;
  if (longScorecard.freshness_hours <= staleHours) {
    return;
  }
  let current: string | null = null;
  let payloadTarget: Record<string, unknown> | null = null;
  if (source.source_kind === SOURCE_KIND_INGESTION_FEED && feed?.scheduling_period && feed.ingestion_running) {
    current = feed.scheduling_period;
    payloadTarget = { target: 'ingestion_feed', feed_id: feed.id, feed_type: feed.entity_type };
  } else if (source.source_kind === SOURCE_KIND_CONNECTOR && connector?.managed && connector.schedule) {
    current = connector.schedule.value;
    payloadTarget = { target: 'connector', connector_id: connector.id, key: connector.schedule.key };
  }
  const currentMs = parseIsoDurationMs(current);
  if (!payloadTarget || currentMs === null) {
    return;
  }
  const proposedMs = Math.max(settings.tuning.min_schedule_minutes * 60000, Math.min(currentMs / 2, (staleHours * HOUR_MS) / 2));
  if (proposedMs >= currentMs) {
    return;
  }
  const proposed = toIsoDuration(proposedMs);
  proposals.push({
    kind: RECOMMENDATION_CHANGE_SCHEDULE,
    source_id: source.internal_id,
    fingerprint: recommendationFingerprint(RECOMMENDATION_CHANGE_SCHEDULE, source.internal_id),
    name: `Run ${source.name} more often`,
    rationale: `No new assertion for ${Math.round(longScorecard.freshness_hours)} hours (threshold ${staleHours} hours) although it produced `
      + `${longScorecard.volume_total} objects over 90 days. Its schedule goes from ${current} to ${proposed}.`,
    payload: { ...payloadTarget, current_value: current, proposed_value: proposed },
    evidence: evidenceOf(longScorecard),
  });
};

/**
 * Deterministic tuning rules for one source. The recommendations only use existing primitives (user confidence, decay
 * rules, exclusion lists, draft routing, connector and feed schedules) and never delete knowledge.
 */
export const evaluateSourceRules = (input: RuleInput): RecommendationProposal[] => {
  const { source, scorecard, settings } = input;
  const proposals: RecommendationProposal[] = [];
  if (!source.enabled) {
    return proposals;
  }
  scheduleRule(input, proposals);
  if (!scorecard || scorecard.volume_total < settings.thresholds.min_volume) {
    return proposals;
  }
  const quarantined = quarantineRule(input, proposals);
  confidenceRules(input, proposals, quarantined);
  decayRuleRule(input, proposals);
  denyListRule(input, proposals);
  retireRule(input, proposals);
  return proposals;
};
