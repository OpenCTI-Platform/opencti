import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import { createEntity, patchAttribute } from '../../database/middleware';
import { fullEntitiesList, pageEntitiesConnection, type EntityOptions } from '../../database/middleware-loader';
import { elCount } from '../../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../../database/utils';
import { getEntitiesListFromCache, getEntityFromCache } from '../../database/cache';
import { redisCurationGetCounters } from '../../database/redis';
import { sendMail, smtpComputeFrom } from '../../database/smtp';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER } from '../../schema/internalObject';
import { isStixObjectAliased, resolveAliasesField } from '../../schema/stixDomainObject';
import { FilterMode, FilterOperator, OrderingMode } from '../../generated/graphql';
import { INTERNAL_USERS, SYSTEM_USER } from '../../utils/access';
import { addNotification } from '../notification/notification-domain';
import { isNotificationRecipientActive } from '../../manager/notificationManager';
import { logApp } from '../../config/conf';
import { now } from '../../utils/format';
import type { BasicStoreSettings } from '../../types/settings';
import {
  type BasicStoreEntityCurationProposal,
  type BasicStoreEntityKnowledgeHealthSnapshot,
  type CurationSettings,
  ENTITY_TYPE_CURATION_PROPOSAL,
  ENTITY_TYPE_KNOWLEDGE_HEALTH_SNAPSHOT,
  ENTITY_TYPE_MERGE_RECORD,
  type KnowledgeHealthComponent,
  type KnowledgeHealthMetrics,
  PROPOSAL_KIND_CONTRADICTION,
  PROPOSAL_KIND_MERGE,
  PROPOSAL_KIND_STALE,
  PROPOSAL_STATUS_ACCEPTED,
  PROPOSAL_STATUS_AUTO_APPLIED,
  PROPOSAL_STATUS_OPEN,
  PROPOSAL_STATUS_REJECTED,
  PROPOSAL_STATUS_REVERTED,
} from './curation-types';

export const SOURCE_CONFLICTS_COUNTER = 'source_conflicts';

// region score (pure)
export const HEALTH_COMPONENT_WEIGHTS = {
  duplicates: 0.3,
  contradictions: 0.2,
  staleness: 0.2,
  alias_coverage: 0.15,
  source_conflicts: 0.15,
};
// Rates at (or above) which a component scores zero.
const DUPLICATE_RATE_FLOOR = 0.1;
const CONTRADICTION_RATE_FLOOR = 0.02;
const SOURCE_CONFLICT_RATE_FLOOR = 0.2;

const component = (name: string, value: number, weight: number, score: number): KnowledgeHealthComponent => ({
  component: name,
  value: Math.round(value * 10000) / 10000,
  weight,
  score: Math.round(Math.min(100, Math.max(0, score)) * 10) / 10,
});

/**
 * Knowledge Health score (0-100): weighted average of five components, each scored from 100 (healthy) to 0.
 */
export const computeHealthScore = (metrics: KnowledgeHealthMetrics): { score: number; breakdown: KnowledgeHealthComponent[] } => {
  const curated = Math.max(1, metrics.curated_entities_count);
  const contradictionRate = metrics.contradiction_count / curated;
  const breakdown = [
    component('duplicates', metrics.duplicate_rate, HEALTH_COMPONENT_WEIGHTS.duplicates, 100 * (1 - Math.min(1, metrics.duplicate_rate / DUPLICATE_RATE_FLOOR))),
    component('contradictions', contradictionRate, HEALTH_COMPONENT_WEIGHTS.contradictions, 100 * (1 - Math.min(1, contradictionRate / CONTRADICTION_RATE_FLOOR))),
    component('staleness', metrics.stale_share, HEALTH_COMPONENT_WEIGHTS.staleness, 100 * (1 - Math.min(1, metrics.stale_share))),
    component('alias_coverage', metrics.alias_coverage, HEALTH_COMPONENT_WEIGHTS.alias_coverage, 100 * Math.min(1, metrics.alias_coverage)),
    component('source_conflicts', metrics.source_conflict_rate, HEALTH_COMPONENT_WEIGHTS.source_conflicts, 100 * (1 - Math.min(1, metrics.source_conflict_rate / SOURCE_CONFLICT_RATE_FLOOR))),
  ];
  const score = Math.round(breakdown.reduce((acc, item) => acc + item.weight * item.score, 0));
  return { score, breakdown };
};

/**
 * Number of entities that would disappear if every open merge proposal were accepted: for each connected component
 * of the duplicate graph, its size minus one.
 */
export const estimateDuplicates = (pairs: string[][]): number => {
  const parent = new Map<string, string>();
  const find = (id: string): string => {
    const current = parent.get(id) ?? id;
    if (current === id) return id;
    const root = find(current);
    parent.set(id, root);
    return root;
  };
  pairs.forEach((ids) => {
    ids.forEach((id) => {
      if (!parent.has(id)) parent.set(id, id);
    });
    for (let index = 1; index < ids.length; index += 1) {
      const left = find(ids[0]);
      const right = find(ids[index]);
      if (left !== right) parent.set(right, left);
    }
  });
  const components = new Set([...parent.keys()].map((id) => find(id)));
  return parent.size - components.size;
};
// endregion

// region metrics
const countProposals = async (context: AuthContext, filters: Array<{ key: string[]; values: string[]; operator?: FilterOperator }>) => {
  return elCount(context, SYSTEM_USER, READ_INDEX_INTERNAL_OBJECTS, {
    types: [ENTITY_TYPE_CURATION_PROPOSAL],
    filters: { mode: FilterMode.And, filters, filterGroups: [] },
    noFiltersChecking: true,
  } as any);
};

const lastDays = (days: number) => R.range(0, days).map((offset) => new Date(Date.now() - offset * 24 * 3600 * 1000).toISOString().slice(0, 10));

export const computeHealthMetrics = async (context: AuthContext, settings: CurationSettings, since: string): Promise<KnowledgeHealthMetrics> => {
  const types = settings.curated_entity_types;
  const curatedCount = await elCount(context, SYSTEM_USER, READ_INDEX_STIX_DOMAIN_OBJECTS, { types });
  const openMerges = await fullEntitiesList<BasicStoreEntityCurationProposal>(context, SYSTEM_USER, [ENTITY_TYPE_CURATION_PROPOSAL], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['proposal_kind'], values: [PROPOSAL_KIND_MERGE], operator: FilterOperator.Eq },
        { key: ['proposal_status'], values: [PROPOSAL_STATUS_OPEN], operator: FilterOperator.Eq },
        { key: ['confidence_score'], values: [String(settings.ambiguous_band_min)], operator: FilterOperator.Gte },
      ],
      filterGroups: [],
    },
    baseData: true,
    baseFields: ['subject_ids'],
    noFiltersChecking: true,
  });
  const duplicateEstimate = estimateDuplicates(openMerges.map((proposal) => proposal.subject_ids));
  const [contradictionCount, staleCount, openCount, autoApplied, accepted, rejected, reverted] = await Promise.all([
    countProposals(context, [{ key: ['proposal_kind'], values: [PROPOSAL_KIND_CONTRADICTION] }, { key: ['proposal_status'], values: [PROPOSAL_STATUS_OPEN] }]),
    countProposals(context, [{ key: ['proposal_kind'], values: [PROPOSAL_KIND_STALE] }, { key: ['proposal_status'], values: [PROPOSAL_STATUS_OPEN] }]),
    countProposals(context, [{ key: ['proposal_status'], values: [PROPOSAL_STATUS_OPEN] }]),
    countProposals(context, [{ key: ['proposal_status'], values: [PROPOSAL_STATUS_AUTO_APPLIED] }, { key: ['decided_at'], values: [since], operator: FilterOperator.Gte }]),
    countProposals(context, [{ key: ['proposal_status'], values: [PROPOSAL_STATUS_ACCEPTED] }, { key: ['decided_at'], values: [since], operator: FilterOperator.Gte }]),
    countProposals(context, [{ key: ['proposal_status'], values: [PROPOSAL_STATUS_REJECTED] }, { key: ['decided_at'], values: [since], operator: FilterOperator.Gte }]),
    countProposals(context, [{ key: ['proposal_status'], values: [PROPOSAL_STATUS_REVERTED] }, { key: ['updated_at'], values: [since], operator: FilterOperator.Gte }]),
  ]);
  const [mergesCount, unmergesCount] = await Promise.all([
    elCount(context, SYSTEM_USER, READ_INDEX_INTERNAL_OBJECTS, {
      types: [ENTITY_TYPE_MERGE_RECORD],
      filters: { mode: FilterMode.And, filters: [{ key: ['created_at'], values: [since], operator: FilterOperator.Gte }], filterGroups: [] },
    }),
    elCount(context, SYSTEM_USER, READ_INDEX_INTERNAL_OBJECTS, {
      types: [ENTITY_TYPE_MERGE_RECORD],
      filters: { mode: FilterMode.And, filters: [{ key: ['unmerged_at'], values: [since], operator: FilterOperator.Gte }], filterGroups: [] },
    }),
  ]);
  // Alias coverage over aliased curated types, grouped by their alias attribute.
  const aliasedTypes = types.filter((type) => isStixObjectAliased(type));
  const byAliasField = R.groupBy((type: string) => resolveAliasesField(type).name, aliasedTypes);
  let aliasedTotal = 0;
  let aliasedWithAliases = 0;
  const groups = Object.entries(byAliasField) as Array<[string, string[]]>;
  for (let index = 0; index < groups.length; index += 1) {
    const [field, groupTypes] = groups[index];
    aliasedTotal += await elCount(context, SYSTEM_USER, READ_INDEX_STIX_DOMAIN_OBJECTS, { types: groupTypes });
    aliasedWithAliases += await elCount(context, SYSTEM_USER, READ_INDEX_STIX_DOMAIN_OBJECTS, {
      types: groupTypes,
      filters: { mode: FilterMode.And, filters: [{ key: [field], values: [], operator: FilterOperator.NotNil }], filterGroups: [] },
    });
  }
  // Source conflicts: fields overwritten by another source within the tracking window, over updated curated entities.
  const conflicts = (await redisCurationGetCounters(SOURCE_CONFLICTS_COUNTER, lastDays(7))).reduce((acc, value) => acc + value, 0);
  const updatedCount = await elCount(context, SYSTEM_USER, READ_INDEX_STIX_DOMAIN_OBJECTS, {
    types,
    filters: { mode: FilterMode.And, filters: [{ key: ['updated_at'], values: [new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString()], operator: FilterOperator.Gte }], filterGroups: [] },
  });
  const curated = Math.max(1, curatedCount);
  return {
    curated_entities_count: curatedCount,
    duplicate_estimate: duplicateEstimate,
    duplicate_rate: duplicateEstimate / curated,
    contradiction_count: contradictionCount,
    stale_count: staleCount,
    stale_share: Math.min(1, staleCount / curated),
    alias_coverage: aliasedTotal > 0 ? aliasedWithAliases / aliasedTotal : 1,
    source_conflict_rate: updatedCount > 0 ? Math.min(1, conflicts / updatedCount) : 0,
    open_proposals_count: openCount,
    auto_applied_count: autoApplied,
    accepted_count: accepted,
    rejected_count: rejected,
    reverted_count: reverted,
    merges_count: mergesCount,
    unmerges_count: unmergesCount,
  };
};
// endregion

// region snapshots
export const findLatestHealthSnapshot = async (context: AuthContext, user: AuthUser) => {
  const page = await pageEntitiesConnection<BasicStoreEntityKnowledgeHealthSnapshot>(context, user, [ENTITY_TYPE_KNOWLEDGE_HEALTH_SNAPSHOT], {
    first: 1,
    orderBy: 'snapshot_date',
    orderMode: OrderingMode.Desc,
  });
  return page.edges[0]?.node ?? null;
};

export const findHealthSnapshotsPaginated = async (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityKnowledgeHealthSnapshot>) => {
  return pageEntitiesConnection<BasicStoreEntityKnowledgeHealthSnapshot>(context, user, [ENTITY_TYPE_KNOWLEDGE_HEALTH_SNAPSHOT], {
    orderBy: 'snapshot_date',
    orderMode: OrderingMode.Desc,
    ...opts,
  });
};

export const createHealthSnapshot = async (context: AuthContext, settings: CurationSettings): Promise<BasicStoreEntityKnowledgeHealthSnapshot> => {
  const previous = await findLatestHealthSnapshot(context, SYSTEM_USER);
  const since = previous?.snapshot_date ?? new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  const metrics = await computeHealthMetrics(context, settings, since);
  const { score, breakdown } = computeHealthScore(metrics);
  const snapshot = {
    snapshot_date: now(),
    health_score: score,
    score_trend: previous ? score - previous.health_score : null,
    health_metrics: metrics,
    score_breakdown: breakdown,
  };
  return await createEntity(context, SYSTEM_USER, snapshot, ENTITY_TYPE_KNOWLEDGE_HEALTH_SNAPSHOT) as unknown as BasicStoreEntityKnowledgeHealthSnapshot;
};
// endregion

// region weekly digest
const resolveRecipients = async (context: AuthContext, memberIds: string[]): Promise<AuthUser[]> => {
  if (memberIds.length === 0) return [];
  const users = (await getEntitiesListFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER)).filter(isNotificationRecipientActive);
  const selected = users.filter((user) => memberIds.includes(user.id)
    || user.groups.some((group) => memberIds.includes(group.internal_id))
    || user.organizations.some((organization) => memberIds.includes(organization.internal_id)));
  return R.uniqBy((user) => user.id, selected).filter((user) => INTERNAL_USERS[user.id] === undefined);
};

const trendLabel = (trend: number | null | undefined) => {
  if (trend === null || trend === undefined) return '';
  return trend >= 0 ? ` (+${trend})` : ` (${trend})`;
};

export const buildDigestLines = (snapshot: BasicStoreEntityKnowledgeHealthSnapshot): string[] => {
  const metrics = snapshot.health_metrics;
  return [
    `Knowledge health score: ${snapshot.health_score}/100${trendLabel(snapshot.score_trend)}`,
    `Estimated duplicates: ${metrics.duplicate_estimate} (${(metrics.duplicate_rate * 100).toFixed(1)}% of ${metrics.curated_entities_count} curated entities)`,
    `Open contradictions: ${metrics.contradiction_count}, stale entities: ${metrics.stale_count} (${(metrics.stale_share * 100).toFixed(1)}%)`,
    `Alias coverage: ${(metrics.alias_coverage * 100).toFixed(1)}%, source conflict rate: ${(metrics.source_conflict_rate * 100).toFixed(1)}%`,
    `Open proposals: ${metrics.open_proposals_count} - accepted ${metrics.accepted_count}, auto-applied ${metrics.auto_applied_count}, rejected ${metrics.rejected_count}, reverted ${metrics.reverted_count}`,
    `Merges: ${metrics.merges_count}, unmerges: ${metrics.unmerges_count}`,
  ];
};

// Quotes are escaped too: the platform URL lands in an attribute.
const escapeHtml = (value: string) => value
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#39;');

/**
 * Weekly Knowledge Health digest (Community Edition): an in-platform notification for every recipient (users,
 * groups, organizations) and an email when SMTP is configured.
 */
export const sendKnowledgeHealthDigest = async (context: AuthContext, settings: CurationSettings, snapshot: BasicStoreEntityKnowledgeHealthSnapshot) => {
  const recipients = await resolveRecipients(context, settings.digest_recipient_ids);
  if (recipients.length === 0) return 0;
  const lines = buildDigestLines(snapshot);
  const title = 'Knowledge health weekly digest';
  const platformSettings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const curationUrl = `${(platformSettings?.platform_url ?? '').replace(/\/$/, '')}/dashboard/data/curation/health`;
  for (let index = 0; index < recipients.length; index += 1) {
    const recipient = recipients[index];
    await addNotification(context, SYSTEM_USER, {
      is_read: false,
      name: title,
      notification_type: 'digest',
      user_id: recipient.id,
      created: now(),
      created_at: now(),
      updated_at: now(),
      notification_content: [{
        title,
        events: lines.map((message) => ({ operation: 'update', message, instance_id: snapshot.internal_id, entity_type: ENTITY_TYPE_KNOWLEDGE_HEALTH_SNAPSHOT })),
      }],
    });
  }
  const emails = recipients.map((recipient) => recipient.user_email).filter((email) => typeof email === 'string' && email.includes('@'));
  if (emails.length > 0) {
    try {
      const html = `<h2>${title}</h2><ul>${lines.map((line) => `<li>${escapeHtml(line)}</li>`).join('')}</ul>`
        + `<p><a href="${escapeHtml(curationUrl)}">Open Knowledge health</a></p>`;
      await sendMail({ from: await smtpComputeFrom(), to: [], bcc: emails, subject: `[OpenCTI] ${title}`, html }, { category: 'curation_digest' });
    } catch (error) {
      logApp.warn('[CURATION] Knowledge Health digest email cannot be sent', { cause: error });
    }
  }
  await patchAttribute(context, SYSTEM_USER, snapshot.internal_id, ENTITY_TYPE_KNOWLEDGE_HEALTH_SNAPSHOT, { digest_sent_at: now() });
  return recipients.length;
};
// endregion
