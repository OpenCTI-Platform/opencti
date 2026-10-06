import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import { createEntity, patchAttribute } from '../../database/middleware';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById, type EntityOptions } from '../../database/middleware-loader';
import { elCount, elFindByIds } from '../../database/engine';
import { READ_DATA_INDICES_WITHOUT_INTERNAL_WITHOUT_INFERRED, READ_INDEX_INTERNAL_OBJECTS, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../../database/utils';
import { getEntitiesListFromCache, getEntityFromCache } from '../../database/cache';
import {
  redisCurationAcquireDigestRetry,
  redisCurationAddDigestDelivery,
  redisCurationClearPendingDigest,
  redisCurationGetCounters,
  redisCurationGetDigestDeliveries,
  redisCurationGetPendingDigest,
  redisCurationSetPendingDigest,
} from '../../database/redis';
import { FunctionalError } from '../../config/errors';
import { sendMail, smtpComputeFrom } from '../../database/smtp';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER } from '../../schema/internalObject';
import { isStixObjectAliased, resolveAliasesField } from '../../schema/stixDomainObject';
import { type FilterGroup, FilterMode, FilterOperator, OrderingMode } from '../../generated/graphql';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import { INTERNAL_USERS, SYSTEM_USER } from '../../utils/access';
import { addNotification } from '../notification/notification-domain';
import { ENTITY_TYPE_NOTIFICATION } from '../notification/notification-types';
import type { BasicStoreEntity } from '../../types/store';
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

/** estimateDuplicates over the subjects that still exist: a deleted or merged subject is no longer a duplicate. */
export const estimateExistingDuplicates = (pairs: string[][], existingIds: Set<string>): number => {
  return estimateDuplicates(pairs.map((ids) => ids.filter((id) => existingIds.has(id))));
};

/** Distinct subjects that still exist: a subject named by several proposals counts once, a deleted or merged one not at all. */
export const countExistingSubjects = (subjectIds: string[][], existingIds: Set<string>): number => {
  return new Set(subjectIds.flat().filter((id) => existingIds.has(id))).size;
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
  // A count without types covers every domain object: an empty selection counts nothing.
  const countKnowledge = async (countTypes: string[], filters?: FilterGroup) => {
    if (countTypes.length === 0) return 0;
    return elCount(context, SYSTEM_USER, READ_INDEX_STIX_DOMAIN_OBJECTS, filters ? { types: countTypes, filters } : { types: countTypes });
  };
  const curatedCount = await countKnowledge(types);
  // The staleness detector always examines Indicators: the stale share is measured over the curated types and Indicators.
  const stalenessTypes = R.uniq([...types, ENTITY_TYPE_INDICATOR]);
  const stalenessScopeCount = stalenessTypes.length === types.length ? curatedCount : await countKnowledge(stalenessTypes);
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
  const openStale = await fullEntitiesList<BasicStoreEntityCurationProposal>(context, SYSTEM_USER, [ENTITY_TYPE_CURATION_PROPOSAL], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['proposal_kind'], values: [PROPOSAL_KIND_STALE], operator: FilterOperator.Eq },
        { key: ['proposal_status'], values: [PROPOSAL_STATUS_OPEN], operator: FilterOperator.Eq },
      ],
      filterGroups: [],
    },
    baseData: true,
    baseFields: ['subject_ids'],
    noFiltersChecking: true,
  });
  const openContradictions = await fullEntitiesList<BasicStoreEntityCurationProposal>(context, SYSTEM_USER, [ENTITY_TYPE_CURATION_PROPOSAL], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['proposal_kind'], values: [PROPOSAL_KIND_CONTRADICTION], operator: FilterOperator.Eq },
        { key: ['proposal_status'], values: [PROPOSAL_STATUS_OPEN], operator: FilterOperator.Eq },
      ],
      filterGroups: [],
    },
    baseData: true,
    baseFields: ['subject_ids', 'target_id'],
    noFiltersChecking: true,
  });
  // A contradiction is about its target: the entity, indicator or relationship whose dates or attributions disagree.
  const contradictionTargets = openContradictions.map((proposal) => proposal.target_id ?? proposal.subject_ids[0]);
  // Open proposals outlive their subjects: only the subjects still in the knowledge count.
  const liveIds = R.uniq([...[...openMerges, ...openStale].flatMap((proposal) => proposal.subject_ids), ...contradictionTargets]);
  const existingSubjects = await elFindByIds<BasicStoreEntity>(context, SYSTEM_USER, liveIds, {
    indices: READ_DATA_INDICES_WITHOUT_INTERNAL_WITHOUT_INFERRED,
    baseData: true,
    baseFields: ['internal_id'],
  }) as BasicStoreEntity[];
  const existingSubjectIds = new Set(existingSubjects.map((subject) => subject.internal_id));
  const duplicateEstimate = estimateExistingDuplicates(openMerges.map((proposal) => proposal.subject_ids), existingSubjectIds);
  // Stale entities, not stale proposals: an entity found stale again while its older proposal is still open counts once.
  const staleCount = countExistingSubjects(openStale.map((proposal) => proposal.subject_ids), existingSubjectIds);
  const contradictionCount = contradictionTargets.filter((id) => existingSubjectIds.has(id)).length;
  const [openCount, autoApplied, accepted, rejected, reverted] = await Promise.all([
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
  const updatedCount = await countKnowledge(types, {
    mode: FilterMode.And,
    filters: [{ key: ['updated_at'], values: [new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString()], operator: FilterOperator.Gte }],
    filterGroups: [],
  });
  const curated = Math.max(1, curatedCount);
  return {
    curated_entities_count: curatedCount,
    duplicate_estimate: duplicateEstimate,
    duplicate_rate: duplicateEstimate / curated,
    contradiction_count: contradictionCount,
    stale_count: staleCount,
    stale_share: Math.min(1, staleCount / Math.max(1, stalenessScopeCount)),
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
    `Knowledge health score: ${snapshot.health_score} of 100${trendLabel(snapshot.score_trend)}`,
    `Estimated duplicates: ${metrics.duplicate_estimate} (${(metrics.duplicate_rate * 100).toFixed(1)}% of ${metrics.curated_entities_count} curated entities)`,
    `Open contradictions: ${metrics.contradiction_count}, stale entities: ${metrics.stale_count} (${(metrics.stale_share * 100).toFixed(1)}%)`,
    `Alias coverage: ${(metrics.alias_coverage * 100).toFixed(1)}%, source conflict rate: ${(metrics.source_conflict_rate * 100).toFixed(1)}%`,
    `Open proposals: ${metrics.open_proposals_count}`,
    // The decisions and merges are counted since the previous snapshot; the first snapshot, without trend, counts the last 24 hours.
    `${R.isNil(snapshot.score_trend) ? 'During the last 24 hours' : 'Since the previous snapshot'}: ${metrics.accepted_count} proposals accepted, ${metrics.auto_applied_count} auto-applied, ${metrics.rejected_count} rejected, ${metrics.reverted_count} reverted; ${metrics.merges_count} merges, ${metrics.unmerges_count} unmerges`,
  ];
};

// Quotes are escaped too: the platform URL lands in an attribute.
const escapeHtml = (value: string) => value
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#39;');

const DIGEST_EMAIL_DELIVERY = 'email';

export interface DigestDelivery {
  delivered: number;
  undelivered: number;
  /** The email is still to send: SMTP refused it. */
  emailPending: boolean;
}

const isDigestPending = (delivery: DigestDelivery) => delivery.undelivered > 0 || delivery.emailPending;

type DigestNotification = BasicStoreEntity & {
  user_id: string;
  notification_content?: Array<{ events?: Array<{ instance_id?: string | null }> }>;
};

/**
 * The recipients a digest notification of this snapshot already reached. The notification records its own delivery,
 * so a delivery mark lost after the notification was created never makes a retry notify the recipient again.
 */
const findNotifiedRecipients = async (context: AuthContext, snapshot: BasicStoreEntityKnowledgeHealthSnapshot, recipientIds: string[]) => {
  if (recipientIds.length === 0) return [];
  // A digest notification is created after its snapshot: the older ones are never read.
  const since = snapshot.created_at ? [{ key: ['created_at'], values: [new Date(snapshot.created_at).toISOString()], operator: FilterOperator.Gte }] : [];
  const notifications = await fullEntitiesList<DigestNotification>(context, SYSTEM_USER, [ENTITY_TYPE_NOTIFICATION], {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['user_id'], values: recipientIds }, { key: ['notification_type'], values: ['digest'] }, ...since],
      filterGroups: [],
    },
    noFiltersChecking: true,
  } as EntityOptions<DigestNotification>);
  return notifications
    .filter((notification) => (notification.notification_content ?? [])
      .some((content) => (content.events ?? []).some((event) => event.instance_id === snapshot.internal_id)))
    .map((notification) => notification.user_id);
};

/**
 * Weekly Knowledge Health digest (Community Edition): an in-platform notification for every recipient (users,
 * groups, organizations) and an email when SMTP is configured. Each delivery is remembered for the snapshot: a digest
 * sent again (after a failure, a restart) only reaches the recipients it missed, and a notification is never created
 * twice for a recipient. The email is delivered at least once: SMTP cannot tell whether a message it accepted was
 * remembered, so an email whose delivery mark is lost is sent again with the retry. A recipient whose notification
 * fails is logged, skipped and counted as undelivered, and the email is sent all the same; the digest only fails when
 * neither channel reached anybody.
 */
export const sendKnowledgeHealthDigest = async (
  context: AuthContext,
  settings: CurationSettings,
  snapshot: BasicStoreEntityKnowledgeHealthSnapshot,
): Promise<DigestDelivery> => {
  const recipients = await resolveRecipients(context, settings.digest_recipient_ids);
  if (recipients.length === 0) return { delivered: 0, undelivered: 0, emailPending: false };
  const lines = buildDigestLines(snapshot);
  const title = 'Knowledge health weekly digest';
  const platformSettings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const curationUrl = `${(platformSettings?.platform_url ?? '').replace(/\/$/, '')}/dashboard/data/curation/health`;
  const delivered = new Set(await redisCurationGetDigestDeliveries(snapshot.internal_id));
  const unmarkedIds = recipients.map((recipient) => recipient.id).filter((id) => !delivered.has(id));
  (await findNotifiedRecipients(context, snapshot, unmarkedIds)).forEach((id) => delivered.add(id));
  const failedRecipientIds: string[] = [];
  let newDeliveries = 0;
  for (let index = 0; index < recipients.length; index += 1) {
    const recipient = recipients[index];
    if (delivered.has(recipient.id)) continue;
    try {
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
    } catch (error) {
      failedRecipientIds.push(recipient.id);
      logApp.warn('[CURATION] Knowledge Health digest notification cannot be created', { cause: error, user_id: recipient.id });
      continue;
    }
    delivered.add(recipient.id);
    newDeliveries += 1;
    await redisCurationAddDigestDelivery(snapshot.internal_id, recipient.id);
  }
  const emails = recipients.map((recipient) => recipient.user_email).filter((email) => typeof email === 'string' && email.includes('@'));
  let emailPending = false;
  let emailDelivered = delivered.has(DIGEST_EMAIL_DELIVERY);
  if (emails.length > 0 && !emailDelivered) {
    try {
      const html = `<h2>${title}</h2><ul>${lines.map((line) => `<li>${escapeHtml(line)}</li>`).join('')}</ul>`
        + `<p><a href="${escapeHtml(curationUrl)}">Open Knowledge health</a></p>`;
      await sendMail({ from: await smtpComputeFrom(), to: [], bcc: emails, subject: `[OpenCTI] ${title}`, html }, { category: 'curation_digest' });
      emailDelivered = true;
      newDeliveries += 1;
      await redisCurationAddDigestDelivery(snapshot.internal_id, DIGEST_EMAIL_DELIVERY);
    } catch (error) {
      emailPending = true;
      const message = emailDelivered
        ? '[CURATION] Knowledge Health digest email sent but not recorded, it may be sent again'
        : '[CURATION] Knowledge Health digest email cannot be sent, it will be sent again';
      logApp.warn(message, { cause: error });
    }
  }
  // The recipients the notifications missed stay pending for the retry; only a digest no channel delivered fails.
  if (failedRecipientIds.length === recipients.length && !emailDelivered) {
    throw FunctionalError('The Knowledge Health digest could not be delivered to any recipient', { snapshot_id: snapshot.internal_id });
  }
  if (newDeliveries > 0) {
    await patchAttribute(context, SYSTEM_USER, snapshot.internal_id, ENTITY_TYPE_KNOWLEDGE_HEALTH_SNAPSHOT, { digest_sent_at: now() });
  }
  return { delivered: recipients.length - failedRecipientIds.length, undelivered: failedRecipientIds.length, emailPending };
};

/**
 * The digest of a manager cycle: first the retry of a digest that missed recipients, on the snapshot it was sent for
 * and for those recipients only, then the digest due this week. A digest that misses recipients stays pending until
 * they all have it or its retry window closes. Returns true when the digest due this week was sent.
 */
export const deliverKnowledgeHealthDigest = async (
  context: AuthContext,
  settings: CurationSettings,
  latest: BasicStoreEntityKnowledgeHealthSnapshot | null,
  due: boolean,
): Promise<boolean> => {
  const pendingId = await redisCurationGetPendingDigest();
  if (pendingId) {
    const pending = settings.digest_enabled
      ? await storeLoadById<BasicStoreEntityKnowledgeHealthSnapshot>(context, SYSTEM_USER, pendingId, ENTITY_TYPE_KNOWLEDGE_HEALTH_SNAPSHOT)
      : undefined;
    if (!pending) {
      await redisCurationClearPendingDigest();
    } else {
      if (await redisCurationAcquireDigestRetry()) {
        const retry = await sendKnowledgeHealthDigest(context, settings, pending);
        logApp.info('[CURATION] Knowledge Health weekly digest sent again to the recipients it missed', { snapshot_id: pendingId, ...retry });
        if (!isDigestPending(retry)) await redisCurationClearPendingDigest();
      }
      return false;
    }
  }
  if (!due || !latest) return false;
  const sent = await sendKnowledgeHealthDigest(context, settings, latest);
  logApp.info('[CURATION] Knowledge Health weekly digest sent', { snapshot_id: latest.internal_id, ...sent });
  if (isDigestPending(sent)) await redisCurationSetPendingDigest(latest.internal_id);
  return true;
};
// endregion
