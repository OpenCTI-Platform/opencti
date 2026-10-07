import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import { createEntity, deleteElementById, patchAttribute } from '../../database/middleware';
import { fullEntitiesList, internalFindByIds, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { getEntitiesListFromCache, getEntitiesMapFromCache } from '../../database/cache';
import { elRawSearch, elUpdate } from '../../database/engine';
import {
  READ_INDEX_STIX_CORE_RELATIONSHIPS,
  READ_INDEX_STIX_CYBER_OBSERVABLES,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_INDEX_STIX_SIGHTING_RELATIONSHIPS,
} from '../../database/utils';
import { notify, publishCacheResetEvent, redisGetSourceIntelligenceState, redisPatchSourceIntelligenceState } from '../../database/redis';
import { isModuleActivated } from '../../database/cluster-module';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { DatabaseError, ForbiddenAccess, FunctionalError, LockTimeoutError, TYPE_LOCK_ERROR } from '../../config/errors';
import { lockResources } from '../../lock/master-lock';
import { publishUserAction } from '../../listener/UserActionListener';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';
import { INTERNAL_USERS, isUserHasCapability, SOURCE_INTELLIGENCE_MANAGER_USER, SYSTEM_USER } from '../../utils/access';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_USER } from '../../schema/internalObject';
import { connectorIdFromIngestId } from '../../domain/connector';
import { ConnectorType, type EditInput, type FilterGroup, FilterMode, FilterOperator } from '../../generated/graphql';
import { addFilter, extractFilterKeys } from '../../utils/filtering/filtering-utils';
import { generateStandardId } from '../../schema/identifier';
import {
  ENTITY_TYPE_INGESTION_CSV,
  ENTITY_TYPE_INGESTION_JSON,
  ENTITY_TYPE_INGESTION_RSS,
  ENTITY_TYPE_INGESTION_TAXII,
  ENTITY_TYPE_INGESTION_TAXII_COLLECTION,
} from '../ingestion/ingestion-types';
import type { BasicStoreEntityConnector } from '../../types/connector';
import type { BasicStoreEntityManagerConfiguration } from '../managerConfiguration/managerConfiguration-types';
import { ENTITY_TYPE_MANAGER_CONFIGURATION } from '../managerConfiguration/managerConfiguration-types';
import { getManagerConfigurationFromCache } from '../managerConfiguration/managerConfiguration-domain';
import {
  DEFAULT_SOURCE_INTELLIGENCE_SETTINGS,
  missingAutonomyCapabilities,
  resolveSourceIntelligenceSettings,
  type SourceIntelligenceSettings,
  validateSourceIntelligenceSettingsInput,
} from './sourceIntelligence-settings';
import {
  ACTIVE_RECOMMENDATION_STATUSES,
  type BasicStoreEntitySource,
  type BasicStoreEntitySourceRecommendation,
  ENTITY_TYPE_SOURCE,
  ENTITY_TYPE_SOURCE_RECOMMENDATION,
  RECOMMENDATION_QUARANTINE,
  RECOMMENDATION_STATUS_APPLIED,
  RECOMMENDATION_STATUS_APPLYING,
  RECOMMENDATION_STATUS_DISMISSED,
  RECOMMENDATION_STATUS_FAILED,
  RECOMMENDATION_STATUS_PROPOSED,
  RECOMMENDATION_STATUS_REVERTING,
  REFERENCE_SCORECARD_PERIOD,
  SCORECARD_PERIOD_DAYS,
  SCORECARD_PERIODS,
  type ScorecardPeriodValue,
  SOURCE_COST_PERIODS,
  SOURCE_INTELLIGENCE_MANAGER_ID,
  SOURCE_KIND_AUTHOR,
  SOURCE_KIND_CONNECTOR,
  SOURCE_KIND_INGESTION_FEED,
  SOURCE_KIND_MANUAL,
  type SourceCost,
  type SourceKindValue,
  type StoreSourceScorecard,
} from './sourceIntelligence-types';
import {
  applyLiveScorecardCost,
  countScoredSources,
  deleteLiveScorecardsOfSources,
  deleteScorecardsOfSources,
  findLiveScorecards,
  moveScorecardSnapshots,
  searchScorecards,
} from './sourceIntelligence-store';
import { computeCostPerActionable, normalizeCostToDays, toSnapshotDate } from './sourceIntelligence-scoring';
import { quarantinedConnectorUserId, releaseQuarantine } from './sourceIntelligence-quarantine';

const DAY_MS = 24 * 3600 * 1000;
const RESTRICTED_AUTHOR_NAME = 'Restricted';

// Activity records are read without the masking of restricted authors: an author source is named there by its id only
export const sourceAuditName = (id: string, source: Pick<BasicStoreEntitySource, 'name' | 'source_kind'> | undefined) => {
  return !source || source.source_kind === SOURCE_KIND_AUTHOR ? `source \`${id}\`` : `source \`${source.name}\``;
};
// The activity log has its own access: what the page of a restricted author withholds (cost, description, tags, owner)
// is left out of the activity of every author source
export const sourceCostActivity = (id: string, source: Pick<BasicStoreEntitySource, 'name' | 'source_kind'> | undefined, cost: SourceCost | null) => {
  const name = sourceAuditName(id, source);
  if (!cost) {
    return { message: `clears the cost of ${name}`, input: { source_cost: null } };
  }
  if (!source || source.source_kind === SOURCE_KIND_AUTHOR) {
    return { message: `sets the cost of ${name}`, input: {} };
  }
  return { message: `sets the cost of ${name} to ${cost.amount} ${cost.currency} per ${cost.period}`, input: { source_cost: cost } };
};
export const sourceEditActivityInput = (source: Pick<BasicStoreEntitySource, 'source_kind'>, patch: Record<string, unknown>) => {
  if (source.source_kind !== SOURCE_KIND_AUTHOR) {
    return patch;
  }
  return 'enabled' in patch ? { enabled: patch.enabled } : {};
};
const INGESTION_FEED_TYPES = [
  ENTITY_TYPE_INGESTION_RSS,
  ENTITY_TYPE_INGESTION_TAXII,
  ENTITY_TYPE_INGESTION_TAXII_COLLECTION,
  ENTITY_TYPE_INGESTION_CSV,
  ENTITY_TYPE_INGESTION_JSON,
];
// Connectors that never write knowledge are not intelligence sources
const NON_PRODUCING_CONNECTOR_TYPES: string[] = [ConnectorType.InternalExportFile];
type ConnectorWithOrigin = BasicStoreEntityConnector & { built_in?: boolean };

// region settings and state
export interface SourceIntelligenceState {
  last_full_run_day?: string | null;
  last_full_run_start?: string | null;
  last_full_run_end?: string | null;
  last_run_success?: boolean | null;
  last_run_message?: string | null;
  last_scanned_objects?: number | null;
  last_scan_truncated?: boolean | null;
  // JSON ScanTrace of the last full computation, read by the live accounting of deletions
  last_scan_trace?: string | null;
  // Set while a full computation writes the live scorecards, cleared with the trace that matches them: until then the
  // stream waits, and the full computation is run again
  live_rebuild_pending?: boolean | null;
  backfill_next_day?: string | null;
  backfill_done?: boolean | null;
  // Planned range of the history backfill: first day, and day before which the days are already covered
  backfill_from_day?: string | null;
  backfill_until_day?: string | null;
  // Last historical day whose scan reached `max_scan_objects`, and the limit it reached
  backfill_truncated_day?: string | null;
  backfill_truncated_limit?: number | null;
  recompute_requested_at?: string | null;
  gaps_last_run_end?: string | null;
  recommendations_last_run_end?: string | null;
}

export const getSourceIntelligenceState = async (): Promise<SourceIntelligenceState> => {
  return (await redisGetSourceIntelligenceState() ?? {}) as SourceIntelligenceState;
};

export const updateSourceIntelligenceState = async (patch: Partial<SourceIntelligenceState>) => {
  await redisPatchSourceIntelligenceState(patch as Record<string, unknown>);
  return getSourceIntelligenceState();
};

export const getSourceIntelligenceManagerConfiguration = async (context: AuthContext) => {
  return getManagerConfigurationFromCache(context, SYSTEM_USER, SOURCE_INTELLIGENCE_MANAGER_ID);
};

export const getSourceIntelligenceSettings = async (context: AuthContext): Promise<SourceIntelligenceSettings> => {
  const configuration = await getSourceIntelligenceManagerConfiguration(context);
  return resolveSourceIntelligenceSettings(configuration?.manager_setting ?? DEFAULT_SOURCE_INTELLIGENCE_SETTINGS);
};

/** The setting of the platform, saved from the settings page: the manager computes only when its deployment enables it. */
export const isSourceIntelligenceRunning = async (context: AuthContext) => {
  const configuration = await getSourceIntelligenceManagerConfiguration(context);
  return configuration?.manager_running !== false;
};

/** Whether the deployment configuration enables the manager on at least one node of the cluster. */
export const isSourceIntelligenceEnabled = async () => {
  return isModuleActivated(SOURCE_INTELLIGENCE_MANAGER_ID);
};

export const editSourceIntelligenceSettings = async (context: AuthContext, user: AuthUser, input: Record<string, any>) => {
  const configuration = await getSourceIntelligenceManagerConfiguration(context);
  if (!configuration) {
    throw FunctionalError('Source intelligence manager configuration not found');
  }
  const { manager_running, ...settingsInput } = input;
  const current = resolveSourceIntelligenceSettings(configuration.manager_setting);
  if (settingsInput.autonomy?.auto_apply_kinds && settingsInput.autonomy.auto_apply_kinds.length > 0 && !(await isEnterpriseEdition(context))) {
    throw ForbiddenAccess('The autonomy policy requires the Enterprise Edition');
  }
  const settings = validateSourceIntelligenceSettingsInput(current, settingsInput);
  // The policy applies its kinds without the capability checks of a manual application
  const missingCapabilities = missingAutonomyCapabilities(user, current.autonomy.auto_apply_kinds, settings.autonomy.auto_apply_kinds);
  if (missingCapabilities.length > 0) {
    throw ForbiddenAccess('Allowing these recommendation kinds in the autonomy policy requires the capabilities of their manual application', {
      capabilities: missingCapabilities,
    });
  }
  const patch: Record<string, unknown> = { manager_setting: settings };
  if (typeof manager_running === 'boolean') {
    patch.manager_running = manager_running;
  }
  const { element } = await patchAttribute(context, user, configuration.id, ENTITY_TYPE_MANAGER_CONFIGURATION, patch);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: 'updates `source intelligence settings`',
    context_data: { id: configuration.id, entity_type: ENTITY_TYPE_MANAGER_CONFIGURATION, input: patch },
  });
  await notify(BUS_TOPICS[ENTITY_TYPE_MANAGER_CONFIGURATION].EDIT_TOPIC, element, user);
  return {
    ...settings,
    manager_running: (element as unknown as BasicStoreEntityManagerConfiguration).manager_running !== false,
    manager_enabled: await isSourceIntelligenceEnabled(),
  };
};

export const requestSourceIntelligenceRecompute = async (context: AuthContext, user: AuthUser) => {
  if (!(await isSourceIntelligenceEnabled())) {
    throw FunctionalError('The source intelligence manager is disabled in the platform configuration');
  }
  const requestedAt = new Date().toISOString();
  await updateSourceIntelligenceState({ recompute_requested_at: requestedAt });
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: 'requests a `source intelligence` recomputation',
    context_data: { id: SOURCE_INTELLIGENCE_MANAGER_ID, entity_type: ENTITY_TYPE_MANAGER_CONFIGURATION, input: { requested_at: requestedAt } },
  });
  return true;
};
// endregion

// region sources access
// Identities among the given ones that the user can access: an identity that cannot be read any more is not part of it
const accessibleIdentityIds = async (context: AuthContext, user: AuthUser, identityIds: string[]) => {
  const ids = Array.from(new Set(identityIds.filter((id) => !!id)));
  if (ids.length === 0) {
    return new Set<string>();
  }
  const accessible = await internalFindByIds(context, user, ids, { baseData: true, baseFields: ['internal_id'] }) as unknown as BasicStoreEntity[];
  return new Set(accessible.map((element) => element.internal_id));
};

const sourceVisibleIds = async (context: AuthContext, user: AuthUser, sources: BasicStoreEntitySource[]) => {
  // Author sources reference identities that can be restricted by markings or organizations: for users who cannot
  // access the identity, the source is count-only (see sourceRestrictions)
  return accessibleIdentityIds(context, user, sources.filter((s) => s.source_kind === SOURCE_KIND_AUTHOR).map((s) => s.ref_id));
};

const CLEARED_LATEST_KPIS = {
  last_computed_at: null,
  latest_value_score: null,
  latest_volume: null,
  latest_unique_contribution: null,
  latest_corroboration_rate: null,
  latest_lead_time_hours: null,
  latest_accuracy: null,
  latest_relevance: null,
  latest_impact_score: null,
  latest_noise: null,
  latest_freshness_hours: null,
  latest_cost_per_actionable: null,
  latest_community_uniqueness: null,
};

/**
 * A source reached by its id whose author the user cannot access: named Restricted, with none of the fields it records
 * about the author (identity, users, metrics, cost, tags, owner); only its kind and its state stay.
 */
export const maskRestrictedSources = async <T extends BasicStoreEntitySource>(context: AuthContext, user: AuthUser, sources: T[]): Promise<T[]> => {
  const accessibleAuthors = await sourceVisibleIds(context, user, sources);
  return sources.map((source) => {
    if (source.source_kind === SOURCE_KIND_AUTHOR && !accessibleAuthors.has(source.ref_id)) {
      return {
        ...source,
        ...CLEARED_LATEST_KPIS,
        name: RESTRICTED_AUTHOR_NAME,
        description: undefined,
        ref_id: '',
        ref_type: undefined,
        source_user_ids: [],
        source_cost: null,
        tags: [],
        owner_id: null,
      };
    }
    return source;
  });
};

type SourceRestrictions = {
  restrictedIds: string[];
  isRestricted: (sourceId: string, sourceKind?: string | null) => boolean;
};

// One resolution per request and user: the gaps, scorecards and overlap entries of a request share it
const sourceRestrictionsByContext = new WeakMap<AuthContext, Map<string, Promise<SourceRestrictions>>>();

/**
 * Whether a source is count-only for the user: an author source whose identity the user cannot access, or an author
 * source that no longer exists and cannot be checked. Such a source is left out of every list, scorecard, overlap,
 * coverage and widget the user reads, so no metric, sort or aggregation tells what it wrote; the number of sources
 * of the status still counts it. The author sources are bounded by the discovery settings.
 */
export const sourceRestrictions = (context: AuthContext, user: AuthUser): Promise<SourceRestrictions> => {
  let memo = sourceRestrictionsByContext.get(context);
  if (!memo) {
    memo = new Map();
    sourceRestrictionsByContext.set(context, memo);
  }
  let resolution = memo.get(user.id);
  if (!resolution) {
    resolution = (async () => {
      const authors = await fullEntitiesList<BasicStoreEntitySource>(context, SYSTEM_USER, [ENTITY_TYPE_SOURCE], {
        filters: { mode: FilterMode.And, filters: [{ key: ['source_kind'], values: [SOURCE_KIND_AUTHOR], operator: FilterOperator.Eq, mode: FilterMode.Or }], filterGroups: [] },
      });
      const accessible = await sourceVisibleIds(context, user, authors);
      const authorIds = new Set(authors.map((source) => source.internal_id));
      const restrictedIds = authors.filter((source) => !accessible.has(source.ref_id)).map((source) => source.internal_id);
      const restricted = new Set(restrictedIds);
      return {
        restrictedIds,
        isRestricted: (sourceId: string, sourceKind?: string | null) => restricted.has(sourceId) || (sourceKind === SOURCE_KIND_AUTHOR && !authorIds.has(sourceId)),
      };
    })();
    memo.set(user.id, resolution);
  }
  return resolution;
};

/** Sources the user reads in full: the author sources it cannot access are left out. */
export const withoutRestrictedSources = async <T extends BasicStoreEntitySource>(context: AuthContext, user: AuthUser, sources: T[]): Promise<T[]> => {
  const accessibleAuthors = await sourceVisibleIds(context, user, sources);
  return sources.filter((source) => source.source_kind !== SOURCE_KIND_AUTHOR || accessibleAuthors.has(source.ref_id));
};

/** Entries naming a source (overlap shares, gap coverage) without those naming a source that is count-only for the user. */
export const withoutRestrictedSourceEntries = async <T extends { source_id: string }>(context: AuthContext, user: AuthUser, entries: T[]): Promise<T[]> => {
  if (entries.length === 0) {
    return entries;
  }
  const { isRestricted } = await sourceRestrictions(context, user);
  return entries.filter((entry) => !isRestricted(entry.source_id));
};

// One resolution per request and recommendation: the masked fields of a recommendation share it
const restrictedNamesByContext = new WeakMap<AuthContext, Map<string, Promise<string[]>>>();

export const parseJsonRecord = (value: string | null | undefined): Record<string, unknown> => {
  try {
    const parsed = value ? JSON.parse(value) : {};
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
};

interface RecommendationTexts {
  source_id?: string | null;
  payload?: string | null;
  named_authors?: string | null;
}

interface NamedAuthor {
  ref_id: string;
  name: string;
}

const parseNamedAuthors = (value: string | null | undefined): NamedAuthor[] => {
  try {
    const parsed = value ? JSON.parse(value) : [];
    return Array.isArray(parsed)
      ? parsed.filter((author) => author && typeof author.ref_id === 'string' && typeof author.name === 'string' && author.name.length > 0)
      : [];
  } catch {
    return [];
  }
};

/**
 * Author sources a recommendation names in its texts (its source, and the peer source of a redundancy): the ones it
 * recorded when its texts were written, and its sources as they are now (the given ones first, then the cache).
 */
const namedAuthorsOf = async (context: AuthContext, recommendation: RecommendationTexts, knownSources: BasicStoreEntitySource[] = []) => {
  const peerSourceId = parseJsonRecord(recommendation.payload).peer_source_id;
  const sourceIds = [recommendation.source_id, typeof peerSourceId === 'string' ? peerSourceId : null].filter((id): id is string => !!id);
  const sourcesById = sourceIds.length > 0
    ? await getEntitiesMapFromCache<BasicStoreEntitySource>(context, SYSTEM_USER, ENTITY_TYPE_SOURCE)
    : new Map<string, BasicStoreEntitySource>();
  const known = new Map(knownSources.map((source) => [source.internal_id, source]));
  const current = sourceIds
    .map((id) => known.get(id) ?? sourcesById.get(id))
    .filter((source): source is BasicStoreEntitySource => source !== undefined && source.source_kind === SOURCE_KIND_AUTHOR && !!source.name)
    .map((source) => ({ ref_id: source.ref_id, name: source.name }));
  const named = new Map<string, NamedAuthor>();
  [...parseNamedAuthors(recommendation.named_authors), ...current].forEach((author) => {
    named.set(JSON.stringify([author.ref_id, author.name]), author);
  });
  return Array.from(named.values());
};

/**
 * Value of `named_authors` to store with texts written now: the authors already recorded plus the current names of the
 * recommendation's author sources, so a later rename or removal of the source never unmasks a name the texts kept.
 */
export const recordNamedAuthors = async (context: AuthContext, recommendation: RecommendationTexts, knownSources: BasicStoreEntitySource[] = []) => {
  return JSON.stringify(await namedAuthorsOf(context, recommendation, knownSources));
};

/**
 * Names a recommendation's texts may quote for authors the user cannot access: every name recorded when the texts were
 * written and the current names of its author sources. Access is checked on the author identity itself, so a renamed or
 * removed source stays masked, and an identity that cannot be read any more keeps its names masked.
 */
export const restrictedRecommendationNames = (
  context: AuthContext,
  user: AuthUser,
  recommendation: RecommendationTexts & { internal_id: string },
): Promise<string[]> => {
  let memo = restrictedNamesByContext.get(context);
  if (!memo) {
    memo = new Map();
    restrictedNamesByContext.set(context, memo);
  }
  const cached = memo.get(recommendation.internal_id);
  if (cached) {
    return cached;
  }
  const resolution = (async () => {
    const authors = await namedAuthorsOf(context, recommendation);
    if (authors.length === 0) {
      return [];
    }
    const accessible = await accessibleIdentityIds(context, user, authors.map((author) => author.ref_id));
    return Array.from(new Set(authors.filter((author) => !accessible.has(author.ref_id)).map((author) => author.name)));
  })();
  memo.set(recommendation.internal_id, resolution);
  return resolution;
};

const escapeRegExp = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export const maskRestrictedNames = (text: string | null | undefined, names: string[]): string | null | undefined => {
  const maskedNames = names.filter((name) => name.length > 0);
  if (!text || maskedNames.length === 0) {
    return text;
  }
  // Whatever its case (free texts such as a dismiss reason are typed by users), and longest first: a name containing
  // another one (a former name extended by a rename) is masked whole
  const pattern = new RegExp([...maskedNames].sort((a, b) => b.length - a.length).map(escapeRegExp).join('|'), 'gi');
  return text.replace(pattern, RESTRICTED_AUTHOR_NAME);
};

const maskJsonValue = (value: unknown, names: string[]): unknown => {
  if (typeof value === 'string') return maskRestrictedNames(value, names);
  if (Array.isArray(value)) return value.map((item) => maskJsonValue(item, names));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, maskJsonValue(item, names)]));
  }
  return value;
};

/** JSON text (payload, evidence) with the restricted names masked in every string value. */
export const maskRestrictedNamesInJson = (json: string | null | undefined, names: string[]): string | null | undefined => {
  if (!json || names.length === 0) {
    return json;
  }
  try {
    return JSON.stringify(maskJsonValue(JSON.parse(json), names));
  } catch {
    return maskRestrictedNames(json, names);
  }
};

/**
 * Scorecards the user reads: those of a source that is count-only for the user are left out, and so are the overlap
 * entries naming one, whatever query returns them.
 */
export const withoutRestrictedScorecards = async <T extends Pick<StoreSourceScorecard, 'source_id' | 'source_kind' | 'overlap'>>(
  context: AuthContext,
  user: AuthUser,
  scorecards: T[],
): Promise<T[]> => {
  if (scorecards.length === 0) {
    return scorecards;
  }
  const { isRestricted } = await sourceRestrictions(context, user);
  return scorecards
    .filter((scorecard) => !isRestricted(scorecard.source_id, scorecard.source_kind))
    .map((scorecard) => ({ ...scorecard, overlap: (scorecard.overlap ?? []).filter((share) => !isRestricted(share.source_id)) }));
};

// The capabilities every Sources query requires
export const canReadSourceIntelligence = (user: AuthUser) => isUserHasCapability(user, 'MODULES') || isUserHasCapability(user, 'INGESTION');

/**
 * Sources and scorecards read through a generic lookup by id (filter representatives), as the Sources queries serve
 * them: none without the Sources capabilities, a source whose author the user cannot access named Restricted, and no
 * scorecard of such a source.
 */
export const readableSourcesAndScorecards = async (context: AuthContext, user: AuthUser, entities: BasicStoreEntity[]): Promise<Array<BasicStoreEntity | undefined>> => {
  if (!canReadSourceIntelligence(user)) {
    return entities.map(() => undefined);
  }
  const { isRestricted } = await sourceRestrictions(context, user);
  return Promise.all(entities.map(async (entity) => {
    if (entity.entity_type === ENTITY_TYPE_SOURCE) {
      const [source] = await maskRestrictedSources(context, user, [entity as unknown as BasicStoreEntitySource]);
      return source as unknown as BasicStoreEntity;
    }
    const scorecard = entity as unknown as StoreSourceScorecard;
    return isRestricted(scorecard.source_id, scorecard.source_kind) ? undefined : entity;
  }));
};

export const findSourceById = async (context: AuthContext, user: AuthUser, id: string) => {
  const source = await storeLoadById<BasicStoreEntitySource>(context, user, id, ENTITY_TYPE_SOURCE);
  if (!source) {
    return source;
  }
  const [masked] = await maskRestrictedSources(context, user, [source]);
  return masked;
};

// PIR relevance is an Enterprise Edition measure: what a computation stored before a license downgrade is never served
const ENTERPRISE_SOURCE_KPIS = ['latest_relevance'];

/**
 * Outside Enterprise Edition, sources are neither filtered nor sorted on an Enterprise Edition KPI: the values kept
 * from an earlier computation would be inferred from the results. A sort on it falls back to the default order.
 */
export const restrictSourceQueryToEdition = async <T extends { orderBy?: string | null; filters?: FilterGroup | null }>(context: AuthContext, args: T): Promise<T> => {
  if (await isEnterpriseEdition(context)) {
    return args;
  }
  if (args.filters && extractFilterKeys(args.filters).some((key) => ENTERPRISE_SOURCE_KPIS.includes(key))) {
    throw FunctionalError('Filtering sources on their relevance requires an Enterprise Edition license');
  }
  return args.orderBy && ENTERPRISE_SOURCE_KPIS.includes(args.orderBy) ? { ...args, orderBy: null } : args;
};

export const findSourcesPaginated = async (context: AuthContext, user: AuthUser, args: Record<string, any>) => {
  const allowed = await restrictSourceQueryToEdition(context, args);
  // Left out by the query itself: neither a sort nor a filter on a metric ranks a source that is count-only for the user
  const { restrictedIds } = await sourceRestrictions(context, user);
  const filters = restrictedIds.length > 0 ? addFilter(allowed.filters, 'internal_id', restrictedIds, 'not_eq', 'and') : allowed.filters;
  const connection = await pageEntitiesConnection<BasicStoreEntitySource>(context, user, [ENTITY_TYPE_SOURCE], { ...allowed, filters });
  const masked = await maskRestrictedSources(context, user, connection.edges.map((edge) => edge.node));
  return { ...connection, edges: connection.edges.map((edge, index) => ({ ...edge, node: masked[index] })) };
};

export const listAllSources = async (context: AuthContext) => {
  return fullEntitiesList<BasicStoreEntitySource>(context, SYSTEM_USER, [ENTITY_TYPE_SOURCE]);
};
// endregion

// region scorecards queries
export const findSourceScorecards = async (
  context: AuthContext,
  user: AuthUser,
  args: { sourceId: string; period?: ScorecardPeriodValue | null; startDate?: string | null; endDate?: string | null; first?: number | null },
) => {
  const source = await storeLoadById<BasicStoreEntitySource>(context, user, args.sourceId, ENTITY_TYPE_SOURCE);
  if (!source) {
    return [];
  }
  const period = args.period ?? REFERENCE_SCORECARD_PERIOD;
  // The live scorecard carries the streaming increments since the last snapshot: it ends a range that reaches today
  const reachesToday = !args.endDate || toSnapshotDate(new Date(args.endDate).getTime()) >= toSnapshotDate(Date.now());
  const [snapshots, live] = await Promise.all([
    searchScorecards(context, {
      sourceIds: [args.sourceId],
      period,
      live: false,
      startDate: args.startDate ?? null,
      endDate: args.endDate ?? null,
      first: args.first ?? 365,
      orderMode: 'asc',
    }),
    reachesToday ? findLiveScorecards(context, period, [args.sourceId]) : Promise.resolve([]),
  ]);
  return withoutRestrictedScorecards(context, user, [...snapshots, ...live]);
};

export const findLatestScorecard = async (context: AuthContext, user: AuthUser, sourceId: string, period?: ScorecardPeriodValue | null) => {
  const [scorecard] = await findLiveScorecards(context, period ?? REFERENCE_SCORECARD_PERIOD, [sourceId]);
  if (!scorecard) {
    return null;
  }
  const [readable] = await withoutRestrictedScorecards(context, user, [scorecard]);
  return readable ?? null;
};

export const findSourceOverlap = async (
  context: AuthContext,
  user: AuthUser,
  args: { period?: ScorecardPeriodValue | null; sourceIds?: string[] | null; first?: number | null },
) => {
  const period = args.period ?? REFERENCE_SCORECARD_PERIOD;
  const first = Math.min(Math.max(args.first ?? 20, 2), 50);
  const scorecards = await withoutRestrictedScorecards(
    context,
    user,
    await findLiveScorecards(context, period, args.sourceIds && args.sourceIds.length > 0 ? args.sourceIds : undefined),
  );
  const selected = scorecards
    .filter((scorecard) => scorecard.volume_total > 0)
    .sort((a, b) => b.volume_total - a.volume_total)
    .slice(0, first);
  const selectedIds = new Set(selected.map((scorecard) => scorecard.source_id));
  const byId = new Map(selected.map((scorecard) => [scorecard.source_id, scorecard]));
  const cells: Array<{ source_a: string; source_b: string; shared_count: number; share_a: number; share_b: number; jaccard: number; measured: boolean }> = [];
  const pairKey = (a: string, b: string) => (a < b ? `${a}|${b}` : `${b}|${a}`);
  const seen = new Set<string>();
  selected.forEach((scorecard) => {
    scorecard.overlap.forEach((share) => {
      if (!selectedIds.has(share.source_id)) return;
      const key = pairKey(scorecard.source_id, share.source_id);
      if (seen.has(key)) return;
      seen.add(key);
      const other = byId.get(share.source_id) as StoreSourceScorecard;
      const union = scorecard.volume_total + other.volume_total - share.shared_count;
      cells.push({
        source_a: scorecard.source_id,
        source_b: share.source_id,
        shared_count: share.shared_count,
        share_a: scorecard.volume_total > 0 ? Math.min(1, share.shared_count / scorecard.volume_total) : 0,
        share_b: other.volume_total > 0 ? Math.min(1, share.shared_count / other.volume_total) : 0,
        jaccard: union > 0 ? share.shared_count / union : 0,
        measured: true,
      });
    });
  });
  // A pair absent from the overlap of both sources shares no object only if one of the two overlaps is complete:
  // when both keep their top entries only, its counts are unknown
  for (let i = 0; i < selected.length; i += 1) {
    for (let j = i + 1; j < selected.length; j += 1) {
      const [a, b] = [selected[i], selected[j]];
      if (!seen.has(pairKey(a.source_id, b.source_id)) && a.overlap_complete !== true && b.overlap_complete !== true) {
        cells.push({ source_a: a.source_id, source_b: b.source_id, shared_count: 0, share_a: 0, share_b: 0, jaccard: 0, measured: false });
      }
    }
  }
  const selectedSources = selected.length > 0
    ? await internalFindByIds(context, user, selected.map((s) => s.source_id), { type: ENTITY_TYPE_SOURCE }) as unknown as BasicStoreEntitySource[]
    : [];
  const sources = selectedSources.length > 0 ? await maskRestrictedSources(context, user, selectedSources) : [];
  const sourcesById = new Map(sources.map((source) => [source.internal_id, source]));
  return {
    period,
    computed_at: selected[0]?.computed_at ?? null,
    sources: selected.map((scorecard) => sourcesById.get(scorecard.source_id)).filter((source) => source !== undefined),
    cells,
  };
};
// endregion

// region sources edition
const CURRENCY_REGEXP = /^[A-Z]{3}$/;

export const validateSourceCost = (input: { amount: number; currency: string; period: string } | null | undefined): SourceCost | null => {
  if (!input) {
    return null;
  }
  if (typeof input.amount !== 'number' || !Number.isFinite(input.amount) || input.amount < 0 || input.amount > 1e12) {
    throw FunctionalError('Invalid source cost amount', { amount: input.amount });
  }
  const currency = (input.currency ?? '').trim().toUpperCase();
  if (!CURRENCY_REGEXP.test(currency)) {
    throw FunctionalError('Invalid source cost currency, an ISO 4217 code is expected', { currency: input.currency });
  }
  if (!(SOURCE_COST_PERIODS as readonly string[]).includes(input.period)) {
    throw FunctionalError('Invalid source cost period', { period: input.period });
  }
  return { amount: input.amount, currency, period: input.period as SourceCost['period'] };
};

// Cost per actionable object of the reference scorecard of a source with a new cost, for the source KPIs
const referenceCostPerActionable = async (context: AuthContext, source: BasicStoreEntitySource, cost: SourceCost | null) => {
  const [reference] = await findLiveScorecards(context, REFERENCE_SCORECARD_PERIOD, [source.internal_id]);
  return reference ? computeCostPerActionable(cost, SCORECARD_PERIOD_DAYS[REFERENCE_SCORECARD_PERIOD], reference.actionable_count) : null;
};

const liveScorecardWindowCosts = (cost: SourceCost | null) => {
  return new Map(SCORECARD_PERIODS.map((period) => [period, normalizeCostToDays(cost, SCORECARD_PERIOD_DAYS[period])]));
};

const sameSourceCost = (a: SourceCost | null | undefined, b: SourceCost | null | undefined) => {
  return (a?.amount ?? null) === (b?.amount ?? null) && (a?.currency ?? null) === (b?.currency ?? null) && (a?.period ?? null) === (b?.period ?? null);
};

const sourceCostLockKey = (id: string) => `source-cost:${id}`;

/** Publishes an edited source as stored, and returns it as the user who edited it reads it (`findSourceById`). */
export const notifySourceEdition = async (context: AuthContext, user: AuthUser, element: unknown) => {
  const notified: BasicStoreEntitySource = await notify(BUS_TOPICS[ENTITY_TYPE_SOURCE].EDIT_TOPIC, element, user);
  const [source] = await maskRestrictedSources(context, user, [notified]);
  return source;
};

/**
 * Cost changes of one source run one at a time, and never while a full computation writes its latest KPIs (same lock,
 * on the internal id). The source holds the cost and is written first; its live scorecards derive from it and are
 * written last: if that write fails, the next full computation rewrites them from the source.
 */
export const sourceSetCost = async (context: AuthContext, user: AuthUser, id: string, input: { amount: number; currency: string; period: string } | null | undefined) => {
  const cost = validateSourceCost(input);
  const target = await storeLoadById<BasicStoreEntitySource>(context, user, id, ENTITY_TYPE_SOURCE);
  if (!target) {
    throw FunctionalError('Source not found', { id });
  }
  let lock;
  let element;
  let source: BasicStoreEntitySource | undefined;
  try {
    lock = await lockResources([sourceCostLockKey(target.internal_id)]);
    source = await storeLoadById<BasicStoreEntitySource>(context, user, target.internal_id, ENTITY_TYPE_SOURCE);
    if (!source) {
      throw FunctionalError('Source not found', { id });
    }
    const costPerActionable = await referenceCostPerActionable(context, source, cost);
    ({ element } = await patchAttribute(context, user, source.internal_id, ENTITY_TYPE_SOURCE, { source_cost: cost, latest_cost_per_actionable: costPerActionable }));
    await applyLiveScorecardCost(context, source.internal_id, cost?.currency ?? null, liveScorecardWindowCosts(cost));
  } catch (err: any) {
    if (err?.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds: [id] });
    }
    throw err;
  } finally {
    if (lock) {
      await lock.unlock();
    }
  }
  const activity = sourceCostActivity(id, source, cost);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: activity.message,
    context_data: { id, entity_type: ENTITY_TYPE_SOURCE, input: activity.input },
  });
  return notifySourceEdition(context, user, element);
};

const EDITABLE_SOURCE_KEYS = ['description', 'tags', 'owner_id', 'enabled'];

export const sourceEditField = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  const source = await storeLoadById<BasicStoreEntitySource>(context, user, id, ENTITY_TYPE_SOURCE);
  if (!source) {
    throw FunctionalError('Source not found', { id });
  }
  const invalidKeys = input.map((i) => i.key).filter((key) => !EDITABLE_SOURCE_KEYS.includes(key));
  if (invalidKeys.length > 0) {
    throw FunctionalError('Invalid or forbidden source field', { keys: invalidKeys });
  }
  const patch: Record<string, unknown> = {};
  input.forEach(({ key, value }) => {
    const values = (value ?? []) as unknown[];
    if (key === 'tags') {
      const tags = values.map((v) => String(v).trim()).filter((v) => v.length > 0 && v.length <= 64);
      if (tags.length > 50) throw FunctionalError('Too many tags on the source', { count: tags.length });
      patch.tags = [...new Set(tags)];
    } else if (key === 'enabled') {
      patch.enabled = values[0] === true || values[0] === 'true';
    } else if (key === 'description') {
      const description = values[0] === null || values[0] === undefined ? null : String(values[0]);
      if (description && description.length > 5000) throw FunctionalError('Source description too long');
      patch.description = description;
    } else if (key === 'owner_id') {
      patch.owner_id = values[0] ? String(values[0]) : null;
    }
  });
  if (patch.owner_id) {
    const owner = await storeLoadById(context, user, patch.owner_id as string, ENTITY_TYPE_USER);
    if (!owner) throw FunctionalError('Source owner not found', { owner_id: patch.owner_id });
  }
  const { element } = await patchAttribute(context, user, id, ENTITY_TYPE_SOURCE, patch);
  // On every save of a disabled source, not only when it gets disabled: saving it again retries a failed cleanup
  if (patch.enabled === false) {
    await clearDisabledSourcesLiveData(context, [element as unknown as BasicStoreEntitySource]);
  }
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${Object.keys(patch).join(', ')}\` for ${sourceAuditName(id, source)}`,
    context_data: { id, entity_type: ENTITY_TYPE_SOURCE, input: sourceEditActivityInput(source, patch) },
  });
  return notifySourceEdition(context, user, element);
};

/**
 * Side-channel update of the denormalized latest KPIs of a source (no stream event, no updated_at change): the
 * scorecards are derived data and must not trigger playbooks, streams or history.
 */
export const updateSourceLatestKpis = async (context: AuthContext, source: BasicStoreEntitySource, kpis: Record<string, unknown>) => {
  const params = { kpis };
  const script = 'for (entry in params.kpis.entrySet()) { ctx._source[entry.getKey()] = entry.getValue(); }';
  await elUpdate(context, source._index, source.internal_id, { script: { source: script, lang: 'painless', params } });
};

/**
 * Latest KPIs of a source after a full computation, written under the lock of its cost changes from the source as it
 * is now: a cost set while the scorecards were computed or written is written again on its live scorecards, and the
 * cost per actionable object of the source derives from that cost. Returns false for a source deleted meanwhile.
 */
export const writeComputedSourceKpis = async (
  context: AuthContext,
  computed: BasicStoreEntitySource,
  reference: Pick<StoreSourceScorecard, 'actionable_count'>,
  kpis: Record<string, unknown>,
) => {
  let lock;
  try {
    lock = await lockResources([sourceCostLockKey(computed.internal_id)]);
    const current = await storeLoadById<BasicStoreEntitySource>(context, SYSTEM_USER, computed.internal_id, ENTITY_TYPE_SOURCE);
    if (!current) {
      return false;
    }
    const cost = current.source_cost ?? null;
    if (!sameSourceCost(cost, computed.source_cost)) {
      await applyLiveScorecardCost(context, current.internal_id, cost?.currency ?? null, liveScorecardWindowCosts(cost));
    }
    const costPerActionable = computeCostPerActionable(cost, SCORECARD_PERIOD_DAYS[REFERENCE_SCORECARD_PERIOD], reference.actionable_count);
    await updateSourceLatestKpis(context, current, { ...kpis, latest_cost_per_actionable: costPerActionable });
    return true;
  } finally {
    if (lock) {
      await lock.unlock();
    }
  }
};

/**
 * A disabled source is not scored anymore: its live scorecards and its latest KPIs are removed (its daily snapshots
 * stay as history), so leaderboards, widgets and consumers of the latest KPIs never show stale values for it.
 */
export const clearDisabledSourcesLiveData = async (context: AuthContext, sources: BasicStoreEntitySource[]) => {
  if (sources.length === 0) {
    return;
  }
  await deleteLiveScorecardsOfSources(context, sources.map((source) => source.internal_id));
  for (let i = 0; i < sources.length; i += 1) {
    if (sources[i].last_computed_at) {
      await updateSourceLatestKpis(context, sources[i], CLEARED_LATEST_KPIS);
    }
  }
  await publishCacheResetEvent(ENTITY_TYPE_SOURCE);
};
// endregion

// region sources materialization
interface SourceCandidate {
  source_kind: SourceKindValue;
  ref_id: string;
  ref_type: string;
  name: string;
  source_user_ids: string[];
}

type TopValueBucket = { key: string; doc_count: number };

const DISCOVERY_INDICES = [READ_INDEX_STIX_DOMAIN_OBJECTS, READ_INDEX_STIX_CYBER_OBSERVABLES, READ_INDEX_STIX_CORE_RELATIONSHIPS, READ_INDEX_STIX_SIGHTING_RELATIONSHIPS];

/**
 * Most frequent values of a field over the knowledge written during the window.
 */
const aggregateTopValues = async (context: AuthContext, field: string, sinceDays: number, minCount: number, size: number, exclude: string[] = []) => {
  if (size <= 0) {
    return [];
  }
  const since = new Date(Date.now() - sinceDays * DAY_MS).toISOString();
  const data = await elRawSearch(context, SYSTEM_USER, ENTITY_TYPE_SOURCE, {
    index: DISCOVERY_INDICES,
    size: 0,
    track_total_hits: false,
    body: {
      query: { range: { updated_at: { gte: since } } },
      aggs: { top: { terms: { field: `${field}.keyword`, size, min_doc_count: minCount, ...termsExclusion(exclude) } } },
    },
  }).catch((err: unknown) => {
    throw DatabaseError('Source intelligence source discovery failed', { cause: err, field });
  });
  return (data.aggregations?.top?.buckets ?? []) as TopValueBucket[];
};

const termsExclusion = (exclude: string[]) => (exclude.length > 0 ? { exclude } : {});

/**
 * Users that are never analysts: the platform internal users, the service accounts and the users of the connectors and
 * feeds. They are left out of the discovery aggregations, so their volume never takes the place of an analyst.
 */
export const analystExclusions = (serviceUserIds: Set<string>, users: Map<string, { user_service_account?: boolean }>) => {
  const excluded = new Set([...serviceUserIds, ...Object.keys(INTERNAL_USERS)]);
  users.forEach((user, userId) => {
    if (user.user_service_account === true) {
      excluded.add(userId);
    }
  });
  return [...excluded].sort();
};

const collectSourceCandidates = async (context: AuthContext, settings: SourceIntelligenceSettings): Promise<SourceCandidate[]> => {
  const candidates: SourceCandidate[] = [];
  const connectors = await getEntitiesListFromCache<BasicStoreEntityConnector>(context, SYSTEM_USER, ENTITY_TYPE_CONNECTOR);
  const feeds = await fullEntitiesList<BasicStoreEntity & { name: string; user_id?: string }>(context, SYSTEM_USER, INGESTION_FEED_TYPES);
  const feedTwinConnectorIds = new Set(feeds.map((feed) => connectorIdFromIngestId(feed.internal_id)));
  const serviceUserIds = new Set<string>();
  connectors
    .filter((connector) => !feedTwinConnectorIds.has(connector.internal_id))
    .forEach((connector) => {
      const userIds = connector.connector_user_id ? [connector.connector_user_id] : [];
      userIds.forEach((userId) => serviceUserIds.add(userId));
      // Built-in connectors run platform work on behalf of analysts (background tasks, playbooks, synchronization,
      // draft validation, file mapping): the knowledge they write is attributed to its authors and analysts
      if ((connector as ConnectorWithOrigin).built_in === true || NON_PRODUCING_CONNECTOR_TYPES.includes(connector.connector_type)) {
        return;
      }
      candidates.push({
        source_kind: SOURCE_KIND_CONNECTOR,
        ref_id: connector.internal_id,
        ref_type: ENTITY_TYPE_CONNECTOR,
        name: (connector as BasicStoreEntityConnector & { title?: string }).title || connector.name,
        source_user_ids: userIds,
      });
    });
  feeds.forEach((feed) => {
    const userIds = feed.user_id ? [feed.user_id] : [];
    userIds.forEach((userId) => serviceUserIds.add(userId));
    candidates.push({ source_kind: SOURCE_KIND_INGESTION_FEED, ref_id: feed.internal_id, ref_type: feed.entity_type, name: feed.name, source_user_ids: userIds });
  });
  // Authors with a significant volume over the longest period
  const maxDays = SCORECARD_PERIOD_DAYS[SCORECARD_PERIODS[SCORECARD_PERIODS.length - 1]];
  const authorBuckets = await aggregateTopValues(context, 'rel_created-by.internal_id', maxDays, settings.min_author_volume, settings.max_author_sources);
  if (authorBuckets.length > 0) {
    const identities = await internalFindByIds(context, SYSTEM_USER, authorBuckets.map((b) => b.key)) as unknown as Array<BasicStoreEntity & { name: string }>;
    identities.forEach((identity) => {
      candidates.push({ source_kind: SOURCE_KIND_AUTHOR, ref_id: identity.internal_id, ref_type: identity.entity_type, name: identity.name, source_user_ids: [] });
    });
  }
  // Analysts writing knowledge directly (not through a connector or a feed)
  const users = await getEntitiesMapFromCache<BasicStoreEntity & { name: string; user_service_account?: boolean }>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const nonAnalystIds = analystExclusions(serviceUserIds, users);
  const analystBuckets = await aggregateTopValues(context, 'creator_id', maxDays, settings.min_manual_volume, settings.max_manual_sources, nonAnalystIds);
  if (analystBuckets.length > 0) {
    analystBuckets
      .filter((bucket) => !serviceUserIds.has(bucket.key) && !INTERNAL_USERS[bucket.key])
      .map((bucket) => users.get(bucket.key))
      .filter((user): user is BasicStoreEntity & { name: string; user_service_account?: boolean } => !!user && user.user_service_account !== true)
      .slice(0, settings.max_manual_sources)
      .forEach((user) => {
        candidates.push({ source_kind: SOURCE_KIND_MANUAL, ref_id: user.internal_id, ref_type: ENTITY_TYPE_USER, name: user.name, source_user_ids: [user.internal_id] });
      });
  }
  return candidates;
};

const REVERTABLE_RECOMMENDATION_STATUSES = [RECOMMENDATION_STATUS_APPLYING, RECOMMENDATION_STATUS_APPLIED, RECOMMENDATION_STATUS_REVERTING];

/**
 * Lifts the quarantine of a connector or feed source about to be removed. The service account of a connector outlives
 * it: its user gets back the draft context recorded when the quarantine was applied, never staying routed to a
 * quarantine draft that no source enforces anymore. A user moved to another draft context since is left there.
 */
export const releaseQuarantineOfRemovedSource = async (context: AuthContext, source: BasicStoreEntitySource) => {
  if (!source.quarantined) {
    return;
  }
  const userId = quarantinedConnectorUserId(source);
  const user = userId ? await storeLoadById<BasicStoreEntity & { draft_context?: string | null }>(context, SYSTEM_USER, userId, ENTITY_TYPE_USER) : undefined;
  let connectorUser: { userId: string; draftContext: string } | undefined;
  if (userId && user && user.draft_context === source.quarantine_draft_id) {
    const recommendations = await fullEntitiesList<BasicStoreEntitySourceRecommendation>(context, SYSTEM_USER, [ENTITY_TYPE_SOURCE_RECOMMENDATION], {
      filters: {
        mode: 'and',
        filters: [
          { key: ['source_id'], values: [source.internal_id], operator: 'eq', mode: 'or' },
          { key: ['recommendation_kind'], values: [RECOMMENDATION_QUARANTINE], operator: 'eq', mode: 'or' },
          { key: ['recommendation_status'], values: REVERTABLE_RECOMMENDATION_STATUSES, operator: 'eq', mode: 'or' },
        ],
        filterGroups: [],
      },
    } as any);
    const revert = recommendations
      .map((recommendation) => parseJsonRecord(recommendation.revert_payload))
      .find((payload) => payload.target === 'connector_user' && payload.user_id === userId);
    connectorUser = { userId, draftContext: typeof revert?.previous_draft_context === 'string' ? revert.previous_draft_context : '' };
  }
  await releaseQuarantine(context, SOURCE_INTELLIGENCE_MANAGER_USER, source.internal_id, connectorUser);
};

const loadSourceIdsWithRevertableChanges = async (context: AuthContext, sourceIds: string[]) => {
  if (sourceIds.length === 0) {
    return new Set<string>();
  }
  const recommendations = await fullEntitiesList<BasicStoreEntitySourceRecommendation>(context, SYSTEM_USER, [ENTITY_TYPE_SOURCE_RECOMMENDATION], {
    filters: {
      mode: 'and',
      filters: [
        { key: ['source_id'], values: sourceIds, operator: 'eq', mode: 'or' },
        { key: ['recommendation_status'], values: REVERTABLE_RECOMMENDATION_STATUSES, operator: 'eq', mode: 'or' },
      ],
      filterGroups: [],
    },
  } as any);
  return new Set(recommendations.map((recommendation) => recommendation.source_id).filter((sourceId): sourceId is string => !!sourceId));
};

/**
 * Authors and analysts are the top contributors of the longest window: one that left them stops being a source,
 * unless someone curated it (cost, description, tags, owner, disabled, quarantined) or a change applied to it can
 * still be reverted. The scored authors and analysts are therefore bounded by the discovery and by what people curate.
 */
export const isKeptOutsideDiscovery = (source: BasicStoreEntitySource & { description?: string | null }, revertableSourceIds: Set<string>) => {
  return !!source.source_cost
    || !!source.description
    || (source.tags ?? []).length > 0
    || !!source.owner_id
    || source.enabled === false
    || source.quarantined === true
    || !!source.quarantine_draft_id
    || revertableSourceIds.has(source.internal_id);
};

type CuratedSource = BasicStoreEntitySource & { description?: string | null };

/** Fingerprint of a recommendation moved from a merged source to the kept one: its source id parts follow the move. */
export const fingerprintOnKeptSource = (fingerprint: string, duplicateId: string, keptId: string) => {
  return fingerprint.split(':').map((part) => (part === duplicateId ? keptId : part)).join(':');
};

const isActiveRecommendation = (recommendation: BasicStoreEntitySourceRecommendation) => {
  return ACTIVE_RECOMMENDATION_STATUSES.includes(recommendation.recommendation_status as typeof ACTIVE_RECOMMENDATION_STATUSES[number]);
};

// Lock held by every status transition of a recommendation (apply, revert, dismiss) and by the engine writes on it
export const recommendationTransitionLock = (id: string) => `source-recommendation-transition:${id}`;

const loadRecommendationsOfSource = (context: AuthContext, sourceId: string) => {
  return fullEntitiesList<BasicStoreEntitySourceRecommendation>(context, SYSTEM_USER, [ENTITY_TYPE_SOURCE_RECOMMENDATION], {
    filters: { mode: 'and', filters: [{ key: ['source_id'], values: [sourceId], operator: 'eq', mode: 'or' }], filterGroups: [] },
  } as any);
};

/**
 * Two analyst sources reference the same user once their users were merged: the kept one takes over what the other
 * one holds before it is removed. Its recommendations follow it with the fingerprint of the kept source, so a change
 * applied to the other one can still be reverted, a reverted one still holds autonomy back and the rules never
 * propose them again; a pending one (proposed or failed) whose fingerprint the kept source already holds live is
 * withdrawn, so one fingerprint keeps one live entry. What a person curated on the other one is kept where the kept
 * source has nothing of its own (a disabled or quarantined state wins, as the revert of the recommendation that set it
 * now targets the kept source); its daily snapshots fill the days the kept source has no snapshot of.
 */
export const mergeDuplicateSource = async (context: AuthContext, duplicate: CuratedSource, kept: CuratedSource) => {
  const recommendations = await loadRecommendationsOfSource(context, duplicate.internal_id);
  const keptLive = new Set((await loadRecommendationsOfSource(context, kept.internal_id))
    .filter(isActiveRecommendation)
    .map((recommendation) => recommendation.fingerprint));
  const pendingStatuses: string[] = [RECOMMENDATION_STATUS_PROPOSED, RECOMMENDATION_STATUS_FAILED];
  for (let i = 0; i < recommendations.length; i += 1) {
    const { internal_id: id } = recommendations[i];
    // Under the transition lock, loaded again: an apply, revert or dismiss in progress settles first and its outcome
    // (status, revert payload) is the one moved
    let lock;
    try {
      lock = await lockResources([recommendationTransitionLock(id)]);
      const recommendation = await storeLoadById<BasicStoreEntitySourceRecommendation>(context, SYSTEM_USER, id, ENTITY_TYPE_SOURCE_RECOMMENDATION);
      if (recommendation) {
        const revert = parseJsonRecord(recommendation.revert_payload);
        const fingerprint = fingerprintOnKeptSource(recommendation.fingerprint, duplicate.internal_id, kept.internal_id);
        const patch: Record<string, unknown> = { source_id: kept.internal_id, fingerprint };
        if (revert.source_id === duplicate.internal_id) {
          patch.revert_payload = JSON.stringify({ ...revert, source_id: kept.internal_id });
        }
        if (keptLive.has(fingerprint) && pendingStatuses.includes(recommendation.recommendation_status)) {
          patch.recommendation_status = RECOMMENDATION_STATUS_DISMISSED;
          patch.dismissed_at = new Date().toISOString();
          patch.dismiss_reason = 'Withdrawn: the merged source already holds this recommendation';
        } else if (isActiveRecommendation(recommendation)) {
          keptLive.add(fingerprint);
        }
        await patchAttribute(context, SOURCE_INTELLIGENCE_MANAGER_USER, id, ENTITY_TYPE_SOURCE_RECOMMENDATION, patch);
      }
    } catch (err: any) {
      if (err?.name === TYPE_LOCK_ERROR) {
        throw LockTimeoutError({ participantIds: [id] });
      }
      throw err;
    } finally {
      if (lock) {
        await lock.unlock();
      }
    }
  }
  const curated: Record<string, unknown> = {};
  if (!kept.source_cost && duplicate.source_cost) curated.source_cost = duplicate.source_cost;
  if (!kept.description && duplicate.description) curated.description = duplicate.description;
  if (!kept.owner_id && duplicate.owner_id) curated.owner_id = duplicate.owner_id;
  const tags = [...new Set([...(kept.tags ?? []), ...(duplicate.tags ?? [])])];
  if (tags.length > (kept.tags ?? []).length) curated.tags = tags;
  if (duplicate.enabled === false && kept.enabled !== false) curated.enabled = false;
  if (duplicate.quarantined === true && kept.quarantined !== true) {
    curated.quarantined = true;
    curated.quarantine_draft_id = kept.quarantine_draft_id ?? duplicate.quarantine_draft_id ?? null;
  }
  if (Object.keys(curated).length > 0) {
    await patchAttribute(context, SOURCE_INTELLIGENCE_MANAGER_USER, kept.internal_id, ENTITY_TYPE_SOURCE, curated);
  }
  await moveScorecardSnapshots(context, duplicate.internal_id, kept.internal_id);
  return { ...kept, ...curated } as CuratedSource;
};

/**
 * Materialize one Source per connector, ingestion feed, significant author and analyst, keeping user edits (cost,
 * tags, owner, enabled), removing sources whose connector or feed no longer exists and the authors and analysts that
 * left the discovery without being curated.
 */
export const syncSources = async (context: AuthContext, settings: SourceIntelligenceSettings) => {
  const candidates = await collectSourceCandidates(context, settings);
  const existing = await listAllSources(context);
  // Two analyst sources reference the same user once their users were merged: the one whose identity matches the
  // shared kind and reference (the one a new discovery of it resolves to) is kept, takes over what the other one holds,
  // and the other one is removed
  const existingByKey = new Map<string, BasicStoreEntitySource>();
  const duplicates: BasicStoreEntitySource[] = [];
  const isCanonical = (source: BasicStoreEntitySource) => source.standard_id === generateStandardId(ENTITY_TYPE_SOURCE, source);
  const sorted = [...existing].sort((a, b) => Number(isCanonical(b)) - Number(isCanonical(a)) || a.internal_id.localeCompare(b.internal_id));
  for (let i = 0; i < sorted.length; i += 1) {
    const source = sorted[i];
    const key = `${source.source_kind}|${source.ref_id}`;
    const kept = existingByKey.get(key);
    if (kept) {
      // The merged curation decides below whether the kept source stays outside the discovery
      existingByKey.set(key, await mergeDuplicateSource(context, source, kept));
      duplicates.push(source);
    } else {
      existingByKey.set(key, source);
    }
  }
  const candidateKeys = new Set<string>();
  let created = 0;
  let updated = 0;
  for (let i = 0; i < candidates.length; i += 1) {
    const candidate = candidates[i];
    const key = `${candidate.source_kind}|${candidate.ref_id}`;
    candidateKeys.add(key);
    const current = existingByKey.get(key);
    if (!current) {
      await createEntity(context, SOURCE_INTELLIGENCE_MANAGER_USER, { ...candidate, enabled: true, quarantined: false }, ENTITY_TYPE_SOURCE);
      created += 1;
    } else {
      const sameUsers = [...(current.source_user_ids ?? [])].sort().join(',') === [...candidate.source_user_ids].sort().join(',');
      if (current.name !== candidate.name || !sameUsers || current.ref_type !== candidate.ref_type) {
        await patchAttribute(context, SOURCE_INTELLIGENCE_MANAGER_USER, current.internal_id, ENTITY_TYPE_SOURCE, {
          name: candidate.name,
          ref_type: candidate.ref_type,
          source_user_ids: candidate.source_user_ids,
        });
        updated += 1;
      }
    }
  }
  const undiscovered = Array.from(existingByKey.values()).filter((source) => !candidateKeys.has(`${source.source_kind}|${source.ref_id}`));
  // Connectors and feeds deleted from the platform or no longer sources: their sources and scorecards are removed
  const orphans = undiscovered.filter((source) => source.source_kind === SOURCE_KIND_CONNECTOR || source.source_kind === SOURCE_KIND_INGESTION_FEED);
  // Authors and analysts out of the discovery: removed with their scorecards, unless they are kept
  const departed = undiscovered.filter((source) => source.source_kind === SOURCE_KIND_AUTHOR || source.source_kind === SOURCE_KIND_MANUAL);
  const revertable = await loadSourceIdsWithRevertableChanges(context, departed.map((source) => source.internal_id));
  const dropped = departed.filter((source) => !isKeptOutsideDiscovery(source, revertable));
  const removed = [...orphans, ...dropped, ...duplicates];
  for (let i = 0; i < orphans.length; i += 1) {
    await releaseQuarantineOfRemovedSource(context, orphans[i]);
  }
  // The sources go last: a removal interrupted before them is found and completed by the next synchronization
  await deleteScorecardsOfSources(context, removed.map((source) => source.internal_id));
  for (let i = 0; i < removed.length; i += 1) {
    await deleteElementById(context, SOURCE_INTELLIGENCE_MANAGER_USER, removed[i].internal_id, ENTITY_TYPE_SOURCE);
  }
  if (created + updated + removed.length > 0) {
    await publishCacheResetEvent(ENTITY_TYPE_SOURCE);
  }
  logApp.info('[OPENCTI-MODULE] Source intelligence sources synchronized', { created, updated, removed: removed.length, total: candidates.length });
  return listAllSources(context);
};
// endregion

// region status
const snapshotDayNumber = (day: string) => Math.floor(new Date(`${day}T00:00:00.000Z`).getTime() / DAY_MS);

/**
 * Progress of the history backfill in days, computed and planned, or null when no backfill was planned.
 */
export const backfillProgress = (state: SourceIntelligenceState): { done: number; total: number } | null => {
  if (!state.backfill_from_day || !state.backfill_until_day) {
    return null;
  }
  const from = snapshotDayNumber(state.backfill_from_day);
  const total = Math.max(0, snapshotDayNumber(state.backfill_until_day) - from);
  if (state.backfill_done || !state.backfill_next_day) {
    return { done: total, total };
  }
  return { done: Math.min(total, Math.max(0, snapshotDayNumber(state.backfill_next_day) - from)), total };
};

/**
 * The historical day the backfill holds on, or null: a day whose scan reached `max_scan_objects` is neither stored nor
 * counted as covered, and is scanned again only once the limit is raised.
 */
export const backfillHeldDay = (state: SourceIntelligenceState, settings: Pick<SourceIntelligenceSettings, 'max_scan_objects'>) => {
  const held = !state.backfill_done
    && !!state.backfill_next_day
    && state.backfill_truncated_day === state.backfill_next_day
    && (state.backfill_truncated_limit ?? 0) >= settings.max_scan_objects;
  return held ? state.backfill_next_day ?? null : null;
};

export const getSourceIntelligenceStatus = async (context: AuthContext) => {
  const [state, settings, sources, scoredSources, running, enabled, enterprise] = await Promise.all([
    getSourceIntelligenceState(),
    getSourceIntelligenceSettings(context),
    listAllSources(context),
    countScoredSources(context),
    isSourceIntelligenceRunning(context),
    isSourceIntelligenceEnabled(),
    isEnterpriseEdition(context),
  ]);
  const backfill = backfillProgress(state);
  return {
    manager_enabled: enabled,
    manager_running: enabled && running,
    enterprise_edition: enterprise,
    sources_count: sources.length,
    scored_sources_count: scoredSources,
    last_full_run_start: state.last_full_run_start ?? null,
    last_full_run_end: state.last_full_run_end ?? null,
    last_run_success: state.last_run_success ?? null,
    last_run_message: state.last_run_message ?? null,
    last_scanned_objects: state.last_scanned_objects ?? null,
    last_scan_truncated: state.last_scan_truncated ?? false,
    backfill_done: state.backfill_done ?? false,
    backfill_next_day: state.backfill_next_day ?? null,
    backfill_days_done: backfill?.done ?? null,
    backfill_days_total: backfill?.total ?? null,
    backfill_held_day: backfillHeldDay(state, settings),
    recompute_requested_at: state.recompute_requested_at ?? null,
  };
};
// endregion

export const checkSourceWriteCapability = (user: AuthUser, capability: string) => {
  if (!isUserHasCapability(user, capability)) {
    throw ForbiddenAccess(`This action requires the ${capability} capability`);
  }
};
