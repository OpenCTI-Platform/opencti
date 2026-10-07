import { createHash } from 'node:crypto';
import * as R from 'ramda';
import { LRUCache } from 'lru-cache';
import conf from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity, BasicStoreRelation } from '../../types/store';
import type { BasicStoreSettings } from '../../types/settings';
import { fullEntitiesList, fullRelationsList, internalFindByIds } from '../../database/middleware-loader';
import { elCount } from '../../database/engine';
import { getEntityFromCache } from '../../database/cache';
import { READ_DATA_INDICES, READ_INDEX_DELETED_OBJECTS, READ_INDEX_STIX_DOMAIN_OBJECTS, READ_INDEX_STIX_META_OBJECTS } from '../../database/utils';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_KILL_CHAIN_PHASE } from '../../schema/stixMetaObject';
import { RELATION_KILL_CHAIN_PHASE } from '../../schema/stixRefRelationship';
import { RELATION_SUBTECHNIQUE_OF, RELATION_USES } from '../../schema/stixCoreRelationship';
import { isBypassUser, SYSTEM_USER } from '../../utils/access';
import { bypassDraftContext } from '../../utils/draftContext';
import { FilterMode, type FilterGroup } from '../../generated/graphql';
import { DEFENSE_THREAT_TYPES, type DefenseCoverage, type DefenseThreatOverlay, type DefenseThreatUsage } from './defenseCoverage-types';
import { type AccessPredicate, collectCoverageIds } from './defenseCoverage-utils';
import { getDefenseCoverageVersion, getDefenseOverlayVersion, getDefenseThreatsVersion } from './defenseCoverage-state';

const READER_CACHE_TTL = conf.get('defense_coverage_manager:reader_cache_ttl') ?? 300000; // 5 minutes
const MAX_SELECTED_THREATS = 500;
const IDS_CHUNK_SIZE = 5000;

export type DefenseThreatScopeMode = 'ALL' | 'SELECTED' | 'FILTERED' | 'NONE';
export interface DefenseThreatScope {
  mode: DefenseThreatScopeMode;
  threatIds?: string[] | null;
  filters?: FilterGroup | null;
}

// region stored coverage snapshot
export interface DefenseTechniqueEntry {
  id: string;
  name: string;
  x_mitre_id?: string;
  description?: string;
  kill_chain_phase_ids: string[];
  parent_id?: string;
  parent_rel_id?: string; // subtechnique-of relationship id, the parent is shown only to readers of both
  coverage?: DefenseCoverage;
}

export interface DefenseKillChainPhase {
  id: string;
  kill_chain_name: string;
  phase_name: string;
  x_opencti_order: number;
}

export interface DefenseSnapshot {
  version: string;
  techniques: DefenseTechniqueEntry[];
  techniquesById: Map<string, DefenseTechniqueEntry>;
  phases: DefenseKillChainPhase[];
  evidenceIds: string[];
}

// The caches of this file are shared by every reader, in a draft or not: they are filled from published knowledge only
const publishedReader = (context: AuthContext, user: AuthUser) => ({
  publishedContext: bypassDraftContext(context),
  publishedUser: { ...user, draft_context: undefined } as AuthUser,
});

let snapshotCache: { version: string; promise: Promise<DefenseSnapshot> } | undefined;

const loadSnapshot = async (context: AuthContext, version: string): Promise<DefenseSnapshot> => {
  const attackPatterns = await fullEntitiesList<BasicStoreEntity>(context, SYSTEM_USER, [ENTITY_TYPE_ATTACK_PATTERN], {
    indices: [READ_INDEX_STIX_DOMAIN_OBJECTS],
    withoutRels: false,
    filters: { mode: FilterMode.And, filters: [{ key: ['revoked'], values: ['false'] }], filterGroups: [] },
  } as never);
  // A revoked sub-technique relationship no longer folds the sub-technique into its parent
  const subTechniques = (await fullRelationsList<BasicStoreRelation>(context, SYSTEM_USER, RELATION_SUBTECHNIQUE_OF, {
    fromTypes: [ENTITY_TYPE_ATTACK_PATTERN],
    toTypes: [ENTITY_TYPE_ATTACK_PATTERN],
    baseData: true,
    baseFields: ['revoked'],
  })).filter((relation) => !relation.revoked);
  const parentBySub = new Map(subTechniques.map((s) => [s.fromId, { id: s.toId, rel: s.internal_id }]));
  const phases = await fullEntitiesList<BasicStoreEntity>(context, SYSTEM_USER, [ENTITY_TYPE_KILL_CHAIN_PHASE], { indices: [READ_INDEX_STIX_META_OBJECTS] });
  const techniques: DefenseTechniqueEntry[] = attackPatterns.map((ap) => {
    const record = ap as unknown as Record<string, unknown>;
    return {
      id: ap.internal_id,
      name: ap.name,
      x_mitre_id: record.x_mitre_id as string | undefined,
      description: ap.description,
      kill_chain_phase_ids: (record[RELATION_KILL_CHAIN_PHASE] as string[] | undefined) ?? [],
      parent_id: parentBySub.get(ap.internal_id)?.id,
      parent_rel_id: parentBySub.get(ap.internal_id)?.rel,
      coverage: record.x_opencti_defense_coverage as DefenseCoverage | undefined,
    };
  });
  const evidenceIds = R.uniq(techniques.flatMap((t) => [t.id, ...(t.parent_rel_id ? [t.parent_rel_id] : []), ...collectCoverageIds(t.coverage)]));
  return {
    version,
    techniques,
    techniquesById: new Map(techniques.map((t) => [t.id, t])),
    phases: phases.map((p) => {
      const record = p as unknown as Record<string, unknown>;
      return {
        id: p.internal_id,
        kill_chain_name: record.kill_chain_name as string,
        phase_name: record.phase_name as string,
        x_opencti_order: (record.x_opencti_order as number | undefined) ?? 0,
      };
    }),
    evidenceIds,
  };
};

/**
 * Stored coverage of every technique, shared by all readers of this node and reloaded when the manager
 * publishes a new version.
 */
export const getDefenseSnapshot = async (context: AuthContext): Promise<DefenseSnapshot> => {
  const version = await getDefenseCoverageVersion();
  if (!snapshotCache || snapshotCache.version !== version) {
    const promise = loadSnapshot(bypassDraftContext(context), version);
    snapshotCache = { version, promise };
    promise.catch(() => {
      if (snapshotCache?.promise === promise) snapshotCache = undefined;
    });
  }
  return snapshotCache.promise;
};

export const clearDefenseSnapshotCache = () => {
  snapshotCache = undefined;
  accessCache.clear();
  overlayCache.clear();
};
// endregion

// region access
const accessCache = new LRUCache<string, Promise<Set<string>>>({ max: 500, ttl: READER_CACHE_TTL });

const sortedIds = (elements: Array<{ internal_id: string }> | undefined) => (elements ?? []).map((e) => e.internal_id).sort();

/**
 * Fingerprint of everything deciding what a reader may access: identity, groups, roles, organizations, capabilities,
 * allowed markings, the service account flag (it bypasses the authorized members), the linked individual and the
 * platform organization (both decide the organization restrictions). Granting or revoking any of them changes the
 * fingerprint, so a read cached under the previous grants is never served again.
 */
export const computeReaderAccessFingerprint = async (context: AuthContext, user: AuthUser): Promise<string> => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const material = JSON.stringify([
    user.id,
    sortedIds(user.groups),
    sortedIds(user.roles),
    sortedIds(user.organizations),
    (user.capabilities ?? []).map((c) => c.name).sort(),
    sortedIds(user.allowed_marking),
    user.user_service_account === true,
    user.individual_id ?? null,
    context.user_inside_platform_organization === true,
    settings?.platform_organization ?? null,
  ]);
  return createHash('sha256').update(material).digest('hex');
};

/**
 * Ids among `ids` that the user can access. With `includeDeleted`, the elements kept in the trash are evaluated too,
 * with the markings and organizations they had when they were deleted.
 */
export const findAccessibleIds = async (
  context: AuthContext,
  user: AuthUser,
  ids: string[],
  opts: { includeDeleted?: boolean } = {},
): Promise<Set<string>> => {
  const accessible = new Set<string>();
  const indices = opts.includeDeleted ? [...READ_DATA_INDICES, READ_INDEX_DELETED_OBJECTS] : undefined;
  const chunks = R.splitEvery(IDS_CHUNK_SIZE, R.uniq(ids));
  for (let index = 0; index < chunks.length; index += 1) {
    const found = await internalFindByIds<BasicStoreEntity>(context, user, chunks[index], { baseData: true, ...(indices ? { indices } : {}) }) as BasicStoreEntity[];
    found.forEach((f) => accessible.add(f.internal_id));
  }
  return accessible;
};

/**
 * Predicate telling if the reader can access an element or a relationship used as evidence.
 * Evaluated once per reader grants and snapshot version, then cached.
 */
export const getAccessPredicate = async (context: AuthContext, user: AuthUser, snapshot: DefenseSnapshot): Promise<AccessPredicate> => {
  if (isBypassUser(user)) {
    return (id) => !!id;
  }
  const key = `${await computeReaderAccessFingerprint(context, user)}|${snapshot.version}`;
  let promise = accessCache.get(key);
  if (!promise) {
    const { publishedContext, publishedUser } = publishedReader(context, user);
    promise = findAccessibleIds(publishedContext, publishedUser, snapshot.evidenceIds);
    accessCache.set(key, promise);
    promise.catch(() => accessCache.delete(key));
  }
  const accessible = await promise;
  return (id) => !!id && accessible.has(id);
};
// endregion

// region threat overlay
const overlayCache = new LRUCache<string, Promise<DefenseThreatOverlay>>({ max: 500, ttl: READER_CACHE_TTL });

const normalizeScope = (scope: DefenseThreatScope | null | undefined): DefenseThreatScope => {
  if (!scope) return { mode: 'ALL' };
  if (scope.mode === 'SELECTED') {
    const threatIds = R.uniq(scope.threatIds ?? []);
    if (threatIds.length > MAX_SELECTED_THREATS) {
      throw FunctionalError(`A threat overlay cannot select more than ${MAX_SELECTED_THREATS} threats`, { count: threatIds.length });
    }
    return { mode: 'SELECTED', threatIds: [...threatIds].sort() };
  }
  if (scope.mode === 'FILTERED') {
    return { mode: 'FILTERED', filters: scope.filters ?? null };
  }
  return { mode: scope.mode };
};

const loadThreatUsages = async (context: AuthContext, user: AuthUser, threatIds?: string[]) => {
  const args = {
    fromTypes: DEFENSE_THREAT_TYPES,
    toTypes: [ENTITY_TYPE_ATTACK_PATTERN],
    baseData: true,
    baseFields: ['confidence', 'revoked'],
    withInferences: true,
  };
  // A revoked usage is withdrawn knowledge: it no longer puts the technique in the overlay
  if (!threatIds) {
    return (await fullRelationsList<BasicStoreRelation>(context, user, RELATION_USES, args)).filter((relation) => !relation.revoked);
  }
  const relations: BasicStoreRelation[] = [];
  const chunks = R.splitEvery(IDS_CHUNK_SIZE, threatIds);
  for (let index = 0; index < chunks.length; index += 1) {
    const found = await fullRelationsList<BasicStoreRelation>(context, user, RELATION_USES, { ...args, fromId: chunks[index] });
    relations.push(...found);
  }
  return relations.filter((relation) => !relation.revoked);
};

// A revoked threat leaves every scope: the SELECTED and FILTERED scopes drop it from their threats
const resolveScopeThreatIds = async (context: AuthContext, user: AuthUser, scope: DefenseThreatScope): Promise<string[] | undefined> => {
  if (scope.mode === 'SELECTED') {
    const found = await internalFindByIds<BasicStoreEntity>(context, user, scope.threatIds ?? [], { type: DEFENSE_THREAT_TYPES, baseData: true, baseFields: ['revoked'] }) as BasicStoreEntity[];
    return found.filter((f) => !f.revoked).map((f) => f.internal_id);
  }
  if (scope.mode === 'FILTERED') {
    // Every matching threat counts: the listing is paginated to the end, as the uses relationships of the
    // ALL scope are, and their usages are then loaded by chunks of ids
    const threats = await fullEntitiesList<BasicStoreEntity>(context, user, DEFENSE_THREAT_TYPES, {
      filters: scope.filters as never,
      baseData: true,
      baseFields: ['revoked'],
    } as never);
    return threats.filter((t) => !t.revoked).map((t) => t.internal_id);
  }
  return undefined;
};

// The ALL scope reads every usage at once: the revoked threats it leaves out are listed to drop their usages and count
const loadRevokedThreatIds = async (context: AuthContext, user: AuthUser) => {
  const revoked = await fullEntitiesList<BasicStoreEntity>(context, user, DEFENSE_THREAT_TYPES, {
    filters: { mode: FilterMode.And, filters: [{ key: ['revoked'], values: ['true'] }], filterGroups: [] },
    baseData: true,
  } as never);
  return new Set(revoked.map((threat) => threat.internal_id));
};

const computeOverlay = async (context: AuthContext, user: AuthUser, scope: DefenseThreatScope): Promise<DefenseThreatOverlay> => {
  const computedAt = new Date().toISOString();
  if (scope.mode === 'NONE') {
    return { computed_at: computedAt, threats_count: 0, usages: new Map() };
  }
  const threatIds = await resolveScopeThreatIds(context, user, scope);
  const revokedIds = threatIds ? new Set<string>() : await loadRevokedThreatIds(context, user);
  // The ALL scope holds every threat the reader can access that is not revoked, those that use no technique yet
  // included, as the other scopes count every threat they match
  const threatsCount = threatIds
    ? threatIds.length
    : Math.max(0, await elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, { types: DEFENSE_THREAT_TYPES }) - revokedIds.size);
  if (threatsCount === 0) {
    return { computed_at: computedAt, threats_count: 0, usages: new Map() };
  }
  const relations = (await loadThreatUsages(context, user, threatIds)).filter((relation) => !revokedIds.has(relation.fromId));
  const usages = new Map<string, DefenseThreatUsage[]>();
  relations.forEach((relation) => {
    const usage: DefenseThreatUsage = {
      threat_id: relation.fromId,
      relationship_id: relation.internal_id,
      confidence: (relation as unknown as { confidence?: number }).confidence ?? 0,
    };
    const list = usages.get(relation.toId);
    if (list) list.push(usage);
    else usages.set(relation.toId, [usage]);
  });
  return { computed_at: computedAt, threats_count: threatsCount, usages };
};

/**
 * Techniques used by the threats of the scope, restricted to the threats and relationships the reader can access.
 * Computed on demand and cached per reader grants, scope and version of the threat usages (a uses relationship or the
 * access to a threat changed), so that a reader never keeps a usage they can no longer see. A filtered scope is also
 * keyed by the version of the threats: any change of a threat or of its relationships can change which threats match.
 */
export const getThreatOverlay = async (context: AuthContext, user: AuthUser, scope?: DefenseThreatScope | null): Promise<DefenseThreatOverlay> => {
  const normalized = normalizeScope(scope);
  const version = await getDefenseOverlayVersion();
  const threatsVersion = normalized.mode === 'FILTERED' ? await getDefenseThreatsVersion() : '';
  const key = `${version}|${threatsVersion}|${await computeReaderAccessFingerprint(context, user)}|${JSON.stringify(normalized)}`;
  let promise = overlayCache.get(key);
  if (!promise) {
    const { publishedContext, publishedUser } = publishedReader(context, user);
    promise = computeOverlay(publishedContext, publishedUser, normalized);
    overlayCache.set(key, promise);
    promise.catch(() => overlayCache.delete(key));
  }
  return promise;
};
// endregion
