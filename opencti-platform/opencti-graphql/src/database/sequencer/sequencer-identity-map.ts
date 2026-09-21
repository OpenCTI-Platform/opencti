// POC ingestion sequencer (plan 0009, Stage C3/C5). Two-level identity map:
//   - bare entries: the elFindByIds hit (_source without rel_*, plus the security docvalues
//     merged by elConvertHits). Enough for reference resolution and access filtering.
//   - with-refs entries: the storeLoadByIdsWithRefs result, i.e. the upsert diff basis.
// Keyed by EVERY instance id (getInstanceIds: internal_id, standard_id, x_opencti_stix_ids,
// alias ids, hash ids) through a secondary index id -> internal_id, so eviction by any id
// removes the element and all its keys. Elements are cached UNRESTRICTED (resolved as
// SYSTEM_USER); every serve applies userFilterStoreElements in memory (D12: equivalence with
// the ES-side restriction is audited at productization; the bench runs one ingestion user).
// LRU bounded by identity_map_size, TTL identity_map_ttl_s as backstop invalidation.
// Invalidation layers (C5): own writes evicted by the loop (D4a), cross-process edits/deletes
// via the EDIT/DELETE pub/sub topics (cacheManager pattern; never ADDED, it fires on no-ops),
// merges partially covered by the EDIT event on the post-merge target (its x_opencti_stix_ids
// then include the absorbed sources' stix ids, so their keys cascade-evict; remaining source
// keys age out by TTL until the Stage D merge barrier evicts explicitly), TTL last.
// Written index (2026-09-21, knob identity_map_written_index): the elements the RUNNING batch
// applied are also pinned in a batch-local index, consulted first and immune to invalidation,
// barrier clears, LRU and TTL until the loop drops it at commit. Under the batch lock the
// sequencer is the single writer of those keys: a mid-batch invalidation of an own write is
// the previous batch's own event coming back through pub/sub, or an external actor racing the
// lock; both re-read from ES at the next batch anyway. Same single-writer caveat as the
// negative cache below.
import { getInstanceIds } from '../../schema/identifier';
import { BASE_TYPE_RELATION } from '../../schema/general';
import { extractEntityRepresentativeName } from '../entity-representative';
import { userFilterStoreElements } from '../../utils/access';
import { getDraftContext } from '../../utils/draftContext';
import { TOPIC_PREFIX, logApp } from '../../config/conf';
import { pubSubSubscription } from '../redis';
import { registerSequencerBarrier } from './sequencer-barrier';
import { SEQUENCER_CONFIG } from './sequencer-config';
import { sequencerMetrics } from './sequencer-metrics';
import type { AuthContext, AuthUser } from '../../types/user';

interface MapEntry {
  element: any;
  withRefs: any | null;
  expiresAt: number;
  keys: string[];
}

const typeMatches = (element: any, types: string[] | null | undefined) => {
  if (!types || types.length === 0) return true;
  if (types.includes(element.entity_type)) return true;
  const parents: string[] = element.parent_types ?? [];
  return types.some((t) => parents.includes(t));
};

export class SequencerIdentityMap {
  // insertion order doubles as LRU order (entries are re-inserted on touch)
  private byInternalId = new Map<string, MapEntry>();

  private idIndex = new Map<string, string>();

  // s10.3 rung 1: per-BATCH negative cache. Ids probed against ES at pre-resolve and not
  // found are KNOWN ABSENT for the batch lifetime: the batch lock is the single writer for
  // those keys, so the apply-time existence checks can be answered from memory instead of
  // paying a guaranteed-negative ES search per creation. absentGlobal = probed with no type
  // filter (absence is unconditional); absentTyped = probed under a type-union filter, and
  // servable only to a query whose own type filter is a SUBSET of that union (a broader
  // probe returning nothing implies any narrower query returns nothing; the converse does
  // not hold). Cleared at every batch boundary; any ingest of an element removes its keys.
  // CAVEAT (recorded in plan 0010): valid under the single-sequencer topology; a
  // multi-replica deployment would need the probe to run under the batch lock.
  private absentGlobal = new Set<string>();

  private absentTyped = new Map<string, string[]>();

  // written index: entries applied by the running batch, by internal id, plus id -> internal id
  private written = new Map<string, MapEntry>();

  private writtenIndex = new Map<string, string>();

  size() {
    return this.byInternalId.size;
  }

  private removeEntry(internalId: string) {
    const entry = this.byInternalId.get(internalId);
    if (!entry) return;
    entry.keys.forEach((k) => this.idIndex.delete(k));
    this.byInternalId.delete(internalId);
  }

  private lookup(id: string): MapEntry | undefined {
    if (SEQUENCER_CONFIG.writtenIndex) {
      const writtenInternalId = this.writtenIndex.get(id);
      const writtenEntry = writtenInternalId ? this.written.get(writtenInternalId) : undefined;
      if (writtenEntry) {
        sequencerMetrics.mapEvent('written_hit');
        return writtenEntry;
      }
    }
    const internalId = this.idIndex.get(id);
    if (!internalId) return undefined;
    const entry = this.byInternalId.get(internalId);
    if (!entry) return undefined;
    if (entry.expiresAt < Date.now()) {
      this.removeEntry(internalId);
      sequencerMetrics.mapEvent('evict');
      return undefined;
    }
    // LRU touch
    this.byInternalId.delete(internalId);
    this.byInternalId.set(internalId, entry);
    return entry;
  }

  private store(element: any, withRefs: any | null) {
    const internalId = element.internal_id;
    if (!internalId) return;
    // Memory-served elements must be ES-shaped: consumers key on `_id` (the ES doc id,
    // which IS the internal id in every OpenCTI index). An apply result is built in
    // memory and lacks it; without it the creation path's second inputResolveRefs
    // (middleware isAlreadyResolved) treats already-resolved refs as raw ids and sends
    // OBJECTS to elFindByIds (found live 2026-09-01, run ch16-d: every co-batched
    // container create rejected DATABASE_ERROR, plan 0009 s9.9.6).
    if (!element._id) element._id = internalId;
    // Same ES-shaping contract, second gap (CS>=24 grid 2026-09-08): a relation CREATION
    // result is memory-built (data-builder) and carries the resolved from/to instances but
    // NOT the loader-synthesized fromName/toName (elBuildRelation reads them off the
    // indexed connections). A later intent resolving this relation as the TARGET of a
    // denormalized connection (report object ref co-batched with its relation) then
    // templates the literal string "undefined ➡️ undefined" into the stored connection
    // name. Synthesize the loader fields so memory-served relations are indistinguishable
    // from ES-loaded ones.
    if (element.base_type === BASE_TYPE_RELATION) {
      if (element.fromName === undefined && element.from) {
        element.fromName = extractEntityRepresentativeName(element.from);
      }
      if (element.toName === undefined && element.to) {
        element.toName = extractEntityRepresentativeName(element.to);
      }
    }
    const previous = this.byInternalId.get(internalId);
    if (previous) this.removeEntry(internalId);
    const keys = getInstanceIds(element);
    const entry: MapEntry = {
      element,
      // a fresh bare ingest keeps a previous with-refs basis only if explicitly re-given
      withRefs: withRefs ?? previous?.withRefs ?? null,
      expiresAt: Date.now() + SEQUENCER_CONFIG.identityMapTtlS * 1000,
      keys,
    };
    this.byInternalId.set(internalId, entry);
    keys.forEach((k) => {
      this.idIndex.set(k, internalId);
      // an ingested element is no longer absent under any of its keys
      this.absentGlobal.delete(k);
      this.absentTyped.delete(k);
    });
    while (this.byInternalId.size > SEQUENCER_CONFIG.identityMapSize) {
      const oldest = this.byInternalId.keys().next().value as string;
      this.removeEntry(oldest);
      sequencerMetrics.mapEvent('evict');
    }
  }

  ingestBare(elements: any[]) {
    elements.forEach((e) => this.store(e, null));
  }

  ingestWithRefs(element: any) {
    this.store(element, element);
  }

  // Apply result of the running batch (read-your-writes for its later intents, E2). With the
  // written index on, the entry is also pinned batch-locally until clearWritten().
  ingestWritten(element: any, withRefsBasis: boolean) {
    this.store(element, withRefsBasis ? element : null);
    if (!SEQUENCER_CONFIG.writtenIndex) return;
    const internalId = element.internal_id;
    const entry = internalId ? this.byInternalId.get(internalId) : undefined;
    if (!entry) return;
    const previous = this.written.get(internalId);
    if (previous) previous.keys.forEach((k) => this.writtenIndex.delete(k));
    this.written.set(internalId, entry);
    entry.keys.forEach((k) => this.writtenIndex.set(k, internalId));
  }

  clearWritten() {
    this.written.clear();
    this.writtenIndex.clear();
  }

  writtenSize() {
    return this.written.size;
  }

  evict(ids: string[], reason: 'write' | 'invalidate' = 'invalidate') {
    const internalIds = new Set<string>();
    ids.forEach((id) => {
      const internalId = this.idIndex.get(id) ?? this.writtenIndex.get(id);
      if (internalId) internalIds.add(internalId);
    });
    internalIds.forEach((internalId) => {
      if (reason === 'invalidate' && SEQUENCER_CONFIG.writtenIndex && this.written.has(internalId)) {
        // an own write of the running batch: shielded until the loop's commit-time evict
        sequencerMetrics.mapEvent('written_shielded');
        return;
      }
      this.removeEntry(internalId);
      if (reason === 'write') {
        const pinned = this.written.get(internalId);
        if (pinned) {
          pinned.keys.forEach((k) => this.writtenIndex.delete(k));
          this.written.delete(internalId);
        }
      }
      sequencerMetrics.mapEvent(reason === 'write' ? 'evict' : 'invalidate');
    });
  }

  hasBare(id: string) {
    return this.lookup(id) !== undefined;
  }

  markAbsent(ids: string[], probedTypes: string[] | null) {
    ids.forEach((id) => {
      if (this.lookup(id)) return; // presence always wins
      if (!probedTypes || probedTypes.length === 0) this.absentGlobal.add(id);
      else if (!this.absentGlobal.has(id)) this.absentTyped.set(id, probedTypes);
    });
  }

  isKnownAbsent(id: string, types: string[] | null): boolean {
    if (this.absentGlobal.has(id)) return true;
    const probed = this.absentTyped.get(id);
    if (!probed) return false;
    // a typed probe only proves absence for queries at least as narrow as the probe
    if (!types || types.length === 0) return false;
    return types.every((t) => probed.includes(t));
  }

  clearAbsent() {
    this.absentGlobal.clear();
    this.absentTyped.clear();
  }

  // P2 chaining (plan 0009 s9.7): the loop re-ingests an applied result with-refs only when
  // a with-refs basis already existed (the element predates the batch), so the next chain
  // step diffs against it; a creation result is never a valid basis.
  hasWithRefs(id: string) {
    const entry = this.lookup(id);
    return entry !== undefined && entry.withRefs !== null;
  }

  resolveInternalId(id: string): string | null {
    const entry = this.lookup(id);
    return entry ? entry.element.internal_id : null;
  }

  // Loop-internal read (lock key set, plan building): no metrics, no user filtering.
  peekBare(id: string): any | null {
    const entry = this.lookup(id);
    return entry ? entry.element : null;
  }

  clear() {
    const count = this.byInternalId.size;
    this.byInternalId.clear();
    this.idIndex.clear();
    this.clearAbsent();
    if (count > 0) sequencerMetrics.mapEvent('invalidate', count);
    // the written index is batch-local: it survives a whole-map clear, the loop drops it at commit
    if (this.written.size > 0) sequencerMetrics.mapEvent('written_shielded', this.written.size);
  }

  // Serve hook called from elFindByIds through context.sequencer.resolutions (no import in
  // engine.ts). Returns null when the map cannot answer for these opts; otherwise the served
  // hits (user-filtered) and the ids to send to ES.
  async serveBare(context: AuthContext, user: AuthUser, ids: string[], opts: {
    type?: string | string[] | null;
    withoutRels?: boolean | null;
    relCount?: boolean | null;
    historyFiltering?: boolean;
    includeDeletedInDraft?: boolean | null;
  }): Promise<{ hits: any[]; misses: string[] } | null> {
    if (SEQUENCER_CONFIG.mode !== 'batch') return null;
    if (opts.withoutRels === false || opts.relCount || opts.historyFiltering || opts.includeDeletedInDraft) return null;
    if (getDraftContext(context, user)) return null;
    const types = opts.type ? (Array.isArray(opts.type) ? opts.type : [opts.type]) : null;
    const servedByInternalId = new Map<string, any>();
    const misses: string[] = [];
    ids.forEach((id) => {
      const entry = this.lookup(id);
      if (entry && typeMatches(entry.element, types)) {
        sequencerMetrics.mapEvent('hit');
        servedByInternalId.set(entry.element.internal_id, entry.element);
      } else if (this.isKnownAbsent(id, types)) {
        // s10.3: known absent under the batch lock: no hit, and NOT sent to ES either
        sequencerMetrics.mapEvent('absent');
      } else {
        sequencerMetrics.mapEvent('miss');
        misses.push(id);
      }
    });
    if (servedByInternalId.size === 0) return { hits: [], misses };
    // In-memory access filtering, same function the SYSTEM_USER existence check applies (D12).
    const filtered = await userFilterStoreElements(context, user, Array.from(servedByInternalId.values()));
    return { hits: filtered, misses };
  }

  async serveWithRefs(context: AuthContext, user: AuthUser, ids: string[], opts: {
    type?: string | string[] | null;
  }): Promise<{ hits: any[]; misses: string[] } | null> {
    if (SEQUENCER_CONFIG.mode !== 'batch') return null;
    if (getDraftContext(context, user)) return null;
    const types = opts.type ? (Array.isArray(opts.type) ? opts.type : [opts.type]) : null;
    const served = new Map<string, any>();
    const misses: string[] = [];
    ids.forEach((id) => {
      const entry = this.lookup(id);
      if (entry && entry.withRefs && typeMatches(entry.element, types)) {
        sequencerMetrics.mapEvent('hit');
        served.set(entry.element.internal_id, entry.withRefs);
      } else {
        sequencerMetrics.mapEvent('miss');
        misses.push(id);
      }
    });
    if (served.size === 0) return { hits: [], misses };
    const filtered = await userFilterStoreElements(context, user, Array.from(served.values()));
    return { hits: filtered, misses };
  }
}

export const sequencerIdentityMap = new SequencerIdentityMap();

// D6: identity-changing operations (merge, rename update_by_query, raw update-by-query,
// delete) evict every involved id at their entry; an unknown scope clears the whole map.
registerSequencerBarrier((ids) => {
  if (ids && ids.length > 0) sequencerIdentityMap.evict(ids);
  else if (!ids) sequencerIdentityMap.clear();
});

// C5 layer 2: cross-process edits/deletes through the existing pub/sub topics. ADDED is NOT
// subscribed: it fires on every worker mutation, no-op upserts included.
let invalidationStarted = false;
export const startIdentityMapInvalidation = async () => {
  if (invalidationStarted) return;
  invalidationStarted = true;
  const EDITS_TOPIC = `${TOPIC_PREFIX}*EDIT_TOPIC`;
  const DELETES_TOPIC = `${TOPIC_PREFIX}*DELETE_TOPIC`;
  const onEvent = (event: { instance?: any }) => {
    if (event?.instance) sequencerIdentityMap.evict(getInstanceIds(event.instance));
  };
  await pubSubSubscription<{ instance: any }>(EDITS_TOPIC, onEvent);
  await pubSubSubscription<{ instance: any }>(DELETES_TOPIC, onEvent);
  logApp.info('[SEQUENCER] Identity map invalidation subscribed (EDIT/DELETE topics)');
};
