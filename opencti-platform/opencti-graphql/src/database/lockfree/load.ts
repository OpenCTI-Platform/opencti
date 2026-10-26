// Reads of the lock-free path. Everything goes through realtime gets by id, which see writes before any
// refresh, and comes back in the platform's own store shape (elConvertHits), so the platform's rules can run
// on it unchanged.
import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import { elRawMget } from '../../database/engine';
import { elConvertHits } from '../../database/engine-data-converter';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { SYSTEM_USER, userFilterStoreElements } from '../../utils/access';
import { internalFindByIds } from '../middleware-loader';
import { getInstanceIds } from '../../schema/identifier';
import { schemaTypesDefinition } from '../../schema/schema-types';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, buildRefRelationKey } from '../../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { pool } from './context';
import { lookupKeys, type Owner } from './identity';
import { versionOf } from './unchanged';

// `partial`: read without the lists of relationships (see mgetRaw's `withoutLists`)
export interface RawDoc { _index: string; _id: string; _seq_no: number; _primary_term: number; _source: Record<string, any>; partial?: boolean }

// The fields listing an entity's core relationships and sightings (rel_indicates, rel_uses...): on a busy entity,
// hundreds of thousands of ids, which the merge rules never read (they read the refs: rel_created-by,
// rel_object-marking...)
let relationshipLists: string[] | undefined;
const relationshipListFields = () => {
  relationshipLists ??= [...schemaTypesDefinition.get(ABSTRACT_STIX_CORE_RELATIONSHIP), STIX_SIGHTING_RELATIONSHIP]
    .flatMap((type) => [buildRefRelationKey(type, '*'), `rel_${type}`]);
  return relationshipLists;
};

// Raw documents by (index, id), realtime. `light` leaves out every rel_* field; `withoutLists` only the lists of
// relationships, keeping the refs (the document is then marked partial: written back from a full read)
export const mgetRaw = async (
  refs: { index: string; id: string }[],
  opts: { light?: boolean; withoutLists?: boolean } = {},
): Promise<Map<string, RawDoc>> => {
  const found = new Map<string, RawDoc>();
  const unique = R.uniqBy((r) => `${r.index}|${r.id}`, refs);
  let excludes: string[] | undefined;
  if (opts.light) excludes = ['rel_*'];
  else if (opts.withoutLists) excludes = relationshipListFields();
  await pool(R.splitEvery(1000, unique), 4, async (slice) => {
    const response: any = await elRawMget({
      docs: slice.map((r) => ({ _index: r.index, _id: r.id, ...(excludes ? { _source: { excludes } } : {}) })),
    });
    response.docs.filter((d: any) => d.found).forEach((d: any) => found.set(d._id, opts.withoutLists ? { ...d, partial: true } : d));
  });
  return found;
};

// Store elements (the platform's shape) from raw documents; the raw document stays attached for the write back
export const toElements = async (raws: RawDoc[]) => {
  const copies = raws.map((raw) => ({ _index: raw._index, _id: raw._id, _source: structuredClone(raw._source) }));
  const elements: any[] = await elConvertHits(copies);
  return elements.map((element, i) => Object.assign(element, { i_raw: raws[i] }));
};

// Owners of keys that are live
export const liveOwners = async (keys: string[]) => {
  const owners = await lookupKeys(keys.filter(Boolean).map((k) => k.toLowerCase()));
  return { owners, live: R.uniqBy((o: Owner) => o.owner_id, [...owners.values()].filter((o) => o.state === 'live')) };
};

// Elements by any of their ids (internal, standard, STIX, alias, hash), realtime
export const loadByAnyIds = async (ids: string[], opts: { light?: boolean } = {}) => {
  const { live } = await liveOwners(ids);
  const raws = await mgetRaw(live.map((o) => ({ index: o.owner_index, id: o.owner_id })), opts);
  return toElements([...raws.values()]);
};

// Ids the identity index does not lead to (an object today's path wrote that it was not told about) are looked up as
// today's path looks them up: today's writes are refreshed, so its search sees them
export const findUnknownBySearch = async (context: AuthContext, ids: string[], found: any[]) => {
  const known = new Set(found.flatMap((e) => getInstanceIds(e).map((id: string) => id.toLowerCase())));
  const unknown = ids.filter((id) => id && !known.has(id.toLowerCase()));
  if (unknown.length === 0) return [];
  return internalFindByIds(context, SYSTEM_USER, unknown) as Promise<any[]>;
};

// The finder handed to inputResolveRefs: same contract as internalFindByIds(context, user, ids), the user's access
// filter included, but realtime
export const makeFinder = (context: AuthContext, user: AuthUser) => async (ids: string[]) => {
  const elements = await loadByAnyIds(ids, { light: true });
  const searched = await findUnknownBySearch(context, ids, elements);
  return userFilterStoreElements(context, user, [...elements, ...searched]);
};

// The ids an element's refs (and a relationship's ends) point to
const refIdsOf = (element: any): string[] => {
  const refs = schemaRelationsRefDefinition.getRelationsRef(element.entity_type);
  const refIds: string[] = refs.flatMap((ref) => ([] as string[]).concat(element[ref.databaseName] ?? []));
  return R.uniq([...refIds, ...(element.fromId ? [element.fromId, element.toId] : [])]);
};

// The element with each ref input holding the referenced elements, from the loaded ones
const attachRefs = (element: any, loaded: any[]) => {
  const refs = schemaRelationsRefDefinition.getRelationsRef(element.entity_type);
  const resolved = new Map<string, any>(loaded.map((e) => [e.internal_id, e]));
  const out: any = { ...element };
  refs.forEach((ref) => {
    const value = element[ref.databaseName];
    if (value === undefined || value === null) return;
    if (ref.multiple) out[ref.name] = [].concat(value).map((id: string) => resolved.get(id)).filter(Boolean);
    else out[ref.name] = resolved.get(value);
  });
  if (element.fromId) {
    out.from = resolved.get(element.fromId);
    out.to = resolved.get(element.toId);
  }
  return out;
};

// An element with its refs resolved, as storeLoadByIdWithRefs returns it: each ref input (createdBy,
// objectMarking, objectLabel, externalReferences, objects...) holds the referenced elements, and a relationship
// holds its from and to
export const loadWithRefs = async (context: AuthContext, user: AuthUser, element: any) => {
  const ids = refIdsOf(element);
  return attachRefs(element, ids.length > 0 ? await loadByAnyIds(ids, { light: true }) : []);
};

// The existing objects a chunk merges into, read once for the chunk (their documents, then the refs of all of
// them) instead of once per object. Each use gets its own copy, as a read of its own. A document stands for its
// object until the chunk writes to it: once written, the object is read again, as one by one.
export class ChunkReads {
  private raws = new Map<string, RawDoc>();

  private owners = new Map<string, Owner>(); // owners of the documents and of their refs, by lowercased id

  private looked = new Set<string>(); // lowercased ids whose owner was looked up

  private refRaws = new Map<string, RawDoc>();

  private fresh = new Map<string, any>(); // documents converted by the read and not handed out yet

  async load(targets: { index: string; id: string }[]) {
    await this.loadDocuments(targets);
    await this.loadRefs(targets.map((t) => t.id));
  }

  // The documents only: their versions, before deciding which ones need their refs
  async loadDocuments(targets: { index: string; id: string }[]) {
    if (targets.length === 0) return;
    const [{ owners }, raws] = await Promise.all([liveOwners(targets.map((t) => t.id)), mgetRaw(targets, { withoutLists: true })]);
    owners.forEach((owner, key) => this.owners.set(key, owner));
    targets.forEach((t) => this.looked.add(t.id.toLowerCase()));
    raws.forEach((raw, id) => this.raws.set(id, raw));
  }

  // The refs of loaded documents, for all of them at once
  async loadRefs(ids: string[]) {
    const raws = ids.map((id) => this.raws.get(id)).filter((r): r is RawDoc => r !== undefined && !this.fresh.has(r._id));
    if (raws.length === 0) return;
    const elements = await toElements(raws);
    elements.forEach((element) => this.fresh.set(element.internal_id, element));
    const refIds = R.uniq(elements.flatMap(refIdsOf)).map((id) => id.toLowerCase());
    const refOwners = await lookupKeys(refIds);
    refOwners.forEach((owner, key) => this.owners.set(key, owner));
    refIds.forEach((id) => this.looked.add(id));
    const live = R.uniqBy((o: Owner) => o.owner_id, [...refOwners.values()].filter((o) => o.state === 'live'));
    (await mgetRaw(live.map((o) => ({ index: o.owner_index, id: o.owner_id })), { light: true })).forEach((raw, id) => this.refRaws.set(id, raw));
  }

  // The version of the object's document as read; undefined when the chunk did not read it or wrote to it since
  version(id: string) {
    const raw = this.raws.get(id);
    return raw ? versionOf(raw) : undefined;
  }

  // Whether the id leads to a live object, as liveOwners tells it
  isLive(id: string) {
    return this.owners.get(id.toLowerCase())?.state === 'live';
  }

  // The object's document, the element and the element with its refs (as loadWithRefs); undefined when the
  // chunk did not read it or wrote to it since
  async take(id: string) {
    const raw = this.raws.get(id);
    if (!raw) return undefined;
    let element = this.fresh.get(id);
    this.fresh.delete(id);
    if (!element) [element] = await toElements([raw]);
    const ids = refIdsOf(element);
    const unread = ids.filter((refId) => !this.looked.has(refId.toLowerCase()));
    const live = R.uniqBy((o: Owner) => o.owner_id, ids.map((refId) => this.owners.get(refId.toLowerCase())).filter((o): o is Owner => o?.state === 'live'));
    const refs = [
      ...await toElements(live.map((o) => this.refRaws.get(o.owner_id)).filter((r): r is RawDoc => r !== undefined)),
      ...(unread.length > 0 ? await loadByAnyIds(unread, { light: true }) : []),
    ];
    return { raw, element, withRefs: attachRefs(element, refs) };
  }

  // The chunk wrote to the object: its document no longer stands for it
  written(id: string) {
    this.raws.delete(id);
    this.fresh.delete(id);
  }
}
