// Reads of the lock-free path. Everything goes through realtime gets by id, which see writes before any
// refresh, and comes back in the platform's own store shape (elConvertHits), so the platform's rules can run
// on it unchanged.
import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import { elRawMget } from '../../database/engine';
import { elConvertHits } from '../../database/engine-data-converter';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { SYSTEM_USER } from '../../utils/access';
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

interface DocRef { index: string; id: string }

interface MgetResponse { docs: (RawDoc & { found: boolean })[] }

interface MgetOptions { light?: boolean; withoutLists?: boolean }

const MGET_BATCH_SIZE = 1000;
const MGET_CONCURRENCY = 4;

const isDefined = <T>(value: T | undefined): value is T => value !== undefined;

// Where an owner's document lives
const documentOf = (owner: Owner): DocRef => ({ index: owner.owner_index, id: owner.owner_id });

// The live owners among `owners`, each object once
const uniqueLiveOwners = (owners: (Owner | undefined)[]): Owner[] => {
  const live = owners.filter((owner): owner is Owner => owner?.state === 'live');
  return R.uniqBy((owner) => owner.owner_id, live);
};

// The fields listing an entity's core relationships and sightings (rel_indicates, rel_uses...): on a busy entity,
// hundreds of thousands of ids, which the merge rules never read (they read the refs: rel_created-by,
// rel_object-marking...)
let relationshipLists: string[] | undefined;
const relationshipListFields = () => {
  relationshipLists ??= [...schemaTypesDefinition.get(ABSTRACT_STIX_CORE_RELATIONSHIP), STIX_SIGHTING_RELATIONSHIP]
    .flatMap((type) => [buildRefRelationKey(type, '*'), `rel_${type}`]);
  return relationshipLists;
};

const sourceExcludes = (opts: MgetOptions): string[] | undefined => {
  if (opts.light) return ['rel_*'];
  if (opts.withoutLists) return relationshipListFields();
  return undefined;
};

// Raw documents by (index, id), realtime, keyed by _id. `light` leaves out every rel_* field; `withoutLists` only
// the lists of relationships, keeping the refs (the document is then marked partial: written back from a full read)
export const mgetRaw = async (refs: DocRef[], opts: MgetOptions = {}): Promise<Map<string, RawDoc>> => {
  const found = new Map<string, RawDoc>();
  const uniqueRefs = R.uniqBy((ref) => `${ref.index}|${ref.id}`, refs);
  const excludes = sourceExcludes(opts);
  const sourceFilter = excludes ? { _source: { excludes } } : {};
  await pool(R.splitEvery(MGET_BATCH_SIZE, uniqueRefs), MGET_CONCURRENCY, async (batch) => {
    const response: MgetResponse = await elRawMget({ docs: batch.map((ref) => ({ _index: ref.index, _id: ref.id, ...sourceFilter })) });
    response.docs.filter((doc) => doc.found).forEach((doc) => {
      found.set(doc._id, opts.withoutLists ? { ...doc, partial: true } : doc);
    });
  });
  return found;
};

// Store elements (the platform's shape) from raw documents; the raw document stays attached (i_raw) for the write back
export const toElements = async (raws: RawDoc[], opts: { owned?: boolean } = {}): Promise<any[]> => {
  // `owned`: the documents are read only to be looked at, never written back: converted in place, without a copy
  // and without the raw document (a container's objects can be hundreds of thousands)
  if (opts.owned) return elConvertHits(raws) as Promise<any[]>;
  const copies = raws.map((raw) => ({ _index: raw._index, _id: raw._id, _source: structuredClone(raw._source) }));
  const elements: any[] = await elConvertHits(copies);
  return elements.map((element, position) => Object.assign(element, { i_raw: raws[position] }));
};

// Owners of keys, by lowercased key, and the live ones among them, each object once
export const liveOwners = async (keys: string[]) => {
  const owners = await lookupKeys(keys.filter(Boolean).map((key) => key.toLowerCase()));
  return { owners, live: uniqueLiveOwners([...owners.values()]) };
};

// Elements by any of their ids (internal, standard, STIX, alias, hash), realtime
export const loadByAnyIds = async (ids: string[], opts: { light?: boolean } = {}) => {
  const { live } = await liveOwners(ids);
  const raws = await mgetRaw(live.map(documentOf), opts);
  return toElements([...raws.values()]);
};

// Ids the identity index does not lead to (an object today's path wrote that it was not told about) are looked up as
// today's path looks them up: today's writes are refreshed, so its search sees them
export const findUnknownBySearch = async (context: AuthContext, ids: string[], found: any[]) => {
  const knownIds = new Set(found.flatMap((element) => getInstanceIds(element).map((id: string) => id.toLowerCase())));
  const unknownIds = ids.filter((id) => id && !knownIds.has(id.toLowerCase()));
  if (unknownIds.length === 0) return [];
  return internalFindByIds(context, SYSTEM_USER, unknownIds) as Promise<any[]>;
};

// The ids an element's refs (and a relationship's ends) point to
const refIdsOf = (element: any): string[] => {
  const refs = schemaRelationsRefDefinition.getRelationsRef(element.entity_type);
  const refIds = refs.flatMap((ref) => ([] as string[]).concat(element[ref.databaseName] ?? []));
  const endIds = element.fromId ? [element.fromId, element.toId] : [];
  return R.uniq([...refIds, ...endIds]);
};

// The element with each ref input holding the referenced elements, from the loaded ones
const attachRefs = (element: any, loaded: any[]) => {
  const refs = schemaRelationsRefDefinition.getRelationsRef(element.entity_type);
  const loadedById = new Map<string, any>(loaded.map((loadedElement) => [loadedElement.internal_id, loadedElement]));
  const withRefs: any = { ...element };
  refs.forEach((ref) => {
    const value = element[ref.databaseName];
    if (value === undefined || value === null) return;
    if (ref.multiple) {
      withRefs[ref.name] = ([] as string[]).concat(value).map((id) => loadedById.get(id)).filter(Boolean);
    } else {
      withRefs[ref.name] = loadedById.get(value);
    }
  });
  if (element.fromId) {
    withRefs.from = loadedById.get(element.fromId);
    withRefs.to = loadedById.get(element.toId);
  }
  return withRefs;
};

// An element with its refs resolved, as storeLoadByIdWithRefs returns it: each ref input (createdBy,
// objectMarking, objectLabel, externalReferences, objects...) holds the referenced elements, and a relationship
// holds its from and to
export const loadWithRefs = async (context: AuthContext, user: AuthUser, element: any) => {
  const refIds = refIdsOf(element);
  const refs = refIds.length > 0 ? await loadByAnyIds(refIds, { light: true }) : [];
  return attachRefs(element, refs);
};

// The existing objects a chunk merges into, read once for the chunk (their documents, then the refs of all of
// them) instead of once per object. Each use gets its own copy, as a read of its own. A document stands for its
// object until the chunk writes to it: once written, the object is read again, as one by one.
export class ChunkReads {
  // The objects' documents, without their lists of relationships, by _id
  private documents = new Map<string, RawDoc>();

  // Owners of the documents and of their refs, by lowercased id
  private owners = new Map<string, Owner>();

  // Lowercased ids whose owner was looked up, found or not
  private lookedUpIds = new Set<string>();

  // The refs' documents (light), by _id
  private refDocuments = new Map<string, RawDoc>();

  // Elements converted by loadRefs and not handed out by take yet, by internal id
  private convertedNotTaken = new Map<string, any>();

  async load(targets: DocRef[]) {
    await this.loadDocuments(targets);
    await this.loadRefs(targets.map((target) => target.id));
  }

  // The documents only: their versions, before deciding which ones need their refs
  async loadDocuments(targets: DocRef[]) {
    if (targets.length === 0) return;
    const [{ owners }, raws] = await Promise.all([
      liveOwners(targets.map((target) => target.id)),
      mgetRaw(targets, { withoutLists: true }),
    ]);
    this.recordLookup(owners, targets.map((target) => target.id.toLowerCase()));
    raws.forEach((raw, id) => this.documents.set(id, raw));
  }

  // The refs of loaded documents, for all of them at once
  async loadRefs(ids: string[]) {
    const raws = ids
      .map((id) => this.documents.get(id))
      .filter((raw): raw is RawDoc => raw !== undefined && !this.convertedNotTaken.has(raw._id));
    if (raws.length === 0) return;
    const elements = await toElements(raws);
    elements.forEach((element) => this.convertedNotTaken.set(element.internal_id, element));
    const refIds = R.uniq(elements.flatMap(refIdsOf)).map((id) => id.toLowerCase());
    const refOwners = await lookupKeys(refIds);
    this.recordLookup(refOwners, refIds);
    const refRaws = await mgetRaw(uniqueLiveOwners([...refOwners.values()]).map(documentOf), { light: true });
    refRaws.forEach((raw, id) => this.refDocuments.set(id, raw));
  }

  // The version of the object's document as read; undefined when the chunk did not read it or wrote to it since
  version(id: string) {
    const raw = this.documents.get(id);
    return raw ? versionOf(raw) : undefined;
  }

  // Whether the id leads to a live object, as liveOwners tells it
  isLive(id: string) {
    return this.owners.get(id.toLowerCase())?.state === 'live';
  }

  // The object's document, the element and the element with its refs (as loadWithRefs); undefined when the
  // chunk did not read it or wrote to it since
  async take(id: string) {
    const raw = this.documents.get(id);
    if (!raw) return undefined;
    const element = await this.takeElement(id, raw);
    const refs = await this.refsOf(element);
    return { raw, element, withRefs: attachRefs(element, refs) };
  }

  // The chunk wrote to the object: its document no longer stands for it
  written(id: string) {
    this.documents.delete(id);
    this.convertedNotTaken.delete(id);
  }

  private recordLookup(owners: Map<string, Owner>, lowercasedIds: string[]) {
    owners.forEach((owner, key) => this.owners.set(key, owner));
    lowercasedIds.forEach((id) => this.lookedUpIds.add(id));
  }

  // The element loadRefs converted, handed out once; otherwise a new conversion of the document
  private async takeElement(id: string, raw: RawDoc) {
    const converted = this.convertedNotTaken.get(id);
    this.convertedNotTaken.delete(id);
    if (converted) return converted;
    const [element] = await toElements([raw]);
    return element;
  }

  // The element's referenced elements: a copy of each ref loadRefs read, then a realtime load of the refs whose
  // owner the chunk never looked up
  private async refsOf(element: any) {
    const refIds = refIdsOf(element);
    // Both decided before any await, from what the chunk has read so far
    const notLookedUp = refIds.filter((refId) => !this.lookedUpIds.has(refId.toLowerCase()));
    const liveRefOwners = uniqueLiveOwners(refIds.map((refId) => this.owners.get(refId.toLowerCase())));
    const readRefRaws = liveRefOwners.map((owner) => this.refDocuments.get(owner.owner_id)).filter(isDefined);
    const readRefs = await toElements(readRefRaws);
    const loadedRefs = notLookedUp.length > 0 ? await loadByAnyIds(notLookedUp, { light: true }) : [];
    return [...readRefs, ...loadedRefs];
  }
}
