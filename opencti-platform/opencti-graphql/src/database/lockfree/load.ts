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
import { pool } from './context';
import { lookupKeys, type Owner } from './identity';

export interface RawDoc { _index: string; _id: string; _seq_no: number; _primary_term: number; _source: Record<string, any> }

// Raw documents by (index, id), realtime. `light` leaves out the rel_* lists of busy entities.
export const mgetRaw = async (refs: { index: string; id: string }[], opts: { light?: boolean } = {}): Promise<Map<string, RawDoc>> => {
  const found = new Map<string, RawDoc>();
  const unique = R.uniqBy((r) => `${r.index}|${r.id}`, refs);
  await pool(R.splitEvery(1000, unique), 4, async (slice) => {
    const response: any = await elRawMget({
      docs: slice.map((r) => ({ _index: r.index, _id: r.id, ...(opts.light ? { _source: { excludes: ['rel_*'] } } : {}) })),
    });
    response.docs.filter((d: any) => d.found).forEach((d: any) => found.set(d._id, d as RawDoc));
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

// An element with its refs resolved, as storeLoadByIdWithRefs returns it: each ref input (createdBy,
// objectMarking, objectLabel, externalReferences, objects...) holds the referenced elements, and a relationship
// holds its from and to
export const loadWithRefs = async (context: AuthContext, user: AuthUser, element: any) => {
  const refs = schemaRelationsRefDefinition.getRelationsRef(element.entity_type);
  const refIds: string[] = refs.flatMap((ref) => ([] as string[]).concat(element[ref.databaseName] ?? []));
  const ids = R.uniq([...refIds, ...(element.fromId ? [element.fromId, element.toId] : [])]);
  const resolved = new Map<string, any>();
  if (ids.length > 0) {
    const loaded = await loadByAnyIds(ids, { light: true });
    loaded.forEach((e) => resolved.set(e.internal_id, e));
  }
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
