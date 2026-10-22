// Identity index of the lock-free write path: one document per identity key (standard id, STIX ids, alias ids,
// hashes), whose _id is derived from the key and which names the object that owns the key.
// Elasticsearch refuses a second `create` of the same _id, so claiming a key is atomic without a lock, and a
// realtime get by _id sees a claim before any refresh. A deleted object keeps its keys as tombstones.
import { v5 as uuidv5 } from 'uuid';
import { lockfreeContext } from './context';
import { elRawBulk, elRawMget } from '../../database/engine';
import { ES_INDEX_PREFIX } from '../../database/utils';
import { getInputIds } from '../../schema/identifier';

const NAMESPACE = 'a6b4c1e2-0f8d-4c5e-9b7a-3d2f1e0c9b8a';
// Outside the platform prefix, so that no platform index template (strict mappings) applies to it
export const IDENTITY_INDEX = `lockfree_identities_${ES_INDEX_PREFIX}`;

export const deterministicId = (key: string) => uuidv5(key, NAMESPACE);

export interface Owner {
  key: string;
  owner_id: string;
  owner_index: string;
  owner_type: string;
  owner_standard_id: string;
  state: 'live' | 'deleted';
}

// Every key that makes two inputs the same object, as the platform computes them for its locks and searches
export const identityKeys = (type: string, input: Record<string, any>): string[] => {
  const ids: string[] = getInputIds(type, { ...input, entity_type: type, internal_id: undefined }, false);
  return ids.map((id) => id.toLowerCase());
};

// Realtime lookup of keys: key -> owner, for the keys that have one
export const lookupKeys = async (keys: string[]): Promise<Map<string, Owner>> => {
  const owners = new Map<string, Owner>();
  const unique = [...new Set(keys)];
  for (let i = 0; i < unique.length; i += 1000) {
    const slice = unique.slice(i, i + 1000);
    const response: any = await elRawMget({ docs: slice.map((key) => ({ _index: IDENTITY_INDEX, _id: deterministicId(key) })) });
    response.docs.forEach((doc: any, j: number) => {
      if (doc.found) owners.set(slice[j], doc._source as Owner);
    });
  }
  return owners;
};

// Claim keys for an owner with `create`: returns the keys another owner already holds (a lost race)
export const claimKeys = async (claims: { keys: string[]; owner: Omit<Owner, 'key' | 'state'> }[]) => {
  const body = claims.flatMap(({ keys, owner }) => keys.flatMap((key) => [
    { create: { _index: IDENTITY_INDEX, _id: deterministicId(key) } },
    { ...owner, key, state: 'live' },
  ]));
  if (body.length === 0) return [];
  const response: any = await elRawBulk(lockfreeContext, { refresh: false, body });
  const flat = claims.flatMap(({ keys, owner }) => keys.map((key) => ({ key, owner })));
  const conflicts = response.items
    .map((item: any, i: number) => ({ item: item.create, ...flat[i] }))
    .filter(({ item }: any) => item.status === 409);
  const failed = response.items.find((item: any) => item.create.status >= 400 && item.create.status !== 409);
  if (failed) throw new Error(`Identity claim failed: ${JSON.stringify(failed.create.error)}`);
  if (conflicts.length === 0) return [];
  // A tombstone or the same owner is not a lost race: take the key over
  const holders = await lookupKeys(conflicts.map((c: any) => c.key));
  const takeOver = conflicts.filter((c: any) => holders.get(c.key)?.state === 'deleted');
  if (takeOver.length > 0) await setKeys(takeOver.map((c: any) => ({ key: c.key, owner: c.owner })));
  return conflicts
    .filter((c: any) => holders.get(c.key)?.state === 'live' && holders.get(c.key)?.owner_id !== c.owner.owner_id)
    .map((c: any) => ({ key: c.key, claimant: c.owner.owner_id, holder: holders.get(c.key) as Owner }));
};

// Overwrite keys (re-pointing after a merge of two objects, or a tombstone)
export const setKeys = async (entries: { key: string; owner: Omit<Owner, 'key' | 'state'>; state?: Owner['state'] }[]) => {
  const body = entries.flatMap(({ key, owner, state }) => [
    { index: { _index: IDENTITY_INDEX, _id: deterministicId(key) } },
    { ...owner, key, state: state ?? 'live' },
  ]);
  if (body.length === 0) return;
  const response: any = await elRawBulk(lockfreeContext, { refresh: false, body });
  if (response.errors) throw new Error('Identity update failed');
};

// One-time backfill for objects that exist before the lock-free path is used (markings, labels, authors...)
export const registerExisting = async (objects: Record<string, any>[]) => {
  await setKeys(objects.flatMap((o) => identityKeys(o.entity_type, { ...o, stix_id: o.standard_id }).concat([o.internal_id]).map((key) => ({
    key,
    owner: { owner_id: o.internal_id, owner_index: o._index, owner_type: o.entity_type, owner_standard_id: o.standard_id },
  }))));
};
