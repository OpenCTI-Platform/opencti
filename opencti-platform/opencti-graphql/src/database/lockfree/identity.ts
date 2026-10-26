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

const LOOKUP_BATCH_SIZE = 1000;
const CONFLICT = 409;

export const deterministicId = (key: string) => uuidv5(key, NAMESPACE);

export interface Owner {
  key: string;
  owner_id: string;
  owner_index: string;
  owner_type: string;
  owner_standard_id: string;
  state: 'live' | 'deleted';
}

type OwnerFields = Omit<Owner, 'key' | 'state'>;

export const ownerFieldsOf = (element: Record<string, any>): OwnerFields => ({
  owner_id: element.internal_id,
  owner_index: element._index,
  owner_type: element.entity_type,
  owner_standard_id: element.standard_id,
});

// Every key that makes two inputs the same object, as the platform computes them for its locks and searches
export const identityKeys = (type: string, input: Record<string, any>): string[] => {
  const ids: string[] = getInputIds(type, { ...input, entity_type: type, internal_id: undefined }, false);
  return ids.map((id) => id.toLowerCase());
};

// Realtime lookup of keys: key -> owner, for the keys that have one
export const lookupKeys = async (keys: string[]): Promise<Map<string, Owner>> => {
  const owners = new Map<string, Owner>();
  const uniqueKeys = [...new Set(keys)];
  for (let offset = 0; offset < uniqueKeys.length; offset += LOOKUP_BATCH_SIZE) {
    const batch = uniqueKeys.slice(offset, offset + LOOKUP_BATCH_SIZE);
    const response: { docs: { found: boolean; _source: Owner }[] } = await elRawMget({ docs: batch.map((key) => ({ _index: IDENTITY_INDEX, _id: deterministicId(key) })) });
    response.docs.forEach((doc, position) => {
      if (doc.found) owners.set(batch[position], doc._source);
    });
  }
  return owners;
};

// Claim keys for an owner with `create`: returns the keys another owner already holds (a lost race): `claimant`
// (an owner_id) lost `key` to `holder`
export const claimKeys = async (claims: { keys: string[]; owner: OwnerFields }[]) => {
  // One claim per key, in the order of the bulk items
  const keyClaims = claims.flatMap(({ keys, owner }) => keys.map((key) => ({ key, owner })));
  if (keyClaims.length === 0) return [];
  const body = keyClaims.flatMap(({ key, owner }) => [
    { create: { _index: IDENTITY_INDEX, _id: deterministicId(key) } },
    { ...owner, key, state: 'live' },
  ]);
  const response = await elRawBulk(lockfreeContext, { refresh: false, body });
  const results: { status: number; error?: unknown }[] = response.items.map((item: any) => item.create);
  const failed = results.find((result) => result.status >= 400 && result.status !== CONFLICT);
  if (failed) throw new Error(`Identity claim failed: ${JSON.stringify(failed.error)}`);
  const conflicts = keyClaims.filter((_, position) => results[position].status === CONFLICT);
  if (conflicts.length === 0) return [];
  // A tombstone or the same owner is not a lost race: a tombstoned key is taken over
  const holders = await lookupKeys(conflicts.map((conflict) => conflict.key));
  const tombstoned = conflicts.filter((conflict) => holders.get(conflict.key)?.state === 'deleted');
  if (tombstoned.length > 0) await setKeys(tombstoned);
  const lostToAnother = conflicts.filter((conflict) => {
    const holder = holders.get(conflict.key);
    return holder?.state === 'live' && holder.owner_id !== conflict.owner.owner_id;
  });
  return lostToAnother.map((conflict) => ({ key: conflict.key, claimant: conflict.owner.owner_id, holder: holders.get(conflict.key) as Owner }));
};

// Overwrite keys (re-pointing after a merge of two objects, or a tombstone)
export const setKeys = async (entries: { key: string; owner: OwnerFields; state?: Owner['state'] }[]) => {
  const body = entries.flatMap(({ key, owner, state }) => [
    { index: { _index: IDENTITY_INDEX, _id: deterministicId(key) } },
    { ...owner, key, state: state ?? 'live' },
  ]);
  if (body.length === 0) return;
  const response = await elRawBulk(lockfreeContext, { refresh: false, body });
  if (response.errors) throw new Error('Identity update failed');
};

// One-time backfill for objects that exist before the lock-free path is used (markings, labels, authors...)
export const registerExisting = async (objects: Record<string, any>[]) => {
  await setKeys(objects.flatMap((object) => {
    const keys = identityKeys(object.entity_type, { ...object, stix_id: object.standard_id }).concat([object.internal_id]);
    const owner = ownerFieldsOf(object);
    return keys.map((key) => ({ key, owner }));
  }));
};
