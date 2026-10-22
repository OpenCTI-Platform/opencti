// One-time backfill of the identity index for data written before the lock-free path: every entity gets its keys
// (internal id, standard id, STIX ids, alias ids, hashes) and every relationship its pair entry. Idempotent: it can
// run again, and keys a lock-free write already holds are not taken from it, unless their holder no longer exists
// (an object deleted or wiped without its tombstone): the object found in the index then takes the key over.
// Runs before lock-free writes are enabled, so a holder without its document is stale, not a write in flight.
import { lockfreeContext } from './context';
import { elRawSearch } from '../../database/engine';
import {
  READ_INDEX_STIX_CORE_RELATIONSHIPS,
  READ_INDEX_STIX_CYBER_OBSERVABLES,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_INDEX_STIX_META_OBJECTS,
  READ_INDEX_STIX_SIGHTING_RELATIONSHIPS,
} from '../../database/utils';
import { elConvertHits } from '../../database/engine-data-converter';
import { SYSTEM_USER } from '../../utils/access';
import { claimKeys, identityKeys, type Owner, setKeys } from './identity';
import { mgetRaw } from './load';
import { appendPairs, pairEntryOf, pairKey } from './pairs';

const scan = async (index: string, size: number, onPage: (elements: any[]) => Promise<void>) => {
  let searchAfter: any[] | undefined;
  let total = 0;
  for (;;) {
    const response: any = await elRawSearch(lockfreeContext, SYSTEM_USER, null, {
      index,
      size,
      body: { sort: [{ 'internal_id.keyword': 'asc' }], query: { match_all: {} }, _source: { excludes: ['rel_*.inferred_id'] }, ...(searchAfter ? { search_after: searchAfter } : {}) },
    });
    const hits = response.hits.hits;
    if (hits.length === 0) return total;
    const elements = await elConvertHits(hits);
    await onPage(elements);
    total += hits.length;
    searchAfter = hits[hits.length - 1].sort;
  }
};

type Claim = Parameters<typeof claimKeys>[0][number];

// Claims, then takes over the keys whose holder's document is gone
const claimTakingOverStale = async (claims: Claim[]) => {
  const conflicts: { key: string; claimant: string; holder: Owner }[] = await claimKeys(claims);
  if (conflicts.length === 0) return 0;
  const holders = await mgetRaw(conflicts.map((c) => ({ index: c.holder.owner_index, id: c.holder.owner_id })), { light: true });
  const stale = conflicts.filter((c) => !holders.has(c.holder.owner_id));
  const ownerOf = new Map(claims.map((c) => [c.owner.owner_id, c.owner]));
  await setKeys(stale.map((c) => ({ key: c.key, owner: ownerOf.get(c.claimant) as Claim['owner'] })));
  return stale.length;
};

export const backfillIdentities = async (opts: { pageSize?: number } = {}) => {
  const size = opts.pageSize ?? 2000;
  const started = Date.now();
  let entities = 0;
  let relationships = 0;
  let staleTakenOver = 0;
  for (const index of [READ_INDEX_STIX_DOMAIN_OBJECTS, READ_INDEX_STIX_CYBER_OBSERVABLES, READ_INDEX_STIX_META_OBJECTS]) {
    entities += await scan(index, size, async (elements) => {
      staleTakenOver += await claimTakingOverStale(elements.map((e: any) => ({
        keys: [...identityKeys(e.entity_type, { ...e, stix_id: e.standard_id }), e.internal_id],
        owner: { owner_id: e.internal_id, owner_index: e._index, owner_type: e.entity_type, owner_standard_id: e.standard_id },
      })));
    });
  }
  for (const index of [READ_INDEX_STIX_CORE_RELATIONSHIPS, READ_INDEX_STIX_SIGHTING_RELATIONSHIPS]) {
    relationships += await scan(index, size, async (elements) => {
      staleTakenOver += await claimTakingOverStale(elements.map((e: any) => ({
        keys: [e.internal_id, e.standard_id, ...(e.x_opencti_stix_ids ?? [])].map((k: string) => k.toLowerCase()),
        owner: { owner_id: e.internal_id, owner_index: e._index, owner_type: e.entity_type, owner_standard_id: e.standard_id },
      })));
      await appendPairs(elements.map((e: any) => ({ key: pairKey(e.entity_type, e.fromId, e.toId), entry: pairEntryOf(e, (e['created-by'] as string) ?? undefined) })));
    });
  }
  const seconds = (Date.now() - started) / 1000;
  return { entities, relationships, stale_taken_over: staleTakenOver, seconds, per_second: Math.round((entities + relationships) / Math.max(seconds, 0.001)) };
};
