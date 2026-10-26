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
import { claimKeys, identityKeys, ownerFieldsOf, setKeys } from './identity';
import { mgetRaw } from './load';
import { appendPairs, pairEntryOf, pairKey } from './pairs';

type Claim = Parameters<typeof claimKeys>[0][number];

// Every document of the index, page by page in internal id order (search_after); returns how many were scanned
const scan = async (index: string, size: number, onPage: (elements: any[]) => Promise<void>) => {
  let searchAfter: any[] | undefined;
  let total = 0;
  for (;;) {
    const body = {
      sort: [{ 'internal_id.keyword': 'asc' }],
      query: { match_all: {} },
      _source: { excludes: ['rel_*.inferred_id'] },
      ...(searchAfter ? { search_after: searchAfter } : {}),
    };
    const response: any = await elRawSearch(lockfreeContext, SYSTEM_USER, null, { index, size, body });
    const hits = response.hits.hits;
    if (hits.length === 0) return total;
    const elements = await elConvertHits(hits);
    await onPage(elements);
    total += hits.length;
    searchAfter = hits[hits.length - 1].sort;
  }
};

// An entity's keys: the ones the platform computes, plus its internal id
const entityClaim = (entity: any): Claim => ({
  keys: [...identityKeys(entity.entity_type, { ...entity, stix_id: entity.standard_id }), entity.internal_id],
  owner: ownerFieldsOf(entity),
});

// A relationship's keys: its own ids, lowercased
const relationshipClaim = (relationship: any): Claim => ({
  keys: [relationship.internal_id, relationship.standard_id, ...(relationship.x_opencti_stix_ids ?? [])].map((key: string) => key.toLowerCase()),
  owner: ownerFieldsOf(relationship),
});

// Claims, then takes over the keys whose holder's document is gone; returns how many were taken over
const claimTakingOverStale = async (claims: Claim[]) => {
  const conflicts = await claimKeys(claims);
  if (conflicts.length === 0) return 0;
  const holderDocuments = await mgetRaw(conflicts.map(({ holder }) => ({ index: holder.owner_index, id: holder.owner_id })), { light: true });
  const stale = conflicts.filter(({ holder }) => !holderDocuments.has(holder.owner_id));
  const claimantOwners = new Map(claims.map((claim) => [claim.owner.owner_id, claim.owner]));
  await setKeys(stale.map((conflict) => ({ key: conflict.key, owner: claimantOwners.get(conflict.claimant) as Claim['owner'] })));
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
      staleTakenOver += await claimTakingOverStale(elements.map(entityClaim));
    });
  }
  for (const index of [READ_INDEX_STIX_CORE_RELATIONSHIPS, READ_INDEX_STIX_SIGHTING_RELATIONSHIPS]) {
    relationships += await scan(index, size, async (elements) => {
      staleTakenOver += await claimTakingOverStale(elements.map(relationshipClaim));
      await appendPairs(elements.map((relationship) => ({
        key: pairKey(relationship.entity_type, relationship.fromId, relationship.toId),
        entry: pairEntryOf(relationship, (relationship['created-by'] as string) ?? undefined),
      })));
    });
  }
  const seconds = (Date.now() - started) / 1000;
  return { entities, relationships, stale_taken_over: staleTakenOver, seconds, per_second: Math.round((entities + relationships) / Math.max(seconds, 0.001)) };
};
