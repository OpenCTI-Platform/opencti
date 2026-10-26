// Relationship duplicates, as today: two relationships are the same when they have the same type and ends and
// match today's duplicate filters (buildRelationDeduplicationFilters: the start/stop or first/last seen window of
// relations_deduplication, its per-type overrides, created-by when configured), or share an id.
// The candidates come from one "pair" document per (type, from, to) in the identity index, listing that pair's
// relationships, read by id (no search, no refresh). Appending to it is a script, atomic per document.
import { lockfreeContext } from './context';
import { elRawBulk, elRawMget } from '../../database/engine';
import { buildRelationDeduplicationFilters } from '../../database/middleware';
import { buildRefRelationKey } from '../../schema/general';
import { RELATION_CREATED_BY } from '../../schema/stixRefRelationship';
import { getInputIds } from '../../schema/identifier';
import { deterministicId, IDENTITY_INDEX } from './identity';
import { mgetRaw } from './load';

export interface PairEntry {
  id: string;
  index: string;
  ids: string[]; // standard id and STIX ids
  start_time?: string;
  stop_time?: string;
  first_seen?: string;
  last_seen?: string;
  created_by?: string;
}

// One of today's duplicate filters, as buildRelationDeduplicationFilters builds it
interface DeduplicationFilter { key: string[]; values: any[]; operator?: string }

// Concurrent appends to one pair document conflict on its version: retried by Elasticsearch
const RETRY_ON_CONFLICT = 20;

export const pairKey = (type: string, fromId: string, toId: string) => `pair|${type}|${fromId}|${toId}`;
const pairDocId = (key: string) => deterministicId(key);

// Each key's entries, empty when the pair has no document yet
export const readPairs = async (keys: string[]): Promise<Map<string, PairEntry[]>> => {
  const entriesByKey = new Map<string, PairEntry[]>();
  const uniqueKeys = [...new Set(keys)];
  if (uniqueKeys.length === 0) return entriesByKey;
  const response: { docs: { found: boolean; _source: { relations?: PairEntry[] } }[] } = await elRawMget({
    docs: uniqueKeys.map((key) => ({ _index: IDENTITY_INDEX, _id: pairDocId(key) })),
  });
  response.docs.forEach((doc, position) => entriesByKey.set(uniqueKeys[position], doc.found ? doc._source.relations ?? [] : []));
  return entriesByKey;
};

const APPEND_SCRIPT = `
  if (ctx._source.relations == null) { ctx._source.relations = []; }
  boolean present = false;
  for (r in ctx._source.relations) { if (r.id == params.entry.id) { present = true; } }
  if (!present) { ctx._source.relations.add(params.entry); }
`;
const REMOVE_SCRIPT = 'if (ctx._source.relations != null) { ctx._source.relations.removeIf(r -> r.id == params.id); }';

// Append entries; returns each pair's list after the append, to detect a duplicate created at the same moment
export const appendPairs = async (entries: { key: string; entry: PairEntry }[]) => {
  const listsAfter = new Map<string, PairEntry[]>();
  if (entries.length === 0) return listsAfter;
  const body = entries.flatMap(({ key, entry }) => [
    { update: { _index: IDENTITY_INDEX, _id: pairDocId(key), retry_on_conflict: RETRY_ON_CONFLICT, _source: true } },
    { script: { source: APPEND_SCRIPT, params: { entry } }, upsert: { kind: 'pair', key, relations: [entry] } },
  ]);
  const response = await elRawBulk(lockfreeContext, { refresh: false, body });
  response.items.forEach((item: any, position: number) => {
    const { key, entry } = entries[position];
    if (item.update.status >= 300) throw new Error(`Pair append failed: ${JSON.stringify(item.update.error)}`);
    // Without a source in the response, the list is taken to be the entry alone
    listsAfter.set(key, item.update.get?._source?.relations ?? [entry]);
  });
  return listsAfter;
};

export const removeFromPair = async (key: string, id: string) => {
  await elRawBulk(lockfreeContext, {
    refresh: false,
    body: [{ update: { _index: IDENTITY_INDEX, _id: pairDocId(key), retry_on_conflict: RETRY_ON_CONFLICT } }, { script: { source: REMOVE_SCRIPT, params: { id } } }],
  });
};

// Entries whose relationship is gone (deleted by today's path, or a reconciled duplicate): a relationship is
// created before its entry is appended, so a realtime get that misses it means it was deleted. They are dropped
// from the candidates and from the pair, so the input is created again, as today.
export const withoutDeleted = async (pairs: Map<string, PairEntry[]>) => {
  const allEntries = [...pairs.values()].flat();
  if (allEntries.length === 0) return pairs;
  const existing = await mgetRaw(allEntries.map((entry) => ({ index: entry.index, id: entry.id })), { light: true });
  const kept = new Map<string, PairEntry[]>();
  const gone: { key: string; id: string }[] = [];
  pairs.forEach((entries, key) => {
    kept.set(key, entries.filter((entry) => existing.has(entry.id)));
    entries.filter((entry) => !existing.has(entry.id)).forEach((entry) => gone.push({ key, id: entry.id }));
  });
  await Promise.all(gone.map(({ key, id }) => removeFromPair(key, id)));
  return kept;
};

// Today's duplicate filters, evaluated on a candidate instead of in a search
const valueOf = (entry: PairEntry, field: string) => {
  if (field === buildRefRelationKey(RELATION_CREATED_BY)) return entry.created_by;
  return entry[field as keyof PairEntry];
};

const filterMatches = (entry: PairEntry, filter: DeduplicationFilter) => {
  const value = valueOf(entry, filter.key[0]);
  if (filter.operator !== 'gt' && filter.operator !== 'lt') return filter.values.includes(value);
  if (value === undefined || value === null) return false;
  const entryTime = new Date(value as string).getTime();
  const boundTime = new Date(filter.values[0]).getTime();
  return filter.operator === 'gt' ? entryTime > boundTime : entryTime < boundTime;
};

// The existing relationships the input duplicates, oldest first (the platform takes the first one found)
export const findDuplicates = (input: Record<string, any>, candidates: PairEntry[]) => {
  const inputIds = new Set(getInputIds(input.relationship_type, input, false).map((id: string) => id.toLowerCase()));
  const filters = buildRelationDeduplicationFilters(input) as DeduplicationFilter[];
  return candidates.filter((candidate) => candidate.ids.some((id) => inputIds.has(id.toLowerCase())) || filters.every((filter) => filterMatches(candidate, filter)));
};

const toIsoDate = (value: any) => (value ? new Date(value).toISOString() : undefined);

export const pairEntryOf = (element: Record<string, any>, createdById?: string): PairEntry => ({
  id: element.internal_id,
  index: element._index,
  ids: [element.standard_id, ...(element.x_opencti_stix_ids ?? [])].filter(Boolean),
  start_time: toIsoDate(element.start_time),
  stop_time: toIsoDate(element.stop_time),
  first_seen: toIsoDate(element.first_seen),
  last_seen: toIsoDate(element.last_seen),
  created_by: createdById,
});
