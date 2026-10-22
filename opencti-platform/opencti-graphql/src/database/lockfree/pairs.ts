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

export const pairKey = (type: string, fromId: string, toId: string) => `pair|${type}|${fromId}|${toId}`;
const pairDocId = (key: string) => deterministicId(key);

export const readPairs = async (keys: string[]): Promise<Map<string, PairEntry[]>> => {
  const out = new Map<string, PairEntry[]>();
  const unique = [...new Set(keys)];
  if (unique.length === 0) return out;
  const response: any = await elRawMget({ docs: unique.map((key) => ({ _index: IDENTITY_INDEX, _id: pairDocId(key) })) });
  response.docs.forEach((doc: any, i: number) => out.set(unique[i], doc.found ? doc._source.relations ?? [] : []));
  return out;
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
  const after = new Map<string, PairEntry[]>();
  if (entries.length === 0) return after;
  const body = entries.flatMap(({ key, entry }) => [
    { update: { _index: IDENTITY_INDEX, _id: pairDocId(key), retry_on_conflict: 20, _source: true } },
    { script: { source: APPEND_SCRIPT, params: { entry } }, upsert: { kind: 'pair', key, relations: [entry] } },
  ]);
  const response: any = await elRawBulk(lockfreeContext, { refresh: false, body });
  response.items.forEach((item: any, i: number) => {
    if (item.update.status >= 300) throw new Error(`Pair append failed: ${JSON.stringify(item.update.error)}`);
    after.set(entries[i].key, item.update.get?._source?.relations ?? [entries[i].entry]);
  });
  return after;
};

export const removeFromPair = async (key: string, id: string) => {
  await elRawBulk(lockfreeContext, {
    refresh: false,
    body: [{ update: { _index: IDENTITY_INDEX, _id: pairDocId(key), retry_on_conflict: 20 } }, { script: { source: REMOVE_SCRIPT, params: { id } } }],
  });
};

// Entries whose relationship is gone (deleted by today's path, or a reconciled duplicate): a relationship is
// created before its entry is appended, so a realtime get that misses it means it was deleted. They are dropped
// from the candidates and from the pair, so the input is created again, as today.
export const withoutDeleted = async (pairs: Map<string, PairEntry[]>) => {
  const entries = [...pairs.values()].flat();
  if (entries.length === 0) return pairs;
  const found = await mgetRaw(entries.map((e) => ({ index: e.index, id: e.id })), { light: true });
  const out = new Map<string, PairEntry[]>();
  const gone: { key: string; id: string }[] = [];
  pairs.forEach((list, key) => {
    out.set(key, list.filter((e) => found.has(e.id)));
    list.filter((e) => !found.has(e.id)).forEach((e) => gone.push({ key, id: e.id }));
  });
  await Promise.all(gone.map((g) => removeFromPair(g.key, g.id)));
  return out;
};

// Today's duplicate filters, evaluated on a candidate instead of in a search
const valueOf = (entry: PairEntry, key: string) => {
  if (key === buildRefRelationKey(RELATION_CREATED_BY)) return entry.created_by;
  return (entry as any)[key];
};
const filterMatches = (entry: PairEntry, filter: { key: string[]; values: any[]; operator?: string }) => {
  const value = valueOf(entry, filter.key[0]);
  const expected = filter.values[0];
  if (filter.operator === 'gt' || filter.operator === 'lt') {
    if (value === undefined || value === null) return false;
    const a = new Date(value).getTime();
    const b = new Date(expected).getTime();
    return filter.operator === 'gt' ? a > b : a < b;
  }
  return filter.values.includes(value);
};

// The existing relationships the input duplicates, oldest first (the platform takes the first one found)
export const findDuplicates = (input: Record<string, any>, candidates: PairEntry[]) => {
  const inputIds = new Set(getInputIds(input.relationship_type, input, false).map((id: string) => id.toLowerCase()));
  const filters = buildRelationDeduplicationFilters(input) as any[];
  return candidates.filter((c) => c.ids.some((id) => inputIds.has(id.toLowerCase())) || filters.every((f) => filterMatches(c, f)));
};

export const pairEntryOf = (element: Record<string, any>, createdById?: string): PairEntry => ({
  id: element.internal_id,
  index: element._index,
  ids: [element.standard_id, ...(element.x_opencti_stix_ids ?? [])].filter(Boolean),
  start_time: element.start_time ? new Date(element.start_time).toISOString() : undefined,
  stop_time: element.stop_time ? new Date(element.stop_time).toISOString() : undefined,
  first_seen: element.first_seen ? new Date(element.first_seen).toISOString() : undefined,
  last_seen: element.last_seen ? new Date(element.last_seen).toISOString() : undefined,
  created_by: createdById,
});
