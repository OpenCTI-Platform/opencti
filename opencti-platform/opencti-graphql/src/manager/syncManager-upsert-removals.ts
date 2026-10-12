import * as jsonpatch from 'fast-json-patch';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { INPUT_GRANTED_REFS, INPUT_MARKINGS } from '../schema/general';
import { logApp } from '../config/conf';

interface SyncEventContext {
  reverse_patch?: jsonpatch.Operation[];
}

export type SyncStixData = Record<string, any> & { extensions?: Record<string, Record<string, any>> };

interface UpsertOperation {
  key?: string;
  value?: unknown;
  operation?: string;
}

// Multi-valued attributes an upsert only adds to: the ones binding an entity to its identity (alternative standard
// ids, aliases) and its access restrictions (markings, organization sharing).
const REMOVABLE_FIELDS: { upsertKey: string; read: (data: SyncStixData | undefined) => unknown }[] = [
  { upsertKey: 'x_opencti_stix_ids', read: (data) => data?.extensions?.[STIX_EXT_OCTI]?.stix_ids },
  { upsertKey: 'aliases', read: (data) => data?.aliases },
  { upsertKey: 'x_opencti_aliases', read: (data) => data?.extensions?.[STIX_EXT_OCTI]?.aliases },
  { upsertKey: INPUT_MARKINGS, read: (data) => data?.object_marking_refs },
  { upsertKey: INPUT_GRANTED_REFS, read: (data) => data?.extensions?.[STIX_EXT_OCTI]?.granted_refs },
];

const valuesOf = (data: SyncStixData | undefined, read: (data: SyncStixData | undefined) => unknown): string[] => {
  const values = read(data);
  return Array.isArray(values) ? values : [];
};

/**
 * A synchronized update is replayed as an upsert, and an upsert only ever adds values to the alternative standard ids
 * and the aliases. The values an update removed (for example the ids and aliases an unmerge gives back to the restored
 * entity) are therefore sent as explicit removals; otherwise the receiving platform keeps them, resolves the restored
 * entity to the entity it had been merged into and folds it back.
 * The reverse patch of the event describes the payload as the stream sent it: the removals are computed from that
 * untouched payload, before any synchronization transformation rewrites or drops fields the patch refers to.
 */
export const computeUpsertRemovals = (data: SyncStixData, context: SyncEventContext | undefined): UpsertOperation[] => {
  const reversePatch = context?.reverse_patch;
  if (!Array.isArray(reversePatch) || reversePatch.length === 0) return [];
  let previous: SyncStixData;
  try {
    previous = jsonpatch.applyPatch(data, reversePatch, false, false).newDocument;
  } catch (error) {
    logApp.warn('[OPENCTI] Sync: the reverse patch of an update does not apply, its removals are not replayed', { cause: error, id: data.id });
    return [];
  }
  const removals: UpsertOperation[] = [];
  for (let i = 0; i < REMOVABLE_FIELDS.length; i += 1) {
    const { upsertKey, read } = REMOVABLE_FIELDS[i];
    const currentValues = valuesOf(data, read);
    const removedValues = valuesOf(previous, read).filter((value) => !currentValues.includes(value));
    if (removedValues.length > 0) {
      removals.push({ key: upsertKey, value: removedValues, operation: 'remove' });
    }
  }
  return removals;
};

/**
 * Adds the removals to the upsert operations of the (transformed) payload. Returns new objects: the input payload is
 * left untouched, as the transformation can be retried.
 */
export const applyUpsertRemovals = <T extends SyncStixData>(data: T, removals: UpsertOperation[]): T => {
  if (removals.length === 0) return data;
  const extension = data.extensions?.[STIX_EXT_OCTI] ?? {};
  // A removal the event already carries for the same attribute is kept: both lists of values are removed.
  const operations = [...((extension.opencti_upsert_operations ?? []) as UpsertOperation[])];
  removals.forEach((removal) => {
    const index = operations.findIndex((operation) => operation.operation === 'remove' && operation.key === removal.key);
    if (index === -1) {
      operations.push(removal);
    } else {
      const carried = Array.isArray(operations[index].value) ? operations[index].value as unknown[] : [];
      operations[index] = { ...operations[index], value: [...new Set([...carried, ...(removal.value as unknown[])])] };
    }
  });
  return {
    ...data,
    extensions: {
      ...data.extensions,
      [STIX_EXT_OCTI]: {
        ...extension,
        opencti_upsert_operations: operations,
      },
    },
  };
};

export const withUpsertRemovals = <T extends SyncStixData>(data: T, context: SyncEventContext | undefined): T => {
  return applyUpsertRemovals(data, computeUpsertRemovals(data, context));
};
