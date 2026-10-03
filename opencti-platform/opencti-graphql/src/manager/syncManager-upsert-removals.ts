import * as jsonpatch from 'fast-json-patch';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';

interface SyncEventContext {
  reverse_patch?: jsonpatch.Operation[];
}

export type SyncStixData = Record<string, any> & { extensions?: Record<string, Record<string, any>> };

interface UpsertOperation {
  key?: string;
  value?: unknown;
  operation?: string;
}

// Multi-valued attributes that bind an entity to its identity: alternative standard ids and aliases.
const REMOVABLE_FIELDS: { upsertKey: string; read: (data: SyncStixData | undefined) => unknown }[] = [
  { upsertKey: 'x_opencti_stix_ids', read: (data) => data?.extensions?.[STIX_EXT_OCTI]?.stix_ids },
  { upsertKey: 'aliases', read: (data) => data?.aliases },
  { upsertKey: 'x_opencti_aliases', read: (data) => data?.extensions?.[STIX_EXT_OCTI]?.aliases },
];

const valuesOf = (data: SyncStixData | undefined, read: (data: SyncStixData | undefined) => unknown): string[] => {
  const values = read(data);
  return Array.isArray(values) ? values : [];
};

/**
 * A synchronized update is replayed as an upsert, and an upsert only ever adds values to the alternative standard ids
 * and the aliases. The values an update removed (for example the ids and aliases an unmerge gives back to the restored
 * entity) are therefore sent as explicit removals; otherwise the receiving platform keeps them, resolves the restored
 * entity to the entity it had been merged into and folds it back. Returns new objects: the input event is left
 * untouched, as the transformation can be retried.
 */
export const withUpsertRemovals = <T extends SyncStixData>(data: T, context: SyncEventContext | undefined): T => {
  const reversePatch = context?.reverse_patch;
  if (!Array.isArray(reversePatch) || reversePatch.length === 0) return data;
  let previous: SyncStixData;
  try {
    previous = jsonpatch.applyPatch(data, reversePatch, false, false).newDocument;
  } catch {
    return data;
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
  if (removals.length === 0) return data;
  const removedKeys = new Set(removals.map((removal) => removal.key));
  const extension = data.extensions?.[STIX_EXT_OCTI] ?? {};
  const operations = ((extension.opencti_upsert_operations ?? []) as UpsertOperation[])
    .filter((operation) => !(operation.operation === 'remove' && removedKeys.has(operation.key)));
  return {
    ...data,
    extensions: {
      ...data.extensions,
      [STIX_EXT_OCTI]: {
        ...extension,
        opencti_upsert_operations: [...operations, ...removals],
      },
    },
  };
};
