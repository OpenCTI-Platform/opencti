import * as jsonpatch from 'fast-json-patch';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';

interface SyncEventContext {
  reverse_patch?: jsonpatch.Operation[];
}

type SyncStixData = Record<string, any> & { extensions?: Record<string, Record<string, any>> };

const STIX_IDS_UPSERT_KEY = 'x_opencti_stix_ids';

const stixIdsOf = (data: SyncStixData | undefined): string[] => {
  const ids = data?.extensions?.[STIX_EXT_OCTI]?.stix_ids;
  return Array.isArray(ids) ? ids : [];
};

/**
 * A synchronized update is replayed as an upsert, and an upsert only ever adds alternative standard ids. The ids an
 * update removed (for example the ids an unmerge gives back to the restored entity) are therefore sent as an explicit
 * removal; otherwise the receiving platform keeps them, and the restored entity is folded into the entity it had been
 * merged into. Returns new objects: the input event is left untouched, as the transformation can be retried.
 */
export const withRemovedStixIdsOperation = <T extends SyncStixData>(data: T, context: SyncEventContext | undefined): T => {
  const reversePatch = context?.reverse_patch;
  if (!Array.isArray(reversePatch) || reversePatch.length === 0) return data;
  let previous: SyncStixData;
  try {
    previous = jsonpatch.applyPatch(data, reversePatch, false, false).newDocument;
  } catch {
    return data;
  }
  const currentIds = stixIdsOf(data);
  const removedIds = stixIdsOf(previous).filter((id) => !currentIds.includes(id));
  if (removedIds.length === 0) return data;
  const extension = data.extensions?.[STIX_EXT_OCTI] ?? {};
  const operations = (extension.opencti_upsert_operations ?? [])
    .filter((operation: { key?: string; operation?: string }) => !(operation.key === STIX_IDS_UPSERT_KEY && operation.operation === 'remove'));
  return {
    ...data,
    extensions: {
      ...data.extensions,
      [STIX_EXT_OCTI]: {
        ...extension,
        opencti_upsert_operations: [...operations, { key: STIX_IDS_UPSERT_KEY, value: removedIds, operation: 'remove' }],
      },
    },
  };
};
