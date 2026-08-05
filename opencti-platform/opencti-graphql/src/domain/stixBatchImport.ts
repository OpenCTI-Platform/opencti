import { addMalware } from './malware';
import { addTool } from './tool';
import { addVulnerability } from './vulnerability';
import { addStixCyberObservable } from './stixCyberObservable';
import type { AuthContext, AuthUser } from '../types/user';

// v1 (leaf-only) slice of Proposal D - batching of dependency-free STIX objects.
// Scope is intentionally narrowed to entity kinds that have an unambiguous,
// subtype-free STIX -> internal input mapping (no identity_class / location_type
// style branching): STIX cyber observables (dispatch already generic on `type`),
// Malware, Vulnerability and Tool. Each item is still created through the exact
// same domain function used by the single-object mutations (addMalware,
// addStixCyberObservable, ...) - business logic is untouched, only invoked in a
// loop from a single GraphQL call instead of N separate calls. Locking, ES bulk
// chunking and other throughput optimizations are intentionally deferred to a
// later iteration (see Proposal D v2).
export const STIX_BATCH_IMPORT_KINDS = ['stix_cyber_observable', 'malware', 'vulnerability', 'tool'] as const;
export type StixBatchImportItemKind = typeof STIX_BATCH_IMPORT_KINDS[number];

export interface StixBatchImportItemInput {
  kind: StixBatchImportItemKind;
  input: Record<string, unknown>;
}

export interface StixBatchImportItemResult {
  id: string | null;
  success: boolean;
  error: string | null;
}

const createByKind = (context: AuthContext, user: AuthUser, kind: StixBatchImportItemKind, input: Record<string, unknown>) => {
  switch (kind) {
    case 'stix_cyber_observable':
      return addStixCyberObservable(context, user, input);
    case 'malware':
      return addMalware(context, user, input);
    case 'vulnerability':
      return addVulnerability(context, user, input);
    case 'tool':
      return addTool(context, user, input);
    default:
      throw Error(`Unsupported batch import kind: ${kind}`);
  }
};

export const stixObjectsBatchImport = async (
  context: AuthContext,
  user: AuthUser,
  items: StixBatchImportItemInput[],
): Promise<StixBatchImportItemResult[]> => {
  const results: StixBatchImportItemResult[] = [];
  // One exception on a single item must not abort the whole batch: catch-and-continue
  // per item, matching the index-aligned success/error contract expected by the worker.
  for (let index = 0; index < items.length; index += 1) {
    const { kind, input } = items[index];
    try {
      const created = await createByKind(context, user, kind, input) as Record<string, unknown>;
      const createdId = (created?.standard_id ?? created?.internal_id ?? null) as string | null;
      results.push({ id: createdId, success: true, error: null });
    } catch (err: any) {
      results.push({ id: null, success: false, error: err?.message ?? String(err) });
    }
  }
  return results;
};
