import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreRelation, StoreObject, StoreRelation } from '../types/store';

export interface MergeDependency {
  _index: string;
  internal_id: string;
  entity_type: string;
  name: string;
  i_relation: StoreRelation;
}

export interface MergeDependencies {
  i_relations_from: MergeDependency[];
  i_relations_to: MergeDependency[];
}

export interface MergePlan {
  fromRedirects: MergeDependency[];
  toRedirects: MergeDependency[];
  fromDeletions: BasicStoreRelation[];
  toDeletions: BasicStoreRelation[];
}

export interface MergePreparationInput {
  target: StoreObject;
  sources: StoreObject[];
  sourcesDependencies: MergeDependencies;
  plan: MergePlan;
  // Free metadata of the caller, for example the curation proposal applied by the merge.
  metadata?: Record<string, string>;
}

export interface MergeCommitInput {
  mergedInstance: StoreObject;
  // Sources after the merge: their x_opencti_files point to the files moved under the target.
  sources: StoreObject[];
}

/**
 * A merge recorder captures what a merge changes (before it runs) and persists it once the merge succeeded, so that
 * the merge can later be reverted. Registered by the curation module, called by mergeEntities.
 */
export interface MergeRecorder<P = unknown> {
  isEnabled: () => boolean;
  prepare: (context: AuthContext, user: AuthUser, input: MergePreparationInput) => Promise<P>;
  commit: (context: AuthContext, user: AuthUser, preparation: P, input: MergeCommitInput) => Promise<void>;
}

let mergeRecorder: MergeRecorder<any> | undefined;

export const registerMergeRecorder = <P>(recorder: MergeRecorder<P>) => {
  mergeRecorder = recorder;
};

export const getMergeRecorder = (): MergeRecorder<any> | undefined => mergeRecorder;

/**
 * Field authority resolver consulted in upsert resolution before the confidence comparison.
 * Returns, per attribute key of the patch, whether the incoming source is more ('allow') or less ('deny')
 * authoritative than the source of the current value. Attributes without a rule are absent from the result.
 */
export type FieldAuthorityDecision = 'allow' | 'deny';
export interface FieldAuthorityResolver {
  resolve: (
    context: AuthContext,
    user: AuthUser,
    element: StoreObject,
    type: string,
    patch: Record<string, unknown>,
  ) => Promise<Map<string, FieldAuthorityDecision>>;
  recordApplied: (
    context: AuthContext,
    user: AuthUser,
    element: StoreObject,
    type: string,
    patch: Record<string, unknown>,
    appliedKeys: string[],
  ) => Promise<void>;
}

let fieldAuthorityResolver: FieldAuthorityResolver | undefined;

export const registerFieldAuthorityResolver = (resolver: FieldAuthorityResolver) => {
  fieldAuthorityResolver = resolver;
};

export const getFieldAuthorityResolver = (): FieldAuthorityResolver | undefined => fieldAuthorityResolver;
