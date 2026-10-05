import * as R from 'ramda';
import { ATTRIBUTE_ADDITIONAL_NAMES, ATTRIBUTE_ALIASES, ATTRIBUTE_ALIASES_OPENCTI } from '../../schema/stixDomainObject';
import { IDS_STIX } from '../../schema/general';
import type { MergeSnapshotRef, MergeSourceSnapshot, MergeTargetSnapshot } from './curation-types';
import { ALREADY_DELETED_ERROR, FUNCTIONAL_ERROR, MISSING_REF_ERROR, VALIDATION_ERROR } from '../../config/errors';

// Attributes never written back on unmerge: identity, technical timestamps and computed internal fields. The creators
// are kept: the creators a reverted source brought leave the target, and the restored source gets its own back.
const IGNORED_ATTRIBUTES = new Set([
  'id',
  'internal_id',
  'standard_id',
  'entity_type',
  'base_type',
  'parent_types',
  'created_at',
  'updated_at',
  'refreshed_at',
  'modified',
  'x_opencti_modified_at',
  'draft_ids',
  'draft_change',
  'metrics',
  'x_opencti_files',
]);

const NAME_CARRYING_ATTRIBUTES = new Set([ATTRIBUTE_ALIASES, ATTRIBUTE_ALIASES_OPENCTI, ATTRIBUTE_ADDITIONAL_NAMES]);

export const isSnapshotAttribute = (key: string) => !IGNORED_ATTRIBUTES.has(key) && !key.startsWith('i_') && !key.startsWith('rel_');

export interface AttributeDescriptor {
  multiple: boolean;
}

export type AttributeDescriptorFn = (key: string) => AttributeDescriptor | undefined;

export interface RefDescriptor {
  name: string;
  multiple: boolean;
}

export interface RevertInput {
  key: string;
  value: unknown[];
  operation: 'add' | 'remove' | 'replace';
}

const asArray = (value: unknown): unknown[] => {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
};

const isEmptyValue = (value: unknown) => value === undefined || value === null || (typeof value === 'string' && value.trim() === '') || (Array.isArray(value) && value.length === 0);

const valueKey = (value: unknown) => (typeof value === 'string' ? value.trim().toLowerCase() : JSON.stringify(value));

const toKeySet = (values: unknown[]) => new Set(values.map(valueKey));

/**
 * Values of a multiple attribute that a source brought to the target during the merge.
 */
export const sourceContribution = (source: MergeSourceSnapshot, key: string): unknown[] => {
  const values = [...asArray(source.attributes[key])];
  if (NAME_CARRYING_ATTRIBUTES.has(key) && source.name) {
    values.push(source.name);
  }
  if (key === IDS_STIX) {
    values.push(source.standard_id);
  }
  return values;
};

const refIds = (refs: MergeSnapshotRef, name: string): string[] => asArray(refs[name]).filter((id): id is string => typeof id === 'string');

/**
 * Compute the edit inputs that revert, on the live target, what the given sources brought during the merge, without
 * touching the values that were there before the merge, the values other (non reverted) sources still contribute,
 * or the values changed by users after the merge.
 */
export const computeTargetRevertInputs = (
  target: MergeTargetSnapshot,
  live: { attributes: Record<string, unknown>; refs: MergeSnapshotRef },
  reverting: MergeSourceSnapshot[],
  remaining: MergeSourceSnapshot[],
  describeAttribute: AttributeDescriptorFn,
  refsDescriptors: RefDescriptor[],
): RevertInput[] => {
  const inputs: RevertInput[] = [];
  const isFullRevert = remaining.length === 0;
  const attributeKeys = R.uniq([...Object.keys(target.post_attributes), ...Object.keys(target.attributes)]).filter(isSnapshotAttribute);
  attributeKeys.forEach((key) => {
    const descriptor = describeAttribute(key);
    if (!descriptor) return;
    const pre = target.attributes[key];
    const post = target.post_attributes[key];
    const current = live.attributes[key];
    if (descriptor.multiple) {
      const preKeys = toKeySet(asArray(pre));
      const postValues = asArray(post);
      const addedByMerge = postValues.filter((value) => !preKeys.has(valueKey(value)));
      const revertingKeys = toKeySet(reverting.flatMap((source) => sourceContribution(source, key)));
      const remainingKeys = toKeySet(remaining.flatMap((source) => sourceContribution(source, key)));
      const currentKeys = toKeySet(asArray(current));
      const toRemove = addedByMerge.filter((value) => {
        const k = valueKey(value);
        return revertingKeys.has(k) && !remainingKeys.has(k) && currentKeys.has(k);
      });
      // Identifiers of the reverted sources must leave the target whatever happened, they are restored on the sources.
      if (key === IDS_STIX) {
        reverting.forEach((source) => {
          [source.standard_id, ...asArray(source.attributes[IDS_STIX])].forEach((id) => {
            if (currentKeys.has(valueKey(id)) && !toRemove.some((value) => valueKey(value) === valueKey(id))) {
              toRemove.push(id);
            }
          });
        });
      }
      if (toRemove.length > 0) {
        const removeKeys = toKeySet(toRemove);
        // The remaining values replace the attribute: an alias input is always applied as a replacement by the update
        // (its operation is not kept), and the target is locked for the whole unmerge.
        inputs.push({ key, value: asArray(current).filter((value) => !removeKeys.has(valueKey(value))), operation: 'replace' });
      }
      return;
    }
    // Mono-valued: the merge only fills empty fields, revert the filling if the value is still the merged one.
    if (!isEmptyValue(pre) || isEmptyValue(post)) return;
    if (valueKey(current) !== valueKey(post)) return;
    const filledByReverted = reverting.some((source) => valueKey(source.attributes[key]) === valueKey(post));
    const filledByRemaining = remaining.some((source) => valueKey(source.attributes[key]) === valueKey(post));
    if (filledByReverted && !filledByRemaining) {
      inputs.push({ key, value: [], operation: 'replace' });
    }
  });
  refsDescriptors.forEach(({ name, multiple }) => {
    const pre = refIds(target.refs, name);
    const post = refIds(target.post_refs, name);
    const current = refIds(live.refs, name);
    if (multiple) {
      const revertingIds = new Set(reverting.flatMap((source) => refIds(source.refs, name)));
      const remainingIds = new Set(remaining.flatMap((source) => refIds(source.refs, name)));
      const toRemove = post.filter((id) => !pre.includes(id) && revertingIds.has(id) && !remainingIds.has(id) && current.includes(id));
      if (toRemove.length > 0) {
        inputs.push({ key: name, value: toRemove, operation: 'remove' });
      }
      if (isFullRevert) {
        // Values the merge removed from the target (for example markings superseded by a source marking).
        const toAdd = pre.filter((id) => !post.includes(id) && !current.includes(id));
        if (toAdd.length > 0) {
          inputs.push({ key: name, value: toAdd, operation: 'add' });
        }
      }
      return;
    }
    if (pre.length > 0 || post.length === 0 || current[0] !== post[0]) return;
    const filledByReverted = reverting.some((source) => refIds(source.refs, name)[0] === post[0]);
    const filledByRemaining = remaining.some((source) => refIds(source.refs, name)[0] === post[0]);
    if (filledByReverted && !filledByRemaining) {
      inputs.push({ key: name, value: [], operation: 'replace' });
    }
  });
  return inputs;
};

// Failures that recreating a relationship removed by a merge can never overcome: an endpoint or a reference is gone, or
// the relationship is not allowed anymore. Any other failure (locks, storage) is transient: the unmerge stops and resumes.
const IRRECOVERABLE_RECREATION_ERRORS = [MISSING_REF_ERROR, ALREADY_DELETED_ERROR, VALIDATION_ERROR, FUNCTIONAL_ERROR];

export const isIrrecoverableRecreationError = (error: unknown): boolean => {
  const code = (error as { extensions?: { code?: unknown } } | null | undefined)?.extensions?.code;
  return typeof code === 'string' && IRRECOVERABLE_RECREATION_ERRORS.includes(code);
};
