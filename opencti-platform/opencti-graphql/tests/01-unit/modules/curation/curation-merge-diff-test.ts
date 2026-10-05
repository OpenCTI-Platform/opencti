import { describe, expect, it } from 'vitest';
import { computeTargetRevertInputs, isIrrecoverableRecreationError } from '../../../../src/modules/curation/curation-merge-diff';
import { DatabaseError, FunctionalError, LockTimeoutError, MissingReferenceError, ValidationError } from '../../../../src/config/errors';
import type { MergeSourceSnapshot, MergeTargetSnapshot } from '../../../../src/modules/curation/curation-types';

const MULTIPLE = new Set(['aliases', 'x_opencti_stix_ids', 'labels_text', 'creator_id']);
const describeAttribute = (key: string) => ({ name: key, multiple: MULTIPLE.has(key) });

const source = (overrides: Partial<MergeSourceSnapshot>): MergeSourceSnapshot => ({
  internal_id: 'source-1',
  standard_id: 'intrusion-set--source-1',
  entity_type: 'Intrusion-Set',
  name: 'clop',
  attributes: { name: 'clop', aliases: ['TA505'], x_opencti_stix_ids: ['intrusion-set--legacy'] },
  refs: {},
  redirected: [],
  recreatable: [],
  moved_file_ids: [],
  contributed_aliases: ['clop', 'TA505'],
  contributed_stix_ids: ['intrusion-set--source-1', 'intrusion-set--legacy'],
  reverted_at: null,
  ...overrides,
} as MergeSourceSnapshot);

const target: MergeTargetSnapshot = {
  internal_id: 'target-1',
  standard_id: 'intrusion-set--target-1',
  entity_type: 'Intrusion-Set',
  name: 'Cl0p',
  attributes: { name: 'Cl0p', aliases: ['Graceful Spider'], description: 'Kept' },
  refs: {},
  post_attributes: {
    name: 'Cl0p',
    aliases: ['Graceful Spider', 'clop', 'TA505', 'FIN11'],
    x_opencti_stix_ids: ['intrusion-set--source-1', 'intrusion-set--legacy', 'intrusion-set--other'],
    description: 'Kept',
  },
  post_refs: {},
  taken_from_source_id: 'source-1',
} as MergeTargetSnapshot;

describe('curation merge revert inputs', () => {
  it('replaces the multiple attributes with what remains once the reverted source contributions are removed', () => {
    const live = {
      attributes: {
        name: 'Cl0p',
        aliases: ['Graceful Spider', 'clop', 'TA505', 'FIN11', 'Added later'],
        x_opencti_stix_ids: ['intrusion-set--source-1', 'intrusion-set--legacy', 'intrusion-set--other'],
        description: 'Kept',
      },
      refs: {},
    };
    const other = source({
      internal_id: 'source-2',
      standard_id: 'intrusion-set--other',
      name: 'FIN11',
      attributes: { name: 'FIN11' },
      contributed_aliases: ['FIN11'],
      contributed_stix_ids: ['intrusion-set--other'],
    });
    const inputs = computeTargetRevertInputs(target, live, [source({})], [other], describeAttribute, []);
    const aliases = inputs.find((input) => input.key === 'aliases');
    // The source name and alias leave, the pre-merge alias, the other source's name and a later edit stay.
    expect(aliases).toEqual({ key: 'aliases', operation: 'replace', value: ['Graceful Spider', 'FIN11', 'Added later'] });
    const stixIds = inputs.find((input) => input.key === 'x_opencti_stix_ids');
    expect(stixIds).toEqual({ key: 'x_opencti_stix_ids', operation: 'replace', value: ['intrusion-set--other'] });
    expect(inputs.find((input) => input.key === 'description')).toBeUndefined();
  });

  it('removes nothing that is already gone (a resumed unmerge)', () => {
    const live = { attributes: { name: 'Cl0p', aliases: ['Graceful Spider'], x_opencti_stix_ids: [] }, refs: {} };
    expect(computeTargetRevertInputs(target, live, [source({})], [], describeAttribute, [])).toEqual([]);
  });

  it('takes back the creators only the reverted source brought, keeping the target creators and the merging user', () => {
    const withCreators: MergeTargetSnapshot = {
      ...target,
      attributes: { ...target.attributes, creator_id: ['analyst-id'] },
      post_attributes: { ...target.post_attributes, creator_id: ['analyst-id', 'connector-a-id', 'connector-b-id', 'merging-user-id'] },
    };
    const reverted = source({ attributes: { name: 'clop', aliases: ['TA505'], creator_id: ['connector-a-id'] } });
    const other = source({
      internal_id: 'source-2',
      standard_id: 'intrusion-set--other',
      name: 'FIN11',
      attributes: { name: 'FIN11', creator_id: ['connector-b-id'] },
      contributed_aliases: ['FIN11'],
      contributed_stix_ids: ['intrusion-set--other'],
    });
    const live = { attributes: { ...withCreators.post_attributes }, refs: {} };
    const inputs = computeTargetRevertInputs(withCreators, live, [reverted], [other], describeAttribute, []);
    expect(inputs.find((input) => input.key === 'creator_id')).toEqual({
      key: 'creator_id',
      operation: 'replace',
      value: ['analyst-id', 'connector-b-id', 'merging-user-id'],
    });
  });
});

describe('Curation unmerge - relationship recreation failures', () => {
  it('skips the relationships that can never be recreated', () => {
    expect(isIrrecoverableRecreationError(MissingReferenceError({ input: { fromId: 'gone' } }))).toBe(true);
    expect(isIrrecoverableRecreationError(ValidationError('Relation not allowed', 'relationship_type'))).toBe(true);
    expect(isIrrecoverableRecreationError(FunctionalError('Relation not supported'))).toBe(true);
  });

  it('stops the unmerge on transient failures so that it is resumed', () => {
    expect(isIrrecoverableRecreationError(LockTimeoutError({ participantIds: ['relationship-1'] }))).toBe(false);
    expect(isIrrecoverableRecreationError(DatabaseError('Bulk failed'))).toBe(false);
    expect(isIrrecoverableRecreationError(new Error('socket hang up'))).toBe(false);
    expect(isIrrecoverableRecreationError(undefined)).toBe(false);
  });
});
