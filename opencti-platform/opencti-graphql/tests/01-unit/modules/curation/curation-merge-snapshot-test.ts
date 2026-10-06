import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { hasFileNameCollision, snapshotAttributes, unmergeLockIds } from '../../../../src/modules/curation/curation-merge-record';
import { generateAliasesId } from '../../../../src/schema/identifier';
import { computeTargetRevertInputs } from '../../../../src/modules/curation/curation-merge-diff';
import { FIELD_AUTHORITY_ATTRIBUTE } from '../../../../src/modules/curation/curation-field-authority';
import type { MergeSourceSnapshot, MergeTargetSnapshot } from '../../../../src/modules/curation/curation-types';
import { ENTITY_TYPE_INTRUSION_SET } from '../../../../src/schema/stixDomainObject';

const fieldAuthority = [{ attribute: 'description', source_type: 'connector', source_id: 'connector-id', updated_at: '2026-10-01T00:00:00.000Z' }];

describe('curation merge snapshots', () => {
  it('holds during an unmerge the identifiers a creation named after an alias of a restored source would lock', () => {
    const source = (internalId: string, aliases: string[], revertedAt?: string) => ({
      internal_id: internalId,
      standard_id: `intrusion-set--${internalId}`,
      entity_type: ENTITY_TYPE_INTRUSION_SET,
      attributes: { name: internalId, aliases },
      contributed_stix_ids: [`intrusion-set--contributed-${internalId}`],
      reverted_at: revertedAt,
    });
    const record = {
      internal_id: 'record-id',
      merge_target_id: 'target-id',
      merge_snapshot: { sources: [source('clop', ['FIN11']), source('restored', ['TA505'], '2026-10-01T00:00:00.000Z')] },
    } as unknown as Parameters<typeof unmergeLockIds>[0];
    const ids = unmergeLockIds(record);
    const [fin11] = generateAliasesId(['FIN11'], { entity_type: ENTITY_TYPE_INTRUSION_SET });
    expect(ids).toEqual(expect.arrayContaining(['record-id', 'target-id', 'clop', 'intrusion-set--clop', 'intrusion-set--contributed-clop', fin11]));
    // A source already restored is not held.
    expect(ids).not.toContain('restored');
    expect(ids).not.toContain(generateAliasesId(['TA505'], { entity_type: ENTITY_TYPE_INTRUSION_SET })[0]);
  });

  it('keeps the field authority bookkeeping of a merged entity, so that its restoration gets it back', () => {
    const attributes = snapshotAttributes({
      entity_type: ENTITY_TYPE_INTRUSION_SET,
      name: 'clop',
      description: 'From the feed',
      [FIELD_AUTHORITY_ATTRIBUTE]: fieldAuthority,
      i_aliases_ids: ['aliases-id'],
      creator_id: ['connector-user-id'],
    });
    expect(attributes[FIELD_AUTHORITY_ATTRIBUTE]).toEqual(fieldAuthority);
    expect(attributes).toMatchObject({ name: 'clop', description: 'From the feed', creator_id: ['connector-user-id'] });
    // The other internal fields are computed again when the entity is restored.
    expect(attributes).not.toHaveProperty('i_aliases_ids');
    expect(snapshotAttributes({ entity_type: ENTITY_TYPE_INTRUSION_SET, name: 'clop' })).not.toHaveProperty(FIELD_AUTHORITY_ATTRIBUTE);
  });

  it('never reverts the field authority bookkeeping of the merge target', () => {
    const target = {
      internal_id: 'target-1',
      standard_id: 'intrusion-set--target-1',
      entity_type: ENTITY_TYPE_INTRUSION_SET,
      name: 'Cl0p',
      attributes: { name: 'Cl0p', [FIELD_AUTHORITY_ATTRIBUTE]: [] },
      refs: {},
      post_attributes: { name: 'Cl0p', [FIELD_AUTHORITY_ATTRIBUTE]: fieldAuthority },
      post_refs: {},
    } as unknown as MergeTargetSnapshot;
    const source = {
      internal_id: 'source-1',
      standard_id: 'intrusion-set--source-1',
      entity_type: ENTITY_TYPE_INTRUSION_SET,
      name: 'clop',
      attributes: { name: 'clop', [FIELD_AUTHORITY_ATTRIBUTE]: fieldAuthority },
      refs: {},
    } as unknown as MergeSourceSnapshot;
    const live = { attributes: { ...target.post_attributes }, refs: {} };
    const inputs = computeTargetRevertInputs(target, live, [source], [], () => ({ multiple: true }), []);
    expect(inputs.find((input) => input.key === FIELD_AUTHORITY_ATTRIBUTE)).toBeUndefined();
  });

  it('tells a merge that would drop a source file named like a file of the target', () => {
    const entity = (internalId: string, names: string[]) => ({
      internal_id: internalId,
      entity_type: ENTITY_TYPE_INTRUSION_SET,
      x_opencti_files: names.map((name) => ({ id: `import/${ENTITY_TYPE_INTRUSION_SET}/${internalId}/${name}`, name })),
    }) as unknown as Parameters<typeof hasFileNameCollision>[0];
    const target = entity('target-1', ['report.pdf']);
    expect(hasFileNameCollision(entity('source-1', ['report.pdf', 'other.pdf']), target)).toBe(true);
    expect(hasFileNameCollision(entity('source-1', ['other.pdf']), target)).toBe(false);
    expect(hasFileNameCollision(entity('source-1', []), target)).toBe(false);
  });
});
