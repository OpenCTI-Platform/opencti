import { afterAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { findById, labelDelete } from '../../../../src/domain/label';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import { getLabelStandardId, importLabel } from '../../../../src/modules/label/label-import';
import { labelsFamily } from '../../../../src/modules/configPreset/registry/labels-configPreset-registry';
import { exportConfigPresetItem } from '../../../../src/modules/configPreset/configPreset-registry';

// One word: the search is an OR of the words of the term, and the word "label" matches the entity type of every label
const VALUE_A = 'ConfigPresetLabelA';
const VALUE_B = 'ConfigPresetLabelB';
const mode = ConfigImportMode.Overwrite;

describe('Label import and export (configuration preset)', () => {
  afterAll(async () => {
    for (const value of [VALUE_A, VALUE_B]) {
      const label = await findById(testContext, ADMIN_USER, value);
      if (label) {
        await labelDelete(testContext, ADMIN_USER, label.id);
      }
    }
  });

  it('writes nothing on a dry run, and creates the label otherwise', async () => {
    expect(await importLabel(testContext, ADMIN_USER, { value: VALUE_A, color: '#112233' }, { mode, dryRun: true })).toMatchObject({ status: 'created', exists: false });
    expect(await findById(testContext, ADMIN_USER, VALUE_A)).toBeFalsy();
    expect(await importLabel(testContext, ADMIN_USER, { value: VALUE_A, color: '#112233' }, { mode })).toMatchObject({ status: 'created', exists: false });
    expect(await findById(testContext, ADMIN_USER, VALUE_A)).toMatchObject({ value: VALUE_A, color: '#112233', standard_id: getLabelStandardId(VALUE_A) });
  });

  it('finds the label by its value whatever its case, and never duplicates it', async () => {
    const before = await labelsFamily.resolveItems(testContext, ADMIN_USER, [getLabelStandardId(VALUE_A)], []);
    expect(await importLabel(testContext, ADMIN_USER, { value: VALUE_A.toUpperCase() }, { mode })).toMatchObject({ status: 'skipped', code: 'unchanged', exists: true });
    expect(await importLabel(testContext, ADMIN_USER, { value: VALUE_A, color: '#112233' }, { mode })).toMatchObject({ status: 'skipped', code: 'unchanged', exists: true });
    const after = await labelsFamily.resolveItems(testContext, ADMIN_USER, [getLabelStandardId(VALUE_A)], []);
    expect(before).toHaveLength(1);
    expect(after).toHaveLength(1);
  });

  it('refuses an existing label in add mode, and gives it the color of the configuration in overwrite mode', async () => {
    expect(await importLabel(testContext, ADMIN_USER, { value: VALUE_A, color: '#445566' }, { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists' });
    expect(await findById(testContext, ADMIN_USER, VALUE_A)).toMatchObject({ color: '#112233' });
    expect(await importLabel(testContext, ADMIN_USER, { value: VALUE_A, color: '#445566' }, { mode, dryRun: true })).toMatchObject({ status: 'overwritten', exists: true });
    expect(await findById(testContext, ADMIN_USER, VALUE_A)).toMatchObject({ color: '#112233' });
    expect(await importLabel(testContext, ADMIN_USER, { value: VALUE_A, color: '#445566' }, { mode })).toMatchObject({ status: 'overwritten', exists: true });
    expect(await findById(testContext, ADMIN_USER, VALUE_A)).toMatchObject({ color: '#445566' });
  });

  it('gives a new label without color the one the platform makes of its value', async () => {
    expect(await importLabel(testContext, ADMIN_USER, { value: VALUE_B }, { mode })).toMatchObject({ status: 'created' });
    expect(await findById(testContext, ADMIN_USER, VALUE_B)).toMatchObject({ color: expect.stringMatching(/^#[0-9a-f]{6}$/) });
  });

  it('lists, searches and resolves the labels through the family, by value', async () => {
    const idA = getLabelStandardId(VALUE_A);
    const idB = getLabelStandardId(VALUE_B);
    const page = await labelsFamily.listItems(testContext, ADMIN_USER, { first: 10, search: 'ConfigPresetLabel' });
    expect(page.edges.map(({ node }) => [node.id, node.label, node.translatable])).toEqual([[idA, VALUE_A, false], [idB, VALUE_B, false]]);
    expect(page.pageInfo.globalCount).toBe(2);
    expect((await labelsFamily.listItems(testContext, ADMIN_USER, { ids: [idB] })).edges.map(({ node }) => node.id)).toEqual([idB]);
    expect((await labelsFamily.listItems(testContext, ADMIN_USER, { ids: [] })).edges).toEqual([]);
    expect((await labelsFamily.resolveItems(testContext, ADMIN_USER, [idA, idB], [idA])).map(({ id }) => id)).toEqual([idB]);
    expect((await labelsFamily.resolveItems(testContext, ADMIN_USER, [], [])).map(({ id }) => id)).toEqual([]);
  });

  it('imports an export back, whatever the platform it comes from', async () => {
    const [item] = await labelsFamily.resolveItems(testContext, ADMIN_USER, [getLabelStandardId(VALUE_A)], []);
    const file = await exportConfigPresetItem(testContext, ADMIN_USER, labelsFamily, item);
    expect(file).toMatchObject({ type: 'taxonomy.labels', id: getLabelStandardId(VALUE_A), configuration: { value: VALUE_A, color: '#445566' } });
    const existing = await findById(testContext, ADMIN_USER, VALUE_A);
    await labelDelete(testContext, ADMIN_USER, existing.id);
    expect(await importLabel(testContext, ADMIN_USER, file.configuration, { mode })).toMatchObject({ status: 'created', exists: false });
    expect(await findById(testContext, ADMIN_USER, VALUE_A)).toMatchObject({ value: VALUE_A, color: '#445566' });
  });
});
