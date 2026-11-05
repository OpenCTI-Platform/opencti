import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  storeLoadById: vi.fn(),
}));
vi.mock('../../../../src/domain/label', () => ({ createLabel: vi.fn(), labelEditField: vi.fn() }));

import { storeLoadById } from '../../../../src/database/middleware-loader';
import { createLabel, labelEditField } from '../../../../src/domain/label';
import { ENTITY_TYPE_LABEL } from '../../../../src/schema/stixMetaObject';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import { getLabelStandardId, importLabel } from '../../../../src/modules/label/label-import';
import { labelImportSchema } from '../../../../src/modules/label/label-import-schema';
import { exportLabel } from '../../../../src/modules/label/label-export';
import type { BasicStoreEntityLabel } from '../../../../src/modules/label/label-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const stored = { id: 'label-internal-id', standard_id: getLabelStandardId('APT'), value: 'APT', color: '#ff0000' } as BasicStoreEntityLabel;

const withExisting = (label?: BasicStoreEntityLabel) => vi.mocked(storeLoadById).mockResolvedValue(label as never);

beforeEach(() => {
  vi.resetAllMocks();
  withExisting(undefined);
  // Like the domain: a label without color is given the one the platform makes of its value
  vi.mocked(createLabel).mockImplementation(async (_context, _user, label) => ({ label: { ...stored, value: label.value, color: label.color ?? '#123456' }, created: true }));
});

describe('Label identity', () => {
  it('derives the standard id from the value, whatever its case and surrounding spaces', () => {
    expect(getLabelStandardId('APT')).toMatch(/^label--[0-9a-f-]{36}$/);
    expect(getLabelStandardId('  apt ')).toBe(getLabelStandardId('APT'));
    expect(getLabelStandardId('APT28')).not.toBe(getLabelStandardId('APT'));
  });
});

describe('Label import schema', () => {
  it('accepts a value with or without a color, and trims the value', () => {
    expect(labelImportSchema.parse({ value: ' APT ', color: '#ff0000' })).toEqual({ value: 'APT', color: '#ff0000' });
    expect(labelImportSchema.parse({ value: 'APT' })).toEqual({ value: 'APT' });
    expect(labelImportSchema.parse({ value: 'APT', color: null })).toEqual({ value: 'APT', color: null });
  });

  it.each([
    [{}],
    [{ value: '   ' }],
    [{ value: 'APT', color: 'red' }],
    [{ value: 'APT', color: 'url(https://evil)' }],
    [{ value: 'APT', color: '' }],
    [{ value: 'APT', standard_id: 'label--x' }],
  ])('refuses %j', (configuration) => {
    expect(labelImportSchema.safeParse(configuration).success).toBe(false);
  });

  it('is the format of the export, so an export imports back as is', () => {
    const configuration = exportLabel({ ...stored, creator_id: ['secret'] } as BasicStoreEntityLabel);
    expect(configuration).toEqual({ value: 'APT', color: '#ff0000' });
    expect(labelImportSchema.safeParse(configuration).success).toBe(true);
  });
});

describe('importLabel', () => {
  it('refuses an invalid configuration with the path of each issue, without reading the platform', async () => {
    const result = await importLabel(context, user, { value: '', color: 'red' }, { mode: ConfigImportMode.Overwrite });
    expect(result).toMatchObject({ status: 'failed', code: 'invalid', exists: false });
    expect(result.reason).toContain('value: Label value is required');
    expect(result.reason).toContain('color: Must be a hex color');
    expect(storeLoadById).not.toHaveBeenCalled();
  });

  it('finds the label by its standard id, so the case of the value does not matter', async () => {
    await importLabel(context, user, { value: 'apt' }, { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(storeLoadById).toHaveBeenCalledWith(context, user, getLabelStandardId('APT'), ENTITY_TYPE_LABEL);
  });

  describe.each([ConfigImportMode.Overwrite, ConfigImportMode.Add])('a label that does not exist (%s)', (mode) => {
    it('creates it with the given color', async () => {
      const result = await importLabel(context, user, { value: 'APT', color: '#ff0000' }, { mode });
      expect(result).toMatchObject({ status: 'created', exists: false });
      expect(createLabel).toHaveBeenCalledWith(context, user, { value: 'APT', color: '#ff0000' });
    });

    it('leaves the color to the platform when the configuration has none', async () => {
      await importLabel(context, user, { value: 'APT' }, { mode });
      expect(createLabel).toHaveBeenCalledWith(context, user, { value: 'APT', color: undefined });
    });

    it('decides the same result on a dry run, and writes nothing', async () => {
      expect(await importLabel(context, user, { value: 'APT' }, { mode, dryRun: true })).toMatchObject({ status: 'created', exists: false });
      expect(createLabel).not.toHaveBeenCalled();
    });
  });

  describe('a label that exists, overwrite', () => {
    beforeEach(() => withExisting(stored));

    it('gives it the color of the configuration', async () => {
      const result = await importLabel(context, user, { value: 'APT', color: '#00ff00' }, { mode: ConfigImportMode.Overwrite });
      expect(result).toMatchObject({ status: 'overwritten', exists: true });
      expect(labelEditField).toHaveBeenCalledWith(context, user, stored.id, [{ key: 'color', value: ['#00ff00'] }]);
      expect(createLabel).not.toHaveBeenCalled();
    });

    it('writes nothing on a dry run', async () => {
      expect(await importLabel(context, user, { value: 'APT', color: '#00ff00' }, { mode: ConfigImportMode.Overwrite, dryRun: true })).toMatchObject({ status: 'overwritten', exists: true });
      expect(labelEditField).not.toHaveBeenCalled();
    });

    it.each([
      ['has the same color, whatever its case', { value: 'APT', color: '#FF0000' }],
      ['has no color', { value: 'APT' }],
      ['has a null color', { value: 'APT', color: null }],
    ])('skips it when the configuration %s', async (_name, configuration) => {
      expect(await importLabel(context, user, configuration, { mode: ConfigImportMode.Overwrite })).toMatchObject({ status: 'skipped', code: 'unchanged', exists: true, reason: 'Already up to date' });
      expect(labelEditField).not.toHaveBeenCalled();
    });
  });

  describe('a label created by someone else since the lookup', () => {
    // createLabel writes nothing and returns it as it is, not created
    beforeEach(() => vi.mocked(createLabel).mockResolvedValue({ label: { ...stored, color: '#0000ff' }, created: false } as never));

    it('gives it the color of the configuration in overwrite mode, as an existing label', async () => {
      const result = await importLabel(context, user, { value: 'APT', color: '#00ff00' }, { mode: ConfigImportMode.Overwrite });
      expect(result).toMatchObject({ status: 'overwritten', exists: true });
      expect(labelEditField).toHaveBeenCalledWith(context, user, stored.id, [{ key: 'color', value: ['#00ff00'] }]);
    });

    it('leaves it untouched when the configuration has no color, and says it is up to date', async () => {
      expect(await importLabel(context, user, { value: 'APT' }, { mode: ConfigImportMode.Overwrite })).toMatchObject({ status: 'skipped', code: 'unchanged', exists: true });
      expect(await importLabel(context, user, { value: 'APT', color: null }, { mode: ConfigImportMode.Overwrite })).toMatchObject({ status: 'skipped', code: 'unchanged', exists: true });
      expect(labelEditField).not.toHaveBeenCalled();
    });

    it('is an existing label, not a created one, when it already has the color of the configuration', async () => {
      expect(await importLabel(context, user, { value: 'APT', color: '#0000FF' }, { mode: ConfigImportMode.Overwrite })).toMatchObject({ status: 'skipped', code: 'unchanged', exists: true });
      expect(labelEditField).not.toHaveBeenCalled();
    });

    it('refuses it in add mode, without writing', async () => {
      expect(await importLabel(context, user, { value: 'APT', color: '#00ff00' }, { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists', exists: true });
      expect(labelEditField).not.toHaveBeenCalled();
    });
  });

  it('refuses a label that exists when the mode is add', async () => {
    withExisting(stored);
    expect(await importLabel(context, user, { value: 'APT', color: '#00ff00' }, { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists', exists: true });
    expect(labelEditField).not.toHaveBeenCalled();
  });

  it('has no copy: a label is its value', async () => {
    withExisting(stored);
    expect(await importLabel(context, user, { value: 'APT' }, { mode: ConfigImportMode.Copy })).toMatchObject({ status: 'failed', code: 'copy_unsupported', exists: true });
    withExisting(undefined);
    expect(await importLabel(context, user, { value: 'APT' }, { mode: ConfigImportMode.Copy })).toMatchObject({ status: 'failed', code: 'copy_unsupported', exists: false });
    expect(createLabel).not.toHaveBeenCalled();
    expect(labelEditField).not.toHaveBeenCalled();
  });
});
