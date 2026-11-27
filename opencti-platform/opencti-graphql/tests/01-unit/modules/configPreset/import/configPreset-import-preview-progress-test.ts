import { afterEach, describe, expect, it, vi } from 'vitest';
import { getConfigPresetImportPreviewProgress, trackConfigPresetImportPreview } from '../../../../../src/modules/configPreset/import/configPreset-import-preview-progress';
import { computeConfigPresetItems } from '../../../../../src/modules/configPreset/import/configPreset-import-domain';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import type { ConfigPresetBundleItem } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';

const USER = 'user-id';
const FILE = 'config_preset/import/id/bundle.zip';

describe('Config preset import: how far the preview has got', () => {
  it('knows nothing of a file whose preview does not run', () => {
    expect(getConfigPresetImportPreviewProgress(USER, FILE)).toBeNull();
  });

  it('starts at zero, only goes up, never says it is done, and is gone when the preview ends', () => {
    const progress = trackConfigPresetImportPreview(USER, FILE);
    expect(getConfigPresetImportPreviewProgress(USER, FILE)).toBe(0);
    progress.set(30.4);
    expect(getConfigPresetImportPreviewProgress(USER, FILE)).toBe(30);
    progress.set(10);
    expect(getConfigPresetImportPreviewProgress(USER, FILE)).toBe(30);
    progress.set(100);
    expect(getConfigPresetImportPreviewProgress(USER, FILE)).toBe(99);
    progress.end();
    expect(getConfigPresetImportPreviewProgress(USER, FILE)).toBeNull();
  });

  it('keeps the progress of the file for the user who asks only', () => {
    const progress = trackConfigPresetImportPreview(USER, FILE);
    progress.set(50);
    expect(getConfigPresetImportPreviewProgress('another-user', FILE)).toBeNull();
    expect(getConfigPresetImportPreviewProgress(USER, 'config_preset/import/other/bundle.zip')).toBeNull();
    progress.end();
  });

  it('lives until the last of the previews of the same file ends, and an end told twice counts once', () => {
    const first = trackConfigPresetImportPreview(USER, FILE);
    const second = trackConfigPresetImportPreview(USER, FILE);
    second.set(40);
    first.end();
    first.end();
    expect(getConfigPresetImportPreviewProgress(USER, FILE)).toBe(40);
    second.end();
    expect(getConfigPresetImportPreviewProgress(USER, FILE)).toBeNull();
  });
});

describe('Config preset import: the progress of the computation of the items', () => {
  const context = { source: 'test' } as AuthContext;
  const user = { id: USER } as AuthUser;
  const labelItems = (count: number): ConfigPresetBundleItem[] => Array.from({ length: count }, (_, i) => ({
    type: 'labels',
    id: `label--${i}`,
    path: `taxonomy/labels/label--${i}.json`,
    configuration: { value: `label ${i}` },
  }));

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('tells how far the preparation and then the items have got, from 0 to 1 and never back', async () => {
    const labels = CONFIG_PRESET_FAMILIES.find(({ id }) => id === 'labels')!.importer!;
    vi.spyOn(labels, 'prepare').mockImplementation(async (_context, _user, items, plan) => {
      plan.onPrepared?.(items.length / 2, items.length);
      plan.onPrepared?.(items.length, items.length);
    });
    vi.spyOn(labels, 'compute').mockResolvedValue({ label: 'label', translatable: false, exists: false, conflict: false, status: 'created' });
    const fractions: number[] = [];
    await computeConfigPresetItems(context, user, labelItems(1200), { onProgress: (fraction) => fractions.push(fraction) });
    expect(fractions[0]).toBeCloseTo(0.325);
    expect(fractions.every((fraction, index) => index === 0 || fraction >= fractions[index - 1])).toBe(true);
    expect(fractions.every((fraction) => fraction >= 0 && fraction <= 1)).toBe(true);
    // Once prepared, the items tell it every 500 of them
    expect(fractions.filter((fraction) => fraction > 0.65)).toHaveLength(2);
    expect(Math.max(...fractions)).toBeLessThan(1);
  });

  it('computes as before without anyone to tell', async () => {
    const labels = CONFIG_PRESET_FAMILIES.find(({ id }) => id === 'labels')!.importer!;
    vi.spyOn(labels, 'prepare').mockResolvedValue(undefined);
    vi.spyOn(labels, 'compute').mockResolvedValue({ label: 'label', translatable: false, exists: false, conflict: false, status: 'created' });
    expect(await computeConfigPresetItems(context, user, labelItems(3))).toHaveLength(3);
  });
});
