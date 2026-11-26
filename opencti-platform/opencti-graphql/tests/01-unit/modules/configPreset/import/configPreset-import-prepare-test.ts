import { afterEach, describe, expect, it, vi } from 'vitest';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import { buildConfigPresetImportTypes, computeConfigPresetItems, finalizeConfigPresetItems } from '../../../../../src/modules/configPreset/import/configPreset-import-domain';
import type { ConfigPresetBundle, ConfigPresetBundleItem, ConfigPresetComputedItem } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const computedItem: ConfigPresetComputedItem = { label: 'item', translatable: false, exists: false, conflict: false, status: 'created' };
const bundleItem = (type: string, id: string, path = `${type}/${id}.json`): ConfigPresetBundleItem => ({ type, id, path, configuration: {} });
const family = (id: string) => CONFIG_PRESET_FAMILIES.find((candidate) => candidate.id === id)!;

afterEach(() => {
  vi.restoreAllMocks();
});

describe('Config preset compute: what the importers read ahead', () => {
  const items = [bundleItem('labels', 'a'), bundleItem('messages', 'banner'), bundleItem('labels', 'b')];

  it('lets the importer of a family read what all its items need once, with the items of this family only', async () => {
    const prepare = vi.spyOn(family('labels').importer!, 'prepare').mockResolvedValue(undefined);
    vi.spyOn(family('labels').importer!, 'compute').mockResolvedValue(computedItem);
    vi.spyOn(family('messages').importer!, 'compute').mockResolvedValue(computedItem);
    await computeConfigPresetItems(context, user, items, { availability: new Map([['labels', true], ['messages', true]]) });
    expect(prepare).toHaveBeenCalledTimes(1);
    expect(prepare.mock.calls[0][2].map(({ id }) => id)).toEqual(['a', 'b']);
  });

  it('prepares before it computes the first item, and gives the importer the plan it computes with', async () => {
    const order: string[] = [];
    const prepare = vi.spyOn(family('labels').importer!, 'prepare').mockImplementation(async () => {
      order.push('prepare');
    });
    const compute = vi.spyOn(family('labels').importer!, 'compute').mockImplementation(async () => {
      order.push('compute');
      return computedItem;
    });
    vi.spyOn(family('messages').importer!, 'compute').mockResolvedValue(computedItem);
    await computeConfigPresetItems(context, user, items, { availability: new Map([['labels', true], ['messages', true]]) });
    expect(order).toEqual(['prepare', 'compute', 'compute']);
    expect(prepare.mock.calls[0][3]).toBe(compute.mock.calls[0][3]);
  });

  it('does not prepare a family the platform cannot use: its importer is never called', async () => {
    const prepare = vi.spyOn(family('labels').importer!, 'prepare').mockResolvedValue(undefined);
    vi.spyOn(family('messages').importer!, 'compute').mockResolvedValue(computedItem);
    await computeConfigPresetItems(context, user, items, { availability: new Map([['labels', false], ['messages', true]]) });
    expect(prepare).not.toHaveBeenCalled();
  });

  it('does not prepare a family that has no item', async () => {
    const prepare = vi.spyOn(family('labels').importer!, 'prepare').mockResolvedValue(undefined);
    vi.spyOn(family('messages').importer!, 'compute').mockResolvedValue(computedItem);
    await computeConfigPresetItems(context, user, [bundleItem('messages', 'banner')], { availability: new Map([['messages', true]]) });
    expect(prepare).not.toHaveBeenCalled();
  });
});

describe('Config preset import: what the importers do at the end', () => {
  const items = [bundleItem('labels', 'a'), bundleItem('messages', 'banner')];
  const plan = { created: new Set<string>() };

  it('lets the importer of a family that had items finalize once, with the plan', async () => {
    const finalize = vi.spyOn(family('labels').importer!, 'finalize').mockResolvedValue(undefined);
    await finalizeConfigPresetItems(context, user, items, plan, new Map([['labels', true], ['messages', true]]));
    expect(finalize).toHaveBeenCalledTimes(1);
    expect(finalize).toHaveBeenCalledWith(context, user, plan);
  });

  it('does not finalize a family without items, nor one the platform cannot use', async () => {
    const finalize = vi.spyOn(family('labels').importer!, 'finalize').mockResolvedValue(undefined);
    await finalizeConfigPresetItems(context, user, [bundleItem('messages', 'banner')], plan, new Map([['labels', true], ['messages', true]]));
    await finalizeConfigPresetItems(context, user, items, plan, new Map([['labels', false], ['messages', true]]));
    expect(finalize).not.toHaveBeenCalled();
  });

  it('does not fail when a finalize fails', async () => {
    vi.spyOn(family('labels').importer!, 'finalize').mockRejectedValue(new Error('search down'));
    await expect(finalizeConfigPresetItems(context, user, items, plan, new Map([['labels', true]]))).resolves.toBeUndefined();
  });
});

describe('Config preset compute: a request that was cancelled', () => {
  const items = [bundleItem('labels', 'a'), bundleItem('labels', 'b'), bundleItem('labels', 'c')];

  it('stops at the next item, and a context without a signal (a real import) never stops', async () => {
    const controller = new AbortController();
    const compute = vi.spyOn(family('labels').importer!, 'compute').mockImplementation(async (_context, _user, item) => {
      if (item.id === 'a') {
        controller.abort();
      }
      return computedItem;
    });
    vi.spyOn(family('labels').importer!, 'prepare').mockResolvedValue(undefined);
    const availability = new Map([['labels', true]]);
    await expect(computeConfigPresetItems({ ...context, requestAbortSignal: controller.signal }, user, items, { availability })).rejects.toMatchObject({
      extensions: { code: 'CLIENT_ABORT_ERROR' },
    });
    expect(compute).toHaveBeenCalledTimes(1);
    compute.mockClear();
    expect(await computeConfigPresetItems(context, user, items, { availability })).toHaveLength(3);
    expect(compute).toHaveBeenCalledTimes(3);
  });
});

describe('Config preset preview: the dependencies of the items', () => {
  const dependencyPath = (id: string) => `platform_settings/branding/${id}.json`;
  const themes = [bundleItem('branding', 'theme-a', dependencyPath('theme-a')), bundleItem('branding', 'theme-b', dependencyPath('theme-b')), bundleItem('branding', 'theme-c', dependencyPath('theme-c'))];
  const labels = [bundleItem('labels', 'label-1'), bundleItem('labels', 'label-2')];
  const platform = bundleItem('platform', 'platform');
  const build = (dependencies: ConfigPresetBundle['dependencies']) => {
    const items = [...themes, ...labels, platform];
    const bundle: ConfigPresetBundle = { metadata: { openCTI_version: '7.0.0', generated_at: 'x', bundle_name: null }, items, dependencies, ignored: [] };
    const results = items.map((item) => ({ item, computed: computedItem }));
    const availability = new Map(['branding', 'labels', 'platform'].map((id) => [id, true]));
    const types = buildConfigPresetImportTypes(bundle, results, availability);
    return Object.fromEntries(types.map((type) => [type.key, Object.fromEntries(type.items.map((entry) => [entry.key, entry.dependsOn]))]));
  };

  it('lists what an item depends on, in the order of the bundle, whatever the order of its dependencies', () => {
    const types = build({ 'platformSettings.platform': { platform: { 'theme-c': dependencyPath('theme-c'), 'theme-a': dependencyPath('theme-a') } } });
    expect(types.platform.platform).toEqual([{ type: 'branding', key: 'theme-a' }, { type: 'branding', key: 'theme-c' }]);
  });

  it('gives an empty list to an item without dependency', () => {
    const types = build({ 'platformSettings.platform': { platform: { 'theme-a': dependencyPath('theme-a') } } });
    expect(types.labels).toEqual({ 'label-1': [], 'label-2': [] });
    expect(types.branding['theme-a']).toEqual([]);
  });

  it('lists a dependency once, and ignores one that is not in the bundle', () => {
    const types = build({ 'platformSettings.platform': { platform: { 'theme-a': dependencyPath('theme-a'), 'theme-a-again': dependencyPath('theme-a'), missing: 'platform_settings/branding/missing.json' } } });
    expect(types.platform.platform).toEqual([{ type: 'branding', key: 'theme-a' }]);
  });
});
