import { afterEach, describe, expect, it } from 'vitest';
import { CONFIG_PRESET_FAMILIES, configPresetRequiresEnterpriseEdition } from '../../../../src/modules/configPreset/configPreset-registry';

describe('configPresetRequiresEnterpriseEdition', () => {
  const messages = CONFIG_PRESET_FAMILIES.find((family) => family.id === 'messages')!;

  afterEach(() => {
    delete messages.requiresEnterpriseEdition;
  });

  it('is true for the whitemark, by the flag of the item', () => {
    expect(configPresetRequiresEnterpriseEdition('branding', 'whitemark')).toBe(true);
  });

  it('is false for the other items, never null', () => {
    expect(configPresetRequiresEnterpriseEdition('branding', 'theme--11111111-2222-4333-8444-555555555555')).toBe(false);
    expect(configPresetRequiresEnterpriseEdition('platform', 'platform')).toBe(false);
    expect(configPresetRequiresEnterpriseEdition('messages', 'banner')).toBe(false);
    expect(configPresetRequiresEnterpriseEdition('unknownFamily', 'x')).toBe(false);
  });

  it('falls back on the flag of the family when the item has none, also for an item with no definition on the target', () => {
    messages.requiresEnterpriseEdition = true;
    expect(configPresetRequiresEnterpriseEdition('messages', 'banner')).toBe(true);
    expect(configPresetRequiresEnterpriseEdition('messages', 'an-item-that-does-not-exist')).toBe(true);
    // The flag of the item wins over the one of the family
    const branding = CONFIG_PRESET_FAMILIES.find((family) => family.id === 'branding')!;
    branding.requiresEnterpriseEdition = false;
    expect(configPresetRequiresEnterpriseEdition('branding', 'whitemark')).toBe(true);
    delete branding.requiresEnterpriseEdition;
  });
});
