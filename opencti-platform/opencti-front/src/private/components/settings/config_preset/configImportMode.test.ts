import { describe, expect, it } from 'vitest';
import { configImportModeKey, isConfigImportMode, sharedConfigImportMode, toItemModes, withConfigImportMode, withConfigImportModeForItems } from './configImportMode';
import { toConfigImportModes } from './import/configPresetImportSelection';

describe('Config preset import mode', () => {
  it('knows the modes of the backend', () => {
    expect(['OVERWRITE', 'COPY'].every(isConfigImportMode)).toBe(true);
    expect(['ADD', '%future added value'].some(isConfigImportMode)).toBe(false);
  });

  it('sets the mode of an item, and drops the entry of the default one', () => {
    const copy = withConfigImportMode({ 'messages/banner': 'COPY' }, 'branding', 'theme-1', 'COPY');
    expect(copy).toEqual({ 'messages/banner': 'COPY', 'branding/theme-1': 'COPY' });
    expect(withConfigImportMode(copy, 'branding', 'theme-1', 'OVERWRITE')).toEqual({ 'messages/banner': 'COPY' });
    expect(withConfigImportMode({}, 'branding', 'theme-1', 'OVERWRITE')).toEqual({});
  });

  it('gives the modes of the items of a type, and only of this type', () => {
    const modes = { 'branding/theme-1': 'COPY', 'branding/theme--2': 'COPY', 'brandingX/theme-1': 'COPY', 'messages/banner': 'COPY' } as const;
    expect(toItemModes(modes, 'branding')).toEqual([{ key: 'theme-1', mode: 'COPY' }, { key: 'theme--2', mode: 'COPY' }]);
    expect(toItemModes(modes, 'platform')).toEqual([]);
    expect(configImportModeKey('branding', 'theme-1')).toBe('branding/theme-1');
  });

  it('sets the same mode on several items at once, leaving the others as they are', () => {
    const modes = withConfigImportModeForItems({ 'branding/theme-3': 'COPY', 'messages/banner': 'COPY' }, 'branding', ['theme-1', 'theme-2'], 'COPY');
    expect(modes).toEqual({ 'branding/theme-3': 'COPY', 'messages/banner': 'COPY', 'branding/theme-1': 'COPY', 'branding/theme-2': 'COPY' });
    // Overwrite is the default: the entries go
    expect(withConfigImportModeForItems(modes, 'branding', ['theme-1', 'theme-2', 'theme-3'], 'OVERWRITE')).toEqual({ 'messages/banner': 'COPY' });
  });

  it('tells the mode that items share, null when they differ', () => {
    expect(sharedConfigImportMode({}, 'branding', ['theme-1', 'theme-2'])).toBe('OVERWRITE');
    expect(sharedConfigImportMode({ 'branding/theme-1': 'COPY', 'branding/theme-2': 'COPY' }, 'branding', ['theme-1', 'theme-2'])).toBe('COPY');
    expect(sharedConfigImportMode({ 'branding/theme-1': 'COPY' }, 'branding', ['theme-1', 'theme-2'])).toBeNull();
    // The modes of another type do not count
    expect(sharedConfigImportMode({ 'messages/theme-1': 'COPY' }, 'branding', ['theme-1'])).toBe('OVERWRITE');
  });

  it('reads the modes of the saved selection, without the default one or an unknown one, and none when a selection has none', () => {
    expect(toConfigImportModes([
      { type: 'branding', item_modes: [{ key: 'theme-1', mode: 'COPY' }, { key: 'theme-2', mode: 'OVERWRITE' }, { key: 'theme-3', mode: 'SOMETHING' }] },
      { type: 'messages', item_modes: null },
      { type: 'platform' },
    ])).toEqual({ 'branding/theme-1': 'COPY' });
  });
});
