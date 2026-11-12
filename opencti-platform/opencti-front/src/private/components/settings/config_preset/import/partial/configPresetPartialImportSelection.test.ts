import { describe, expect, it } from 'vitest';
import {
  partialImportConflictKeys,
  partialImportItemModes,
  partialImportSelectedKeys,
  sharedPartialImportMode,
  toggleSelectedKey,
  withPartialImportModeForItems,
} from './configPresetPartialImportSelection';

describe('configPresetPartialImportSelection', () => {
  it('selects every item of the bundle at first', () => {
    expect([...partialImportSelectedKeys([{ key: 'a' }, { key: 'b' }])]).toEqual(['a', 'b']);
  });

  it('toggles an item without changing the given selection', () => {
    const selected = new Set(['a']);
    expect([...toggleSelectedKey(selected, 'b')]).toEqual(['a', 'b']);
    expect([...toggleSelectedKey(selected, 'a')]).toEqual([]);
    expect([...selected]).toEqual(['a']);
  });

  it('sends the mode of every item in conflict, the default one when none was chosen, and none for the others', () => {
    const items = [{ key: 'a', conflict: true }, { key: 'b', conflict: true }, { key: 'c', conflict: false }];
    expect(partialImportItemModes(items, { b: 'OVERWRITE' }, 'COPY')).toEqual([{ key: 'a', mode: 'COPY' }, { key: 'b', mode: 'OVERWRITE' }]);
  });

  it('takes the selected items in conflict, the ones a mode is chosen for', () => {
    const items = [{ key: 'a', conflict: true }, { key: 'b', conflict: false }, { key: 'c', conflict: true }];
    expect(partialImportConflictKeys(items, new Set(['a', 'b']))).toEqual(['a']);
    expect(partialImportConflictKeys(items, new Set(['a', 'b', 'c']))).toEqual(['a', 'c']);
  });

  it('gives the mode the items share, the default one for an item without one, and null when they differ', () => {
    expect(sharedPartialImportMode({}, ['a', 'b'], 'COPY')).toBe('COPY');
    expect(sharedPartialImportMode({ a: 'OVERWRITE', b: 'OVERWRITE' }, ['a', 'b'], 'COPY')).toBe('OVERWRITE');
    expect(sharedPartialImportMode({ a: 'OVERWRITE' }, ['a', 'b'], 'COPY')).toBeNull();
  });

  it('gives the same mode to the given items, the others keep theirs', () => {
    expect(withPartialImportModeForItems({ a: 'COPY', z: 'COPY' }, ['a', 'b'], 'OVERWRITE')).toEqual({ a: 'OVERWRITE', b: 'OVERWRITE', z: 'COPY' });
  });
});
