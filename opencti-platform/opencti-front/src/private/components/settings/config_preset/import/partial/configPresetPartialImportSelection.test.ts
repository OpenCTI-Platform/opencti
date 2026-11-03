import { describe, expect, it } from 'vitest';
import { partialImportItemModes, partialImportSelectedKeys, toggleSelectedKey } from './configPresetPartialImportSelection';

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
});
