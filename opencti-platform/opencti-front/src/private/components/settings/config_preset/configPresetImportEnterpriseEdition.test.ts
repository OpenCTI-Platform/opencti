import { describe, expect, it } from 'vitest';
import {
  addEnterpriseEditionExclusions,
  dropEnterpriseEditionItems,
  excludeEnterpriseEditionItems,
  getEnterpriseEditionKeys,
  withoutEnterpriseEditionItems,
} from './configPresetImportEnterpriseEdition';

const types = [
  { key: 'branding', items: [{ key: 'whitemark', requiresEnterpriseEdition: true }, { key: 'theme', requiresEnterpriseEdition: false }] },
  { key: 'messages', items: [{ key: 'banner', requiresEnterpriseEdition: false }] },
];
const eeKeys = getEnterpriseEditionKeys(types);

describe('Enterprise Edition items of an import', () => {
  it('lists the keys of the items that need it, by type', () => {
    expect(eeKeys).toEqual({ branding: ['whitemark'], messages: [] });
  });

  it('leaves them out of the types the selection helpers see on a Community platform only', () => {
    expect(withoutEnterpriseEditionItems(types, false)[0].items.map(({ key }) => key)).toEqual(['theme']);
    expect(withoutEnterpriseEditionItems(types, true)[0].items.map(({ key }) => key)).toEqual(['whitemark', 'theme']);
  });

  it('drops them from the types in "some" mode of a restored selection', () => {
    expect(dropEnterpriseEditionItems({ branding: { mode: 'some', ids: ['whitemark', 'theme'] }, messages: { mode: 'all', ids: [] } }, eeKeys)).toEqual({
      branding: { mode: 'some', ids: ['theme'] },
      messages: { mode: 'all', ids: [] },
    });
  });

  it('excludes them from the types in "all" mode once a license unlocks them, and touches nothing else', () => {
    expect(excludeEnterpriseEditionItems({ branding: { mode: 'all', ids: ['theme'] }, messages: { mode: 'some', ids: ['banner'] } }, eeKeys)).toEqual({
      branding: { mode: 'all', ids: ['theme', 'whitemark'] },
      messages: { mode: 'some', ids: ['banner'] },
    });
  });

  it('adds their keys to the excluded items of the types sent in "all" mode', () => {
    expect(addEnterpriseEditionExclusions([
      { type: 'branding', items: null },
      { type: 'messages', items: null },
      { type: 'branding', items: ['theme'] },
    ], eeKeys)).toEqual([
      { type: 'branding', items: null, excluded_items: ['whitemark'] },
      { type: 'messages', items: null },
      { type: 'branding', items: ['theme'] },
    ]);
    expect(addEnterpriseEditionExclusions([{ type: 'branding', items: null, excluded_items: ['whitemark', 'x'] }], eeKeys)).toEqual([
      { type: 'branding', items: null, excluded_items: ['whitemark', 'x'] },
    ]);
  });
});
