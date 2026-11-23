import { describe, expect, it } from 'vitest';
import { allMenuEntries } from './menuEntries';
import { navSections } from './navSections';

const items = navSections.flatMap((section) => ('page' in section ? [section.page] : section.items));
const referenced = new Set(items.flatMap((item) => ('path' in item ? [item] : item.entries)));

// Sections reference entries by value, so a typo cannot hide a page: what is left to check is a page nobody references.
describe('navSections', () => {
  it('reaches every entry from the left bar, or declares where else it is reached from', () => {
    const unreachable = allMenuEntries
      .filter((entry) => !entry.standaloneParents && !referenced.has(entry))
      .map(({ path }) => path);
    expect(unreachable).toEqual([]);
  });
});
