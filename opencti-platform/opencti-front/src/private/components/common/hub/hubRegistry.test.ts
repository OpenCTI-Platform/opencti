import { describe, expect, it } from 'vitest';
import { isHubListed, sortedHubEntries } from './hubRegistry';

describe('sortedHubEntries', () => {
  it('orders the entries of the registry files by their position, whatever the file order', () => {
    const modules = {
      './areas/zeta.tsx': { order: 30, path: 'zeta' },
      './areas/alpha.tsx': { order: 20, path: 'alpha' },
      './areas/mu.tsx': { order: 10, path: 'mu' },
    };
    expect(sortedHubEntries(modules).map((entry) => entry.path)).toEqual(['mu', 'alpha', 'zeta']);
  });

  it('collects nothing from a registry without files', () => {
    expect(sortedHubEntries({})).toEqual([]);
  });
});

describe('isHubListed', () => {
  it('lists a hub with no registered entry, whose landing page says so', () => {
    expect(isHubListed([], [])).toBe(true);
  });

  it('lists a hub with an entry visible to the reader', () => {
    expect(isHubListed(['alpha', 'beta'], ['beta'])).toBe(true);
  });

  it('does not list a hub whose registered entries are all hidden from the reader', () => {
    expect(isHubListed(['alpha'], [])).toBe(false);
  });
});
