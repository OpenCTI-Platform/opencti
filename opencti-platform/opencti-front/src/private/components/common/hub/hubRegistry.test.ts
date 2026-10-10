import { describe, expect, it } from 'vitest';
import { sortedHubEntries } from './hubRegistry';

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
