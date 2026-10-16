import { beforeEach, describe, expect, it, vi } from 'vitest';

const fetchQueryMock = vi.hoisted(() => vi.fn());

vi.mock('../../../../relay/environment', () => ({ fetchQuery: fetchQueryMock }));

const loadFreshCountryNames = async () => (await import('./countryNames')).loadCountryNames;

describe('loadCountryNames', () => {
  beforeEach(() => {
    vi.resetModules();
    fetchQueryMock.mockReset();
  });

  it('maps every alias of a Country entity to its name', async () => {
    fetchQueryMock.mockReturnValue({
      toPromise: () => Promise.resolve({
        countries: { edges: [{ node: { name: 'French Republic', x_opencti_aliases: ['FRA', 'FR', null] } }] },
      }),
    });
    const names = await (await loadFreshCountryNames())();
    expect(names?.get('FRA')).toBe('French Republic');
    expect(names?.get('FR')).toBe('French Republic');
  });

  it('returns null when the countries cannot be read', async () => {
    fetchQueryMock.mockReturnValue({ toPromise: () => Promise.reject(new Error('You must be logged in to do this.')) });
    expect(await (await loadFreshCountryNames())()).toBeNull();
  });

  it('queries the countries only once', async () => {
    fetchQueryMock.mockReturnValue({ toPromise: () => Promise.resolve({ countries: { edges: [] } }) });
    const loadCountryNames = await loadFreshCountryNames();
    await loadCountryNames();
    await loadCountryNames();
    expect(fetchQueryMock).toHaveBeenCalledTimes(1);
  });
});
