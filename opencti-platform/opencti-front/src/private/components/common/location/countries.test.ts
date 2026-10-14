import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../relay/environment', () => ({ APP_BASE_PATH: '' }));

const collection = { type: 'FeatureCollection', features: [] };

const deferred = () => {
  let resolve: (value: Response) => void = () => {};
  let reject: (reason: unknown) => void = () => {};
  const promise = new Promise<Response>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
};

const okResponse = () => ({ ok: true, status: 200, json: async () => collection }) as unknown as Response;

const loader = () => import('./countries');

describe('countries loader', () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    vi.resetModules();
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it('should fetch again once the loaded boundaries are five minutes old', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-10-06T10:00:00Z'));
    fetchMock.mockResolvedValue(okResponse());
    const { loadCountries } = await loader();
    await loadCountries();
    vi.setSystemTime(new Date('2026-10-06T10:04:59Z'));
    await loadCountries();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    vi.setSystemTime(new Date('2026-10-06T10:05:00Z'));
    await loadCountries();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock).toHaveBeenLastCalledWith('/maps/countries.json', undefined);
  });

  it('should share one request between callers', async () => {
    fetchMock.mockResolvedValue(okResponse());
    const { loadCountries } = await loader();
    const [first, second] = await Promise.all([loadCountries(), loadCountries()]);
    expect(first).toBe(second);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith('/maps/countries.json', undefined);
  });

  it('should bypass the HTTP cache after an invalidation even when an older request completes later', async () => {
    const inFlight = deferred();
    fetchMock.mockReturnValueOnce(inFlight.promise).mockResolvedValue(okResponse());
    const { loadCountries, invalidateCountries } = await loader();
    const stale = loadCountries();
    invalidateCountries();
    inFlight.resolve(okResponse());
    await stale;
    await loadCountries();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock).toHaveBeenLastCalledWith('/maps/countries.json', { cache: 'reload' });
  });

  it('should forget a failed request so the next call retries', async () => {
    fetchMock.mockResolvedValueOnce({ ok: false, status: 503 } as Response).mockResolvedValue(okResponse());
    const { loadCountries } = await loader();
    await expect(loadCountries()).rejects.toThrow('Unable to load country boundaries (503)');
    await expect(loadCountries()).resolves.toEqual(collection);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('should keep the newer request when an older one fails after an invalidation', async () => {
    const inFlight = deferred();
    fetchMock.mockReturnValueOnce(inFlight.promise).mockResolvedValue(okResponse());
    const { loadCountries, invalidateCountries } = await loader();
    const stale = loadCountries();
    invalidateCountries();
    const fresh = loadCountries();
    inFlight.reject(new Error('network'));
    await expect(stale).rejects.toThrow('network');
    expect(loadCountries()).toBe(fresh);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('should still bypass the HTTP cache after a failed reload', async () => {
    fetchMock.mockResolvedValueOnce(okResponse())
      .mockRejectedValueOnce(new Error('network'))
      .mockResolvedValue(okResponse());
    const { loadCountries, invalidateCountries } = await loader();
    await loadCountries();
    invalidateCountries();
    await expect(loadCountries()).rejects.toThrow('network');
    await loadCountries();
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/maps/countries.json', { cache: 'reload' });
    expect(fetchMock).toHaveBeenNthCalledWith(3, '/maps/countries.json', { cache: 'reload' });
  });
});
