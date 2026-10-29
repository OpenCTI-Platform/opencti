import { afterEach, describe, expect, it, vi } from 'vitest';

// Loads the real storage module with a given environment. config/test.json sets s3 endpoint, port and bucket name.
// The warn spy is set before the storage module loads, to see a warning logged at load time.
const loadStorage = async (env: Record<string, string>) => {
  Object.keys(process.env).filter((name) => /^(s3|minio)__/i.test(name)).forEach((name) => vi.stubEnv(name, undefined));
  Object.entries(env).forEach(([name, value]) => vi.stubEnv(name, value));
  vi.resetModules();
  const { logApp } = await import('../../../src/config/conf');
  const warn = vi.spyOn(logApp, 'warn');
  const storage = await import('../../../src/database/raw-file-storage');
  return { storage, warn };
};

describe('Object storage configuration', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
  });

  it('should read the former minio names and report them', async () => {
    const { storage, warn } = await loadStorage({ MINIO__ENDPOINT: 'legacy-host', MINIO__ACCESS_KEY: 'legacy-access', MINIO__SECRET_KEY: 'legacy-secret' });
    expect(storage.s3ConnectionConfig()).toMatchObject({ endpoint: 'legacy-host', access_key: 'legacy-access', secret_key: 'legacy-secret', bucket_name: 'test' });
    const { used, ignored, shadowed } = storage.storageConfDeprecations();
    expect(used).toEqual(['minio:endpoint', 'minio:access_key', 'minio:secret_key']);
    expect(ignored).toEqual([]);
    expect(shadowed).toEqual(['s3:endpoint']);
    storage.logStorageConfDeprecations();
    expect(warn).toHaveBeenCalledWith('[FILE STORAGE] s3 configuration ignored, a minio name of higher priority is set', { keys: ['s3:endpoint (S3__ENDPOINT)'] });
  });
  it('should prefer the s3 names and report the ignored minio names', async () => {
    const { storage } = await loadStorage({ S3__ENDPOINT: 'new-host', MINIO__ENDPOINT: 'old-host', S3__PORT: '19000' });
    expect(storage.s3ConnectionConfig()).toMatchObject({ endpoint: 'new-host', port: 19000 });
    const { used, ignored, shadowed } = storage.storageConfDeprecations();
    expect(used).toEqual([]);
    expect(ignored).toEqual(['minio:endpoint']);
    expect(shadowed).toEqual([]);
  });
  it('should report nothing without minio names', async () => {
    const { storage, warn } = await loadStorage({ S3__ENDPOINT: 'new-host' });
    storage.logStorageConfDeprecations();
    expect(warn).not.toHaveBeenCalled();
  });
  it('should log key and variable names, never values', async () => {
    const { storage, warn } = await loadStorage({ MINIO__SECRET_KEY: 'super-secret-value', S3__ENDPOINT: 'new-host', MINIO__ENDPOINT: 'old-host' });
    storage.logStorageConfDeprecations();
    expect(warn).toHaveBeenCalledTimes(2);
    const logged = JSON.stringify(warn.mock.calls);
    expect(logged).toContain('minio:secret_key (MINIO__SECRET_KEY)');
    expect(logged).toContain('minio:endpoint (MINIO__ENDPOINT)');
    expect(logged).not.toContain('super-secret-value');
    expect(logged).not.toContain('old-host');
  });
  it('should report the former names at storage init, not at module load', async () => {
    const { storage, warn } = await loadStorage({ MINIO__ENDPOINT: 'legacy-host' });
    expect(warn).not.toHaveBeenCalled();
    // Stops storageInit at the first warning, before any connection
    warn.mockImplementation(() => {
      throw new Error('warned');
    });
    await expect(storage.storageInit()).rejects.toThrow('warned');
  });
  it('should take the remote credentials provider from the minio section when only it is set', async () => {
    const { storage } = await loadStorage({ MINIO__CREDENTIALS_PROVIDER__SELECTOR: 'cyberark' });
    expect(storage.storageConfKey('credentials_provider')).toBe('minio:credentials_provider');
  });
});
