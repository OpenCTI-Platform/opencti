import { afterEach, describe, expect, it, vi } from 'vitest';

// Strong values for every checked setting, so each test only sets the default it checks.
const STRONG_CONFIGURATION = {
  APP__ADMIN__PASSWORD: 'a-strong-admin-password',
  APP__ADMIN__EXTERNALLY_MANAGED: 'false',
  APP__HEALTH_ACCESS_KEY: 'a-strong-health-key',
  RABBITMQ__USERNAME: 'opencti',
  RABBITMQ__PASSWORD: 'a-strong-rabbitmq-password',
  MINIO__ACCESS_KEY: 'opencti',
  MINIO__SECRET_KEY: 'a-strong-minio-secret',
  MINIO__USE_AWS_ROLE: 'false',
};

// The configuration is read once, when the modules are loaded:
// reload them with the given environment variables.
const loadModules = async (env: Record<string, string>) => {
  Object.entries({ ...STRONG_CONFIGURATION, ...env }).forEach(([key, value]) => vi.stubEnv(key, value));
  vi.resetModules();
  const credentials = await import('../../../src/config/default-credentials');
  const { logApp } = await import('../../../src/config/conf');
  const warn = vi.spyOn(logApp, 'warn').mockImplementation(() => {});
  return { ...credentials, warn };
};

describe('Default credentials', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it('should find no default credentials with strong values', async () => {
    const { findDefaultCredentials } = await loadModules({});

    expect(findDefaultCredentials()).toEqual([]);
  });

  it.each([
    ['app:admin:password', 'changeme', 'APP__ADMIN__PASSWORD'],
    ['app:health_access_key', 'changeme', 'APP__HEALTH_ACCESS_KEY'],
    ['rabbitmq:username', 'guest', 'RABBITMQ__USERNAME'],
    ['rabbitmq:username', 'changeme', 'RABBITMQ__USERNAME'],
    ['rabbitmq:password', 'guest', 'RABBITMQ__PASSWORD'],
    ['rabbitmq:password', 'changeme', 'RABBITMQ__PASSWORD'],
    ['minio:access_key', 'minioadmin', 'MINIO__ACCESS_KEY'],
    ['minio:access_key', 'ChangeMe', 'MINIO__ACCESS_KEY'],
    ['minio:secret_key', 'minioadmin', 'MINIO__SECRET_KEY'],
    ['minio:secret_key', 'ChangeMe', 'MINIO__SECRET_KEY'],
  ])('should find %s set to %s', async (setting, value, envKey) => {
    const { findDefaultCredentials } = await loadModules({ [envKey]: value });

    expect(findDefaultCredentials()).toEqual([setting]);
  });

  it.each(['changeme', 'ChangeMe', 'CHANGEME', 'cHaNgEmE', ' changeme '])('should ignore the case of %s', async (value) => {
    const { findDefaultCredentials } = await loadModules({ APP__ADMIN__PASSWORD: value, RABBITMQ__PASSWORD: value });

    expect(findDefaultCredentials()).toEqual(['app:admin:password', 'rabbitmq:password']);
  });

  it.each(['GUEST', 'Guest'])('should ignore the case of the RabbitMQ default %s', async (value) => {
    const { findDefaultCredentials } = await loadModules({ RABBITMQ__USERNAME: value, RABBITMQ__PASSWORD: value });

    expect(findDefaultCredentials()).toEqual(['rabbitmq:username', 'rabbitmq:password']);
  });

  it.each(['MinioAdmin', 'MINIOADMIN'])('should ignore the case of the MinIO default %s', async (value) => {
    const { findDefaultCredentials } = await loadModules({ MINIO__ACCESS_KEY: value, MINIO__SECRET_KEY: value });

    expect(findDefaultCredentials()).toEqual(['minio:access_key', 'minio:secret_key']);
  });

  it.each(['CHANGEME', 'cHaNgEmE', ' ChangeMe ', 'ChangeMe '])('should ignore the case of the health access key %s', async (value) => {
    const { findDefaultCredentials } = await loadModules({ APP__HEALTH_ACCESS_KEY: value });

    expect(findDefaultCredentials()).toEqual(['app:health_access_key']);
  });

  it.each([
    ['an empty value', ''],
    ['a number', '123'],
    ['a boolean', 'true'],
  ])('should ignore %s', async (_label, value) => {
    const { findDefaultCredentials } = await loadModules({ APP__ADMIN__PASSWORD: value, RABBITMQ__PASSWORD: value, MINIO__SECRET_KEY: value });

    expect(findDefaultCredentials()).toEqual([]);
  });

  it('should skip the admin password of an externally managed admin, which is locked', async () => {
    const { findDefaultCredentials } = await loadModules({ APP__ADMIN__EXTERNALLY_MANAGED: 'true', APP__ADMIN__PASSWORD: 'changeme' });

    expect(findDefaultCredentials()).toEqual([]);
  });

  it('should only check the known defaults of each setting', async () => {
    const { findDefaultCredentials } = await loadModules({ APP__ADMIN__PASSWORD: 'guest', RABBITMQ__PASSWORD: 'minioadmin' });

    expect(findDefaultCredentials()).toEqual([]);
  });

  it('should accept the exact ChangeMe health access key, which keeps /health disabled', async () => {
    const { findDefaultCredentials } = await loadModules({ APP__HEALTH_ACCESS_KEY: 'ChangeMe' });

    expect(findDefaultCredentials()).toEqual([]);
  });

  it('should skip the MinIO keys with an AWS role', async () => {
    const { findDefaultCredentials } = await loadModules({ MINIO__USE_AWS_ROLE: 'true', MINIO__ACCESS_KEY: 'ChangeMe', MINIO__SECRET_KEY: 'ChangeMe' });

    expect(findDefaultCredentials()).toEqual([]);
  });

  it.each([
    ['both keys', 'MINIO__CREDENTIALS_PROVIDER__CYBERARK__FIELD_TARGETS', '["accessKeyId","secretAccessKey"]', []],
    ['both keys, from the generic option', 'MINIO__CREDENTIALS_PROVIDER__FIELD_TARGETS', '["accessKeyId","secretAccessKey"]', []],
    ['the secret key only', 'MINIO__CREDENTIALS_PROVIDER__CYBERARK__FIELD_TARGETS', '["secretAccessKey"]', ['minio:access_key']],
    ['the access key only', 'MINIO__CREDENTIALS_PROVIDER__CYBERARK__FIELD_TARGETS', '["accessKeyId"]', ['minio:secret_key']],
  ])('should skip the MinIO keys a remote credentials provider replaces: %s', async (_label, targetsKey, targets, expected) => {
    const { findDefaultCredentials } = await loadModules({
      MINIO__CREDENTIALS_PROVIDER__SELECTOR: 'cyberark',
      [targetsKey]: targets,
      MINIO__ACCESS_KEY: 'ChangeMe',
      MINIO__SECRET_KEY: 'ChangeMe',
    });

    expect(findDefaultCredentials()).toEqual(expected);
  });

  it('should check the MinIO keys with an unsupported remote credentials provider, which falls back to them', async () => {
    const { findDefaultCredentials } = await loadModules({
      MINIO__CREDENTIALS_PROVIDER__SELECTOR: 'unknown',
      MINIO__CREDENTIALS_PROVIDER__FIELD_TARGETS: '["accessKeyId","secretAccessKey"]',
      MINIO__ACCESS_KEY: 'ChangeMe',
      MINIO__SECRET_KEY: 'ChangeMe',
    });

    expect(findDefaultCredentials()).toEqual(['minio:access_key', 'minio:secret_key']);
  });

  describe('MinIO keys resolved by a remote credentials provider', () => {
    const PROVIDER = {
      MINIO__CREDENTIALS_PROVIDER__SELECTOR: 'cyberark',
      MINIO__CREDENTIALS_PROVIDER__CYBERARK__FIELD_TARGETS: '["accessKeyId","secretAccessKey"]',
      MINIO__ACCESS_KEY: 'ChangeMe',
      MINIO__SECRET_KEY: 'ChangeMe',
    };

    it('should find the configured defaults the provider fell back to after a failure', async () => {
      const { findResolvedMinioDefaultCredentials } = await loadModules(PROVIDER);

      // enrichWithRemoteCredentials returns the configured keys when the fetch fails
      expect(findResolvedMinioDefaultCredentials({ accessKeyId: 'ChangeMe', secretAccessKey: 'ChangeMe' })).toEqual(['minio:access_key', 'minio:secret_key']);
    });

    it('should find a default returned by the provider itself', async () => {
      const { findResolvedMinioDefaultCredentials } = await loadModules(PROVIDER);

      expect(findResolvedMinioDefaultCredentials({ accessKeyId: 'opencti', secretAccessKey: 'MinioAdmin' })).toEqual(['minio:secret_key']);
    });

    it('should find nothing once the provider replaced the keys', async () => {
      const { findResolvedMinioDefaultCredentials } = await loadModules(PROVIDER);

      expect(findResolvedMinioDefaultCredentials({ accessKeyId: 'opencti', secretAccessKey: 'a-strong-remote-secret' })).toEqual([]);
    });

    it('should not report again a key the provider does not target, already checked at startup', async () => {
      const { findResolvedMinioDefaultCredentials } = await loadModules({ ...PROVIDER, MINIO__CREDENTIALS_PROVIDER__CYBERARK__FIELD_TARGETS: '["secretAccessKey"]' });

      expect(findResolvedMinioDefaultCredentials({ accessKeyId: 'ChangeMe', secretAccessKey: 'ChangeMe' })).toEqual(['minio:secret_key']);
    });

    it('should find nothing without a supported remote credentials provider', async () => {
      const { findResolvedMinioDefaultCredentials } = await loadModules({ ...PROVIDER, MINIO__CREDENTIALS_PROVIDER__SELECTOR: 'unknown' });

      expect(findResolvedMinioDefaultCredentials({ accessKeyId: 'ChangeMe', secretAccessKey: 'ChangeMe' })).toEqual([]);
    });

    it('should warn after a provider failure when the switch is disabled', async () => {
      const { checkResolvedMinioCredentials, warn } = await loadModules(PROVIDER);

      expect(() => checkResolvedMinioCredentials({ accessKeyId: 'ChangeMe', secretAccessKey: 'ChangeMe' })).not.toThrow();
      expect(warn).toHaveBeenCalledWith(expect.any(String), { settings: ['minio:access_key', 'minio:secret_key'] });
    });

    it('should refuse to start after a provider failure when the switch is enabled', async () => {
      const { checkResolvedMinioCredentials } = await loadModules({ ...PROVIDER, APP__CREDENTIALS__SECURE_BY_DEFAULT: 'true' });

      expect(() => checkResolvedMinioCredentials({ accessKeyId: 'ChangeMe', secretAccessKey: 'ChangeMe' })).toThrow(/Default credentials are configured/);
    });
  });

  describe('switch app:credentials:secure_by_default', () => {
    it('should be disabled by default', async () => {
      const { CREDENTIALS_SECURE_BY_DEFAULT } = await loadModules({});

      expect(CREDENTIALS_SECURE_BY_DEFAULT).toBe(false);
    });

    it('should be disabled when set to false', async () => {
      const { CREDENTIALS_SECURE_BY_DEFAULT, checkDefaultCredentials, warn } = await loadModules({
        APP__CREDENTIALS__SECURE_BY_DEFAULT: 'false',
        APP__ADMIN__PASSWORD: 'ChangeMe',
      });

      expect(CREDENTIALS_SECURE_BY_DEFAULT).toBe(false);
      expect(() => checkDefaultCredentials()).not.toThrow();
      expect(warn).toHaveBeenCalledWith(expect.any(String), { settings: ['app:admin:password'] });
    });

    it('should do nothing without default credentials', async () => {
      const { checkDefaultCredentials, warn } = await loadModules({ APP__CREDENTIALS__SECURE_BY_DEFAULT: 'true' });

      expect(() => checkDefaultCredentials()).not.toThrow();
      expect(warn).not.toHaveBeenCalled();
    });

    it('should warn with the setting names, never the values, when disabled', async () => {
      const { checkDefaultCredentials, warn } = await loadModules({ RABBITMQ__PASSWORD: 'Guest', MINIO__SECRET_KEY: 'minioadmin' });

      expect(() => checkDefaultCredentials()).not.toThrow();
      expect(warn).toHaveBeenCalledTimes(1);
      const [message, meta] = warn.mock.calls[0];
      expect(meta).toEqual({ settings: ['rabbitmq:password', 'minio:secret_key'] });
      expect(JSON.stringify([message, meta])).not.toMatch(/guest|minioadmin/i);
    });

    it('should refuse to start when enabled', async () => {
      const { checkDefaultCredentials, warn } = await loadModules({ APP__CREDENTIALS__SECURE_BY_DEFAULT: 'true', APP__ADMIN__PASSWORD: 'changeme' });

      expect(() => checkDefaultCredentials()).toThrow(/Default credentials are configured/);
      expect(warn).not.toHaveBeenCalled();
    });

    it('should name the settings, never the values, in the error', async () => {
      const { checkDefaultCredentials } = await loadModules({ APP__CREDENTIALS__SECURE_BY_DEFAULT: 'true', RABBITMQ__USERNAME: 'guest' });

      let thrown: unknown;
      try {
        checkDefaultCredentials();
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toMatchObject({ extensions: { data: { settings: ['rabbitmq:username'] } } });
      expect(JSON.stringify(thrown)).not.toMatch(/guest/i);
    });
  });
});
