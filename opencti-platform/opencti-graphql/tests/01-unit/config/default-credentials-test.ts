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
  ELASTICSEARCH__USERNAME: 'opencti',
  ELASTICSEARCH__PASSWORD: 'a-strong-elasticsearch-password',
  REDIS__USERNAME: 'opencti',
  REDIS__PASSWORD: 'a-strong-redis-password',
  // The Sentinel credentials are only used, and checked, in Sentinel mode
  REDIS__MODE: 'sentinel',
  REDIS__SENTINEL_USERNAME: 'opencti',
  REDIS__SENTINEL_PASSWORD: 'a-strong-sentinel-password',
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
    ['rabbitmq:password', 'guest', 'RABBITMQ__PASSWORD'],
    ['rabbitmq:password', 'changeme', 'RABBITMQ__PASSWORD'],
    ['minio:secret_key', 'minioadmin', 'MINIO__SECRET_KEY'],
    ['minio:secret_key', 'ChangeMe', 'MINIO__SECRET_KEY'],
    ['elasticsearch:password', 'changeme', 'ELASTICSEARCH__PASSWORD'],
    ['elasticsearch:password', 'admin', 'ELASTICSEARCH__PASSWORD'],
    ['redis:password', 'ChangeMe', 'REDIS__PASSWORD'],
    ['redis:sentinel_password', 'changeme', 'REDIS__SENTINEL_PASSWORD'],
  ])('should find %s set to %s', async (setting, value, envKey) => {
    const { findDefaultCredentials } = await loadModules({ [envKey]: value });

    expect(findDefaultCredentials()).toEqual([setting]);
  });

  it.each([
    ['rabbitmq:username', 'rabbitmq:password', 'guest', 'RABBITMQ__USERNAME', 'RABBITMQ__PASSWORD'],
    ['rabbitmq:username', 'rabbitmq:password', 'changeme', 'RABBITMQ__USERNAME', 'RABBITMQ__PASSWORD'],
    ['minio:access_key', 'minio:secret_key', 'minioadmin', 'MINIO__ACCESS_KEY', 'MINIO__SECRET_KEY'],
    ['minio:access_key', 'minio:secret_key', 'ChangeMe', 'MINIO__ACCESS_KEY', 'MINIO__SECRET_KEY'],
    ['elasticsearch:username', 'elasticsearch:password', 'changeme', 'ELASTICSEARCH__USERNAME', 'ELASTICSEARCH__PASSWORD'],
    ['elasticsearch:username', 'elasticsearch:password', 'admin', 'ELASTICSEARCH__USERNAME', 'ELASTICSEARCH__PASSWORD'],
    ['redis:username', 'redis:password', 'changeme', 'REDIS__USERNAME', 'REDIS__PASSWORD'],
    ['redis:sentinel_username', 'redis:sentinel_password', 'changeme', 'REDIS__SENTINEL_USERNAME', 'REDIS__SENTINEL_PASSWORD'],
  ])('should find %s with %s both set to %s', async (userSetting, passwordSetting, value, userEnvKey, passwordEnvKey) => {
    const { findDefaultCredentials } = await loadModules({ [userEnvKey]: value, [passwordEnvKey]: value });

    expect(findDefaultCredentials()).toEqual([userSetting, passwordSetting]);
  });

  it.each([
    ['elasticsearch:username', 'elastic', 'elasticsearch:password', 'changeme', 'ELASTICSEARCH__USERNAME', 'ELASTICSEARCH__PASSWORD'],
    ['elasticsearch:username', 'Elastic', 'elasticsearch:password', 'ChangeMe', 'ELASTICSEARCH__USERNAME', 'ELASTICSEARCH__PASSWORD'],
    ['redis:username', 'default', 'redis:password', 'changeme', 'REDIS__USERNAME', 'REDIS__PASSWORD'],
    ['redis:sentinel_username', 'default', 'redis:sentinel_password', 'changeme', 'REDIS__SENTINEL_USERNAME', 'REDIS__SENTINEL_PASSWORD'],
  ])('should find %s set to %s with %s set to %s', async (userSetting, user, passwordSetting, password, userEnvKey, passwordEnvKey) => {
    const { findDefaultCredentials } = await loadModules({ [userEnvKey]: user, [passwordEnvKey]: password });

    expect(findDefaultCredentials()).toEqual([userSetting, passwordSetting]);
  });

  it.each([
    ['rabbitmq:username', 'guest', 'RABBITMQ__USERNAME'],
    ['rabbitmq:username', 'changeme', 'RABBITMQ__USERNAME'],
    ['minio:access_key', 'minioadmin', 'MINIO__ACCESS_KEY'],
    ['minio:access_key', 'ChangeMe', 'MINIO__ACCESS_KEY'],
    ['elasticsearch:username', 'elastic', 'ELASTICSEARCH__USERNAME'],
    ['elasticsearch:username', 'admin', 'ELASTICSEARCH__USERNAME'],
    ['redis:username', 'default', 'REDIS__USERNAME'],
    ['redis:sentinel_username', 'default', 'REDIS__SENTINEL_USERNAME'],
  ])('should accept %s set to %s with a strong password, as the pair is not a default', async (_setting, value, envKey) => {
    const { findDefaultCredentials } = await loadModules({ [envKey]: value });

    expect(findDefaultCredentials()).toEqual([]);
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

  it('should check the admin password when externally_managed is the string "true", which initAdmin does not lock', async () => {
    const { findDefaultCredentials } = await loadModules({ APP__ADMIN__PASSWORD: 'changeme' });
    // A JSON configuration file can hold the string "true" (the environment is parsed into a boolean): initAdmin compares the flag to the true boolean.
    const { default: conf } = await import('../../../src/config/conf');
    const get = conf.get.bind(conf);
    vi.spyOn(conf, 'get').mockImplementation((key?: string) => (key === 'app:admin:externally_managed' ? 'true' : get(key)));

    expect(findDefaultCredentials()).toEqual(['app:admin:password']);
  });

  it('should only check the known defaults of each setting', async () => {
    const { findDefaultCredentials } = await loadModules({
      APP__ADMIN__PASSWORD: 'guest',
      RABBITMQ__PASSWORD: 'minioadmin',
      ELASTICSEARCH__PASSWORD: 'guest',
      REDIS__PASSWORD: 'admin',
      REDIS__SENTINEL_PASSWORD: 'elastic',
    });

    expect(findDefaultCredentials()).toEqual([]);
  });

  it('should only count the user names as defaults of the user name settings', async () => {
    const { findDefaultCredentials } = await loadModules({ ELASTICSEARCH__PASSWORD: 'elastic', REDIS__PASSWORD: 'default' });

    expect(findDefaultCredentials()).toEqual([]);
  });

  it('should skip the Elasticsearch user and password with an API key, which the client uses instead', async () => {
    const { findDefaultCredentials } = await loadModules({
      ELASTICSEARCH__API_KEY: 'an-elasticsearch-api-key',
      ELASTICSEARCH__USERNAME: 'elastic',
      ELASTICSEARCH__PASSWORD: 'changeme',
    });

    expect(findDefaultCredentials()).toEqual([]);
  });

  it.each(['single', 'cluster'])('should skip the Sentinel credentials in %s mode, which does not use them', async (mode) => {
    const { findDefaultCredentials } = await loadModules({
      REDIS__MODE: mode,
      REDIS__SENTINEL_USERNAME: 'default',
      REDIS__SENTINEL_PASSWORD: 'changeme',
    });

    expect(findDefaultCredentials()).toEqual([]);
  });

  it('should check the Redis credentials in cluster mode', async () => {
    const { findDefaultCredentials } = await loadModules({ REDIS__MODE: 'cluster', REDIS__USERNAME: 'default', REDIS__PASSWORD: 'changeme' });

    expect(findDefaultCredentials()).toEqual(['redis:username', 'redis:password']);
  });

  it('should skip the Elasticsearch credentials with AWS SigV4, which signs the requests instead', async () => {
    const { findDefaultCredentials } = await loadModules({
      OPENSEARCH__REGION: 'eu-west-1',
      ELASTICSEARCH__URL: 'http://admin:admin@localhost:9200',
      ELASTICSEARCH__USERNAME: 'admin',
      ELASTICSEARCH__PASSWORD: 'admin',
    });

    expect(findDefaultCredentials()).toEqual([]);
  });

  describe('Elasticsearch credentials in elasticsearch:url', () => {
    it.each([
      ['a default pair', 'http://elastic:changeme@localhost:9200'],
      ['the OpenSearch default pair', 'https://admin:admin@localhost:9200'],
      ['a default password with any user', 'http://opencti:ChangeMe@localhost:9200'],
      ['an encoded default password', 'http://opencti:%43hange%4De@localhost:9200'],
      ['a default pair in one of the URLs', '["http://localhost:9200","http://elastic:changeme@localhost:9201"]'],
    ])('should find %s, naming the setting only', async (_label, url) => {
      const { findDefaultCredentials } = await loadModules({ ELASTICSEARCH__URL: url });

      expect(findDefaultCredentials()).toEqual(['elasticsearch:url']);
    });

    it('should use the URL credentials over the configured ones, as the clients do', async () => {
      const { findDefaultCredentials } = await loadModules({
        ELASTICSEARCH__URL: 'http://opencti:a-strong-url-password@localhost:9200',
        ELASTICSEARCH__USERNAME: 'elastic',
        ELASTICSEARCH__PASSWORD: 'changeme',
      });

      expect(findDefaultCredentials()).toEqual([]);
    });

    it('should use the first URL holding a user and a password, as the clients do', async () => {
      const { findDefaultCredentials } = await loadModules({
        ELASTICSEARCH__URL: '["http://opencti:a-strong-url-password@localhost:9200","http://elastic:changeme@localhost:9201"]',
      });

      expect(findDefaultCredentials()).toEqual([]);
    });

    it.each([
      ['a user only', 'http://elastic@localhost:9200'],
      ['no credentials', 'http://localhost:9200'],
      ['an invalid URL', 'not a url'],
    ])('should check the configured credentials with %s in the URL', async (_label, url) => {
      const { findDefaultCredentials } = await loadModules({ ELASTICSEARCH__URL: url, ELASTICSEARCH__PASSWORD: 'changeme' });

      expect(findDefaultCredentials()).toEqual(['elasticsearch:password']);
    });

    it('should check the URL credentials with a remote credentials provider, as the clients use them over the resolved ones', async () => {
      const { findDefaultCredentials } = await loadModules({
        ELASTICSEARCH__CREDENTIALS_PROVIDER__SELECTOR: 'cyberark',
        ELASTICSEARCH__CREDENTIALS_PROVIDER__CYBERARK__FIELD_TARGETS: '["username","password"]',
        ELASTICSEARCH__URL: 'http://elastic:changeme@localhost:9200',
      });

      expect(findDefaultCredentials()).toEqual(['elasticsearch:url']);
    });

    it('should skip the URL credentials with an API key', async () => {
      const { findDefaultCredentials } = await loadModules({
        ELASTICSEARCH__API_KEY: 'an-elasticsearch-api-key',
        ELASTICSEARCH__URL: 'http://elastic:changeme@localhost:9200',
      });

      expect(findDefaultCredentials()).toEqual([]);
    });
  });

  it.each([
    ['opensearch', 'the forced OpenSearch client, which has no API key support', 'an-elasticsearch-api-key'],
    ['auto', 'an empty API key', ''],
  ])('should check the Elasticsearch credentials with engine_client %s and %s', async (engineClient, _label, apiKey) => {
    const { findDefaultCredentials } = await loadModules({
      ELASTICSEARCH__ENGINE_CLIENT: engineClient,
      ELASTICSEARCH__API_KEY: apiKey,
      ELASTICSEARCH__USERNAME: 'elastic',
      ELASTICSEARCH__PASSWORD: 'changeme',
    });

    expect(findDefaultCredentials()).toEqual(['elasticsearch:username', 'elasticsearch:password']);
  });

  it.each([
    ['Elasticsearch', 'ELASTICSEARCH', '["username","password"]', { ELASTICSEARCH__USERNAME: 'elastic', ELASTICSEARCH__PASSWORD: 'changeme' }],
    ['Redis', 'REDIS', '["username","password","sentinelUsername","sentinelPassword"]', {
      REDIS__USERNAME: 'changeme',
      REDIS__PASSWORD: 'changeme',
      REDIS__SENTINEL_USERNAME: 'changeme',
      REDIS__SENTINEL_PASSWORD: 'changeme',
    }],
  ])('should leave the %s credentials targeted by a remote credentials provider, and check the others', async (_label, prefix, targets, defaults) => {
    const { findDefaultCredentials } = await loadModules({
      [`${prefix}__CREDENTIALS_PROVIDER__SELECTOR`]: 'cyberark',
      [`${prefix}__CREDENTIALS_PROVIDER__CYBERARK__FIELD_TARGETS`]: targets,
      ...defaults,
      RABBITMQ__PASSWORD: 'guest',
    });

    expect(findDefaultCredentials()).toEqual(['rabbitmq:password']);
  });

  it('should check the configured password when a remote credentials provider only targets the user', async () => {
    const { findDefaultCredentials } = await loadModules({
      ELASTICSEARCH__CREDENTIALS_PROVIDER__SELECTOR: 'cyberark',
      ELASTICSEARCH__CREDENTIALS_PROVIDER__CYBERARK__FIELD_TARGETS: '["username"]',
      ELASTICSEARCH__USERNAME: 'elastic',
      ELASTICSEARCH__PASSWORD: 'changeme',
    });

    // The configured user name is replaced, so only the password is reported
    expect(findDefaultCredentials()).toEqual(['elasticsearch:password']);
  });

  it('should check the Sentinel credentials when a remote credentials provider only targets the Redis ones', async () => {
    const { findDefaultCredentials } = await loadModules({
      REDIS__CREDENTIALS_PROVIDER__SELECTOR: 'cyberark',
      REDIS__CREDENTIALS_PROVIDER__CYBERARK__FIELD_TARGETS: '["username","password"]',
      REDIS__PASSWORD: 'changeme',
      REDIS__SENTINEL_USERNAME: 'default',
      REDIS__SENTINEL_PASSWORD: 'changeme',
    });

    expect(findDefaultCredentials()).toEqual(['redis:sentinel_username', 'redis:sentinel_password']);
  });

  it('should check the Elasticsearch and Redis credentials with an unsupported remote credentials provider, which falls back to them', async () => {
    const { findDefaultCredentials } = await loadModules({
      ELASTICSEARCH__CREDENTIALS_PROVIDER__SELECTOR: 'unknown',
      ELASTICSEARCH__CREDENTIALS_PROVIDER__FIELD_TARGETS: '["username","password"]',
      ELASTICSEARCH__PASSWORD: 'changeme',
      REDIS__CREDENTIALS_PROVIDER__SELECTOR: 'unknown',
      REDIS__CREDENTIALS_PROVIDER__FIELD_TARGETS: '["password"]',
      REDIS__PASSWORD: 'changeme',
    });

    expect(findDefaultCredentials()).toEqual(['elasticsearch:password', 'redis:password']);
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
    ['both keys', 'MINIO__CREDENTIALS_PROVIDER__CYBERARK__FIELD_TARGETS', '["accessKeyId","secretAccessKey"]'],
    ['both keys, from the generic option', 'MINIO__CREDENTIALS_PROVIDER__FIELD_TARGETS', '["accessKeyId","secretAccessKey"]'],
    ['the secret key only', 'MINIO__CREDENTIALS_PROVIDER__CYBERARK__FIELD_TARGETS', '["secretAccessKey"]'],
    ['the access key only', 'MINIO__CREDENTIALS_PROVIDER__CYBERARK__FIELD_TARGETS', '["accessKeyId"]'],
  ])('should leave the MinIO keys to their resolution with a remote credentials provider targeting %s', async (_label, targetsKey, targets) => {
    const { findDefaultCredentials } = await loadModules({
      MINIO__CREDENTIALS_PROVIDER__SELECTOR: 'cyberark',
      [targetsKey]: targets,
      MINIO__ACCESS_KEY: 'ChangeMe',
      MINIO__SECRET_KEY: 'ChangeMe',
    });

    expect(findDefaultCredentials()).toEqual([]);
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

    it('should accept a default access key with a strong resolved secret key, as the pair is not a default', async () => {
      const { findResolvedMinioDefaultCredentials } = await loadModules(PROVIDER);

      expect(findResolvedMinioDefaultCredentials({ accessKeyId: 'minioadmin', secretAccessKey: 'a-strong-remote-secret' })).toEqual([]);
    });

    it('should also check the key the provider does not target, left to this check at startup', async () => {
      const { findResolvedMinioDefaultCredentials } = await loadModules({ ...PROVIDER, MINIO__CREDENTIALS_PROVIDER__CYBERARK__FIELD_TARGETS: '["secretAccessKey"]' });

      expect(findResolvedMinioDefaultCredentials({ accessKeyId: 'ChangeMe', secretAccessKey: 'ChangeMe' })).toEqual(['minio:access_key', 'minio:secret_key']);
    });

    it('should find nothing without a supported remote credentials provider', async () => {
      const { findResolvedMinioDefaultCredentials } = await loadModules({ ...PROVIDER, MINIO__CREDENTIALS_PROVIDER__SELECTOR: 'unknown' });

      expect(findResolvedMinioDefaultCredentials({ accessKeyId: 'ChangeMe', secretAccessKey: 'ChangeMe' })).toEqual([]);
    });

    it('should warn after a provider failure when the switch is disabled', async () => {
      const { checkResolvedMinioCredentials, warn } = await loadModules(PROVIDER);

      expect(() => checkResolvedMinioCredentials({ accessKeyId: 'ChangeMe', secretAccessKey: 'ChangeMe' })).not.toThrow();
      expect(warn).toHaveBeenCalledWith(expect.stringMatching(/remote credentials provider/), { settings: ['minio:access_key', 'minio:secret_key'] });
    });

    it('should refuse to start after a provider failure when the switch is enabled', async () => {
      const { checkResolvedMinioCredentials } = await loadModules({ ...PROVIDER, APP__CREDENTIALS__SECURE_BY_DEFAULT: 'true' });

      expect(() => checkResolvedMinioCredentials({ accessKeyId: 'ChangeMe', secretAccessKey: 'ChangeMe' })).toThrow(/Default MinIO keys are in use with the remote credentials provider/);
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
      const { checkDefaultCredentials } = await loadModules({ APP__CREDENTIALS__SECURE_BY_DEFAULT: 'true', RABBITMQ__USERNAME: 'guest', RABBITMQ__PASSWORD: 'guest' });

      let thrown: unknown;
      try {
        checkDefaultCredentials();
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toMatchObject({ extensions: { data: { settings: ['rabbitmq:username', 'rabbitmq:password'] } } });
      expect(JSON.stringify(thrown)).not.toMatch(/guest/i);
    });
  });
});
