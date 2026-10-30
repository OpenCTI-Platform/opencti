import { afterEach, describe, expect, it, vi } from 'vitest';

// The HTTP options are read once, when the module is loaded:
// reload it with the given environment variables.
const loadHttpConfig = async (env: Record<string, string>) => {
  Object.entries(env).forEach(([key, value]) => vi.stubEnv(key, value));
  vi.resetModules();
  return import('../../../src/http/httpConfig');
};

describe('HTTP secure defaults', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('should keep the current defaults when disabled globally', async () => {
    const httpConfig = await loadHttpConfig({});

    expect(httpConfig.isHttpSecureByDefault()).toBe(false);
    expect(httpConfig.isUnsecureHttpResourceAllowed()).toBe(true);
    expect(httpConfig.getRateProtectionTimeWindowMs()).toBe(1000);
    expect(httpConfig.getRateProtectionMaxRequests()).toBe(10000);
    expect(httpConfig.getMaxPayloadBodySize()).toBe('50mb');
    expect(httpConfig.getHttpMaxRedirects()).toBe(21);
  });

  it('should apply the secure defaults when enabled globally', async () => {
    const httpConfig = await loadHttpConfig({ APP__HTTP__SECURE_BY_DEFAULT: 'true' });

    expect(httpConfig.isHttpSecureByDefault()).toBe(true);
    expect(httpConfig.isUnsecureHttpResourceAllowed()).toBe(false);
    expect(httpConfig.getRateProtectionTimeWindowMs()).toBe(60000);
    expect(httpConfig.getRateProtectionMaxRequests()).toBe(30000);
    expect(httpConfig.getMaxPayloadBodySize()).toBe('10mb');
    expect(httpConfig.getHttpMaxRedirects()).toBe(5);
  });

  it('should let the HTTP options override the global option', async () => {
    const httpConfig = await loadHttpConfig({
      APP__HTTP__SECURE_BY_DEFAULT: 'true',
      APP__ALLOW_UNSECURE_HTTP_RESOURCES: 'true',
      APP__RATE_PROTECTION__TIME_WINDOW: '1',
      APP__RATE_PROTECTION__MAX_REQUESTS: '10000',
      APP__MAX_PAYLOAD_BODY_SIZE: '50mb',
      APP__HTTP__MAX_REDIRECTS: '21',
    });

    expect(httpConfig.isUnsecureHttpResourceAllowed()).toBe(true);
    expect(httpConfig.getRateProtectionTimeWindowMs()).toBe(1000);
    expect(httpConfig.getRateProtectionMaxRequests()).toBe(10000);
    expect(httpConfig.getMaxPayloadBodySize()).toBe('50mb');
    expect(httpConfig.getHttpMaxRedirects()).toBe(21);
  });

  it('should let the HTTP options apply the secure values when disabled globally', async () => {
    const httpConfig = await loadHttpConfig({
      APP__ALLOW_UNSECURE_HTTP_RESOURCES: 'false',
      APP__HTTP__MAX_REDIRECTS: '0',
    });

    expect(httpConfig.isHttpSecureByDefault()).toBe(false);
    expect(httpConfig.isUnsecureHttpResourceAllowed()).toBe(false);
    expect(httpConfig.getHttpMaxRedirects()).toBe(0);
  });

  it('should fall back to the default number of redirects when the option is invalid', async () => {
    const httpConfig = await loadHttpConfig({ APP__HTTP__SECURE_BY_DEFAULT: 'true', APP__HTTP__MAX_REDIRECTS: 'many' });

    expect(httpConfig.getHttpMaxRedirects()).toBe(5);
  });
});
