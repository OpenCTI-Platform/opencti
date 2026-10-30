import { afterEach, describe, expect, it, vi } from 'vitest';

// The GraphQL options are read once, when the module is loaded:
// reload it with the given environment variables.
const loadConf = async (env: Record<string, string>) => {
  Object.entries(env).forEach(([key, value]) => vi.stubEnv(key, value));
  vi.resetModules();
  return import('../../../src/config/conf');
};

describe('GraphQL secure defaults', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('should keep armor disabled and the playground enabled when disabled globally', async () => {
    const conf = await loadConf({});

    expect(conf.GRAPHQL_SECURE_BY_DEFAULT).toBe(false);
    expect(conf.GRAPHQL_ARMOR_DISABLED).toBe(true);
    expect(conf.PLAYGROUND_ENABLED).toBe(true);
  });

  it('should enable armor and disable the playground when enabled globally', async () => {
    const conf = await loadConf({ APP__GRAPHQL__SECURE_BY_DEFAULT: 'true' });

    expect(conf.GRAPHQL_SECURE_BY_DEFAULT).toBe(true);
    expect(conf.GRAPHQL_ARMOR_DISABLED).toBe(false);
    expect(conf.PLAYGROUND_ENABLED).toBe(false);
  });

  it('should let the GraphQL options relax the enabled global option', async () => {
    const conf = await loadConf({
      APP__GRAPHQL__SECURE_BY_DEFAULT: 'true',
      APP__GRAPHQL__ARMOR_PROTECTION__DISABLED: 'true',
      APP__GRAPHQL__PLAYGROUND__ENABLED: 'true',
    });

    expect(conf.GRAPHQL_ARMOR_DISABLED).toBe(true);
    expect(conf.PLAYGROUND_ENABLED).toBe(true);
  });

  it('should let the GraphQL options harden the disabled global option', async () => {
    const conf = await loadConf({
      APP__GRAPHQL__SECURE_BY_DEFAULT: 'false',
      APP__GRAPHQL__ARMOR_PROTECTION__DISABLED: 'false',
      APP__GRAPHQL__PLAYGROUND__ENABLED: 'false',
    });

    expect(conf.GRAPHQL_ARMOR_DISABLED).toBe(false);
    expect(conf.PLAYGROUND_ENABLED).toBe(false);
  });

  it('should disable the playground when the UI is disabled', async () => {
    const conf = await loadConf({ APP__ENABLED_UI: 'false', APP__GRAPHQL__PLAYGROUND__ENABLED: 'true' });

    expect(conf.PLAYGROUND_ENABLED).toBe(false);
  });
});
