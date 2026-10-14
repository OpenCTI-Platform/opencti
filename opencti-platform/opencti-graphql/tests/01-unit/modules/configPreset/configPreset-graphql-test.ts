import { afterEach, describe, expect, it, vi } from 'vitest';

const registerGraphqlSchema = vi.hoisted(() => vi.fn());
const flags = vi.hoisted(() => ({ enabled: false }));

vi.mock('../../../../src/graphql/schema', () => ({ registerGraphqlSchema }));
vi.mock('../../../../src/config/conf', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/config/conf')>()),
  isFeatureEnabled: vi.fn(() => flags.enabled),
}));

// The registration is a module-level side effect: import the module again for each case
const importConfigPresetGraphql = async () => {
  vi.resetModules();
  await import('../../../../src/modules/configPreset/configPreset-graphql');
};

describe('Config preset GraphQL schema registration', () => {
  afterEach(() => {
    registerGraphqlSchema.mockClear();
  });

  it('does not register the schema when CONFIG_PRESET is disabled', async () => {
    flags.enabled = false;
    await importConfigPresetGraphql();
    expect(registerGraphqlSchema).not.toHaveBeenCalled();
  });

  it('registers the module type definitions and resolvers once when CONFIG_PRESET is enabled', async () => {
    flags.enabled = true;
    await importConfigPresetGraphql();
    const { default: configPresetTypeDefs } = await import('../../../../src/modules/configPreset/configPreset.graphql');
    const { default: configPresetResolvers } = await import('../../../../src/modules/configPreset/configPreset-resolver');
    expect(registerGraphqlSchema).toHaveBeenCalledTimes(1);
    expect(registerGraphqlSchema).toHaveBeenCalledWith({ schema: configPresetTypeDefs, resolver: configPresetResolvers });
  });
});
