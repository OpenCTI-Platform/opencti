import { describe, it, expect } from 'vitest';
import { testRenderHook } from '../tests/test-render';
import useAuth, { UserContextType } from './useAuth';

describe('Hook: useAuth', () => {
  const baseUserContext = {
    me: { me: 'me' },
    schema: { schema: 'schema' },
    bannerSettings: { bannerSettings: 'bannerSettings' },
    entitySettings: { entitySettings: 'entitySettings' },
    platformModuleHelpers: { platformModuleHelpers: 'platformModuleHelpers' },
    settings: { settings: 'settings' },
  } as unknown as UserContextType;

  it('should throw an error if "me" undefined', () => {
    const call = () => testRenderHook(
      () => useAuth(),
      {
        userContext: {
          ...baseUserContext,
          me: undefined,
        },
      },
    );
    expect(call).toThrowError('Invalid user context !');
  });

  // TODO other throws

  it('should return the context if everything fine', () => {
    const { hook } = testRenderHook(
      () => useAuth(),
      { userContext: baseUserContext },
    );
    const data = hook.result.current;
    expect(data.me).toEqual({ me: 'me' });
    expect(data.schema).toEqual({ schema: 'schema' });
    expect(data.bannerSettings).toEqual({ bannerSettings: 'bannerSettings' });
    expect(data.entitySettings).toEqual({ entitySettings: 'entitySettings' });
    expect(data.platformModuleHelpers).toEqual({ platformModuleHelpers: 'platformModuleHelpers' });
    expect(data.settings).toEqual({ settings: 'settings' });
  });
});
