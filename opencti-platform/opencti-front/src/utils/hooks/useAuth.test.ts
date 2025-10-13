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
    about: { version: '6.7.17' },
    themes:
      {
        edges: [
          {
            node: {
              id: 'aa4294eb-7f02-45f3-81c0-e52268021cd3',
              name: 'Light',
              theme_background: '#f8f8f8',
              theme_accent: '#dfdfdf',
              theme_paper: '#ffffff',
              theme_nav: '#ffffff',
              theme_primary: '#001bda',
              theme_secondary: '#0c7e69',
              theme_text_color: '#000000',
              theme_logo: '',
              theme_logo_collapsed: '',
              theme_logo_login: '' },
          },
          {
            node: {
              id: 'b9e9766f-467c-4b1e-a4cd-dbf600e139be',
              name: 'Dark',
              theme_background: '#161616',
              theme_accent: '#0f1e38',
              theme_paper: '#09101e',
              theme_nav: '#070d19',
              theme_primary: '#0fbcff',
              theme_secondary: '#00f1bd',
              theme_text_color: '#ffffff',
              theme_logo: '',
              theme_logo_collapsed: '',
              theme_logo_login: '',
            },
          }],
        me: {
          theme: 'b9e9766f-467c-4b1e-a4cd-dbf600e139be',
        },
      },
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
    expect(data.about.version).toEqual('6.7.17');
  });
});
