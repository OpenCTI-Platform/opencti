import { createTheme, ThemeProvider } from '@mui/material/styles';
import { RelayEnvironmentProvider } from 'react-relay/hooks';
import React, { ReactNode } from 'react';
import { render, renderHook } from '@testing-library/react';
import { createMockEnvironment } from 'relay-test-utils';
import { EnvironmentConfig } from 'relay-runtime';
import userEvent from '@testing-library/user-event';
import { RelayMockEnvironment } from 'relay-test-utils/lib/RelayModernMockEnvironment';
import { UserContext, UserContextType } from '../hooks/useAuth';
import AppIntlProvider from '../../components/AppIntlProvider';

// 'unknown' to facilitate mocking partial context without having TS errors
interface CreateUserContextOptions {
  me?: unknown,
  settings?: unknown,
  bannerSettings?: unknown,
  entitySettings?: unknown,
  platformModuleHelpers?: unknown,
  schema?: unknown,
}

/**
 * Create a fake user context to match your needs while testing.
 * If no special need, you don't have to specify any option.
 *
 * @param options (optional) Context values to push into the fake context.
 * @returns The user context for the tests.
 */
export const createMockUserContext = (options?: CreateUserContextOptions): UserContextType => {
  const {
    me,
    settings,
    bannerSettings,
    entitySettings,
    platformModuleHelpers,
    schema,
  } = options ?? {};

  return {
    me: (me ?? {
      name: 'admin',
      user_email: 'admin@opencti.io',
      firstname: 'Admin',
      lastname: 'OpenCTI',
      language: 'en-us',
      unit_system: 'auto',
      theme: 'default',
      external: true,
      userSubscriptions: {
        edges: [],
      },
    }) as UserContextType['me'],
    settings: (settings ?? {}) as UserContextType['settings'],
    bannerSettings: (bannerSettings ?? {}) as UserContextType['bannerSettings'],
    entitySettings: (entitySettings ?? {}) as UserContextType['entitySettings'],
    platformModuleHelpers: (platformModuleHelpers ?? {}) as UserContextType['platformModuleHelpers'],
    schema: (schema ?? {}) as UserContextType['schema'],
  };
};

export interface ProvidersWrapperProps {
  children: ReactNode
  relayEnv: RelayMockEnvironment
  userContext?: Partial<UserContextType>
}

export const ProvidersWrapper = ({ children, relayEnv, userContext }: ProvidersWrapperProps) => {
  const defaultUserContext = userContext ?? createMockUserContext();

  return (
    <RelayEnvironmentProvider environment={relayEnv}>
      <AppIntlProvider settings={{ platform_language: 'auto' }}>
        <ThemeProvider theme={createTheme()}>
          <UserContext.Provider value={defaultUserContext as UserContextType}>
            {children}
          </UserContext.Provider>
        </ThemeProvider>
      </AppIntlProvider>
    </RelayEnvironmentProvider>
  );
};

interface TestRenderOptions {
  relayConfig?: Partial<EnvironmentConfig>,
  userContext?: Partial<UserContextType>,
}

/**
 * Renders a React component to test it.
 *
 * @param ui The React component to test.
 * @param options (optional) Options to configure mocked providers needed to render the component.
 * @returns Rendered component we can manipulate and make assertions on.
 */
const testRender = (ui: ReactNode, options?: TestRenderOptions) => {
  const { relayConfig, userContext } = options ?? {};
  // TODO Fix this
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  const relayEnv = createMockEnvironment(relayConfig);

  return {
    user: userEvent.setup(),
    relayEnv,
    ...render(ui, {
      wrapper: ({ children }) => (
        <ProvidersWrapper relayEnv={relayEnv} userContext={userContext}>
          {children}
        </ProvidersWrapper>
      ),
    }),
  };
};

/**
 * Renders a React component to test it.
 *
 * @param hook The React hook to test.
 * @param options (optional) Options to configure mocked providers needed to render the hook.
 * @returns Rendered hook we can manipulate and make assertions on.
 */
export function testRenderHook<A, R>(hook: (args: A) => R, options?: TestRenderOptions) {
  const { relayConfig, userContext } = options ?? {};
  // TODO Fix this
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  const relayEnv = createMockEnvironment(relayConfig);

  return {
    relayEnv,
    hook: renderHook(hook, {
      wrapper: ({ children }) => (
        <ProvidersWrapper relayEnv={relayEnv} userContext={userContext}>
          {children}
        </ProvidersWrapper>
      ),
    }),
  };
}

export default testRender;
