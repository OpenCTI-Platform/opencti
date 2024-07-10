import { createTheme, ThemeProvider } from '@mui/material/styles';
import { RelayEnvironmentProvider } from 'react-relay/hooks';
import React, { ReactNode } from 'react';
import { render } from '@testing-library/react';
import { createMockEnvironment } from 'relay-test-utils';
import { EnvironmentConfig } from 'relay-runtime';
import userEvent from '@testing-library/user-event';
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
  overviewLayoutCustomization?: unknown,
}

const fakeOverviewLayoutCustomization = new Map();
const threatActorIndividualConfiguration = new Map();
threatActorIndividualConfiguration.set('details', { order: 1, width: 6 });
threatActorIndividualConfiguration.set('basicInformation', { order: 2, width: 6 });
threatActorIndividualConfiguration.set('demographics-biographics', { order: 3, width: 6 });
threatActorIndividualConfiguration.set('latestCreatedRelationships', { order: 5, width: 6 });
threatActorIndividualConfiguration.set('latestContainers', { order: 6, width: 6 });
threatActorIndividualConfiguration.set('externalReferences', { order: 7, width: 6 });
threatActorIndividualConfiguration.set('mostRecentHistory', { order: 8, width: 6 });
threatActorIndividualConfiguration.set('notes', { order: 9, width: 12 });
fakeOverviewLayoutCustomization.set(
  'Threat-Actor-Individual',
  threatActorIndividualConfiguration,
);

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
    overviewLayoutCustomization,
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
    overviewLayoutCustomization: (overviewLayoutCustomization ?? fakeOverviewLayoutCustomization) as UserContextType['overviewLayoutCustomization'],
  };
};

export interface ProvidersWrapperProps {
  children: ReactNode
  relayConfig?: Partial<EnvironmentConfig>
  userContext?: Partial<UserContextType>
}

export const ProvidersWrapper = ({ children, relayConfig, userContext }: ProvidersWrapperProps) => {
  const relayEnv = createMockEnvironment(relayConfig);
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
  return {
    user: userEvent.setup(),
    ...render(ui, {
      wrapper: ({ children }) => (
        <ProvidersWrapper relayConfig={relayConfig} userContext={userContext}>
          {children}
        </ProvidersWrapper>
      ),
    }),
  };
};

export default testRender;
