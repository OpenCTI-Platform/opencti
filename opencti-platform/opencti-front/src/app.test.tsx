import React from 'react';
import { act, cleanup, render } from '@testing-library/react';
import { OperationDescriptor, RelayEnvironmentProvider } from 'react-relay/hooks';
import { createMockEnvironment, MockPayloadGenerator as MockGen } from 'relay-test-utils';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { BrowserRouter } from 'react-router-dom';
import { describe, afterEach, it, expect } from 'vitest';
import AppIntlProvider from './components/AppIntlProvider';
import Profile, { profileQuery } from './private/components/profile/Profile';
import { APP_BASE_PATH } from './relay/environment';
import { UserContext } from './utils/hooks/useAuth';

const me = {
  name: 'admin',
  user_email: 'admin@opencti.io',
  firstname: 'Admin',
  lastname: 'OpenCTI',
  language: 'auto',
  unit_system: 'auto',
  theme: 'default',
  external: true,
  userSubscriptions: {
    edges: [],
  },
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const UserContextValue: any = { me, settings: {}, bannerSettings: {}, entitySettings: {}, platformModuleHelpers: {}, schema: {}, about: {}, themes: {} };

describe('App', () => {
  afterEach(cleanup);

  it('renders without crashing', async () => {
    const environment = createMockEnvironment();
    const profileMockOperation = (operation: OperationDescriptor) => MockGen.generate(operation, {
      MeUser() {
        return me;
      },
      AppInfo() {
        return { version: '5.4.0' };
      },
      Settings() {
        return {
          platform_modules: [],
          otp_mandatory: false,
        };
      },
    });
    environment.mock.queueOperationResolver((operation) => profileMockOperation(operation));
    environment.mock.queuePendingOperation(profileQuery, {});
    const { getByDisplayValue } = render(
      <RelayEnvironmentProvider environment={environment}>
        <BrowserRouter basename={APP_BASE_PATH}>
          <AppIntlProvider settings={{ platform_language: 'auto', platform_translations: '{}' }}>
            <ThemeProvider theme={createTheme()}>
              <UserContext.Provider value={UserContextValue}>
                <Profile />
              </UserContext.Provider>
            </ThemeProvider>
          </AppIntlProvider>
        </BrowserRouter>
      </RelayEnvironmentProvider>,
    );
    act(() => {
      const firstname = getByDisplayValue('Admin');
      expect(firstname).toBeDefined();
    });
  });
});
