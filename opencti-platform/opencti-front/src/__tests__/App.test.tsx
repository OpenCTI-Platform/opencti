/* eslint-disable no-console */
import React from 'react';
import { act, cleanup, render } from '@testing-library/react';
import { OperationDescriptor, RelayEnvironmentProvider } from 'react-relay/hooks';
import { createMockEnvironment, MockPayloadGenerator as MockGen } from 'relay-test-utils';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { BrowserRouter } from 'react-router-dom';
import { CompatRouter } from 'react-router-dom-v5-compat';
import { describe, afterEach, it, expect } from 'vitest';
import AppIntlProvider from '../components/AppIntlProvider';
import Profile, { profileQuery } from '../private/components/profile/Profile';
import { APP_BASE_PATH } from '../relay/environment';

describe('App', () => {
  afterEach(cleanup);

  it('renders without crashing', async () => {
    const environment = createMockEnvironment();
    const profileMockOperation = (operation: OperationDescriptor) => MockGen.generate(operation, {
      MeUser() {
        return {
          name: 'admin',
          user_email: 'admin@opencti.io',
          firstname: 'Admin',
          lastname: 'OpenCTI',
          language: 'auto',
          theme: 'default',
          external: true,
          userSubscriptions: {
            edges: [],
          },
        };
      },
      AppInfo() {
        return { version: '5.9.6' };
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
          <CompatRouter>
            <AppIntlProvider settings={{ platform_language: 'auto' }}>
              <ThemeProvider theme={createTheme()}>
                <Profile/>
              </ThemeProvider>
            </AppIntlProvider>
          </CompatRouter>
        </BrowserRouter>
      </RelayEnvironmentProvider>,
    );
    act(() => {
      const firstname = getByDisplayValue('Admin');
      expect(firstname).toBeDefined();
    });
  });
});
