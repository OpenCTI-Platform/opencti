/* eslint-disable no-console */
import React from 'react';
import { act, cleanup, render } from '@testing-library/react';
import { RelayEnvironmentProvider } from 'react-relay/hooks';
import { createMockEnvironment, MockPayloadGenerator } from 'relay-test-utils';
import { ThemeProvider } from '@mui/material/styles';
import createTheme from '@mui/material/styles/createTheme';
import { BrowserRouter } from 'react-router-dom';
import { CompatRouter } from 'react-router-dom-v5-compat';
import AppIntlProvider from '../components/AppIntlProvider';
import Profile from '../private/components/Profile';
import { APP_BASE_PATH } from '../relay/environment';

const originalError = console.error.bind(console.error);
beforeAll(() => {
  console.error = (msg) => {
    const data = msg.toString();
    return !data.includes('formError') && !data.includes('%s') && originalError(msg);
  };
});
afterAll(() => {
  console.error = originalError;
});

afterEach(cleanup);

test('renders without crashing', async () => {
  const environment = createMockEnvironment();
  // eslint-disable-next-line arrow-body-style
  environment.mock.queueOperationResolver((operation) => {
    return MockPayloadGenerator.generate(operation, {
      MeUser() {
        return {
          name: 'admin',
          user_email: 'admin@opencti.io',
          firstname: 'Admin',
          lastname: 'OpenCTI',
          language: 'auto',
          theme: 'default',
          userSubscriptions: {
            edges: [],
          },
        };
      },
      AppInfo() {
        return { version: '5.4.0' };
      },
      Settings() {
        return {
          platform_modules: [],
        };
      },
    });
  });
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
