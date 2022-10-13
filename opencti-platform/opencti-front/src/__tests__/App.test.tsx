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
          id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
          name: 'admin',
          user_email: 'admin@opencti.io',
          external: true,
          firstname: 'Admin',
          lastname: 'OpenCTI',
          language: 'auto',
          theme: 'default',
          api_token: 'd434ce02-e58e-4cac-8b4c-42bf16748e84',
          otp_activated: null,
          otp_qr: null,
          description: 'Principal admin account',
          userSubscriptions: {
            edges: [],
            pageInfo: {
              endCursor: '',
              hasNextPage: false,
            },
          },
        };
      },
      AppInfo() {
        return { version: '5.4.0' };
      },
      Settings() {
        return {
          platform_modules: [
            {
              id: 'EXPIRATION_SCHEDULER',
              enable: true,
            },
            {
              id: 'TASK_MANAGER',
              enable: true,
            },
            {
              id: 'RULE_ENGINE',
              enable: true,
            },
            {
              id: 'SUBSCRIPTION_MANAGER',
              enable: true,
            },
            {
              id: 'SYNC_MANAGER',
              enable: true,
            },
            {
              id: 'RETENTION_MANAGER',
              enable: true,
            },
            {
              id: 'HISTORY_MANAGER',
              enable: true,
            },
          ],
          id: 'ed26637e-1604-4cd2-be39-93d81a5f0a29',
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
