import { describe, it, expect } from 'vitest';
import { RelayEnvironmentProvider } from 'react-relay/hooks';
import { createTheme, ThemeProvider } from '@mui/material/styles';
import React from 'react';
import { RelayMockEnvironment } from 'relay-test-utils/lib/RelayModernMockEnvironment';
import ReactDOM from 'react-dom/client';
import { createMockEnvironment } from 'relay-test-utils';
import Alert from '@mui/material/Alert';
import { act } from '@testing-library/react';
import Security from '../../utils/Security';
import AppIntlProvider from '../../components/AppIntlProvider';
import { BYPASS, EXPLORE_EXUPDATE, KNOWLEDGE_KNUPDATE } from '../../utils/hooks/useGranted';
import { UserContext } from '../../utils/hooks/useAuth';

const userAdmin = {
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
  capabilities: [{ name: BYPASS }],
};

const userZeroCapability = {
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
  capabilities: [],
};

const userOneCapability = {
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
  capabilities: [{ name: KNOWLEDGE_KNUPDATE }],
};

const userTwoCapability = {
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
  capabilities: [{ name: KNOWLEDGE_KNUPDATE }, { name: EXPLORE_EXUPDATE }],
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const AdminContext: any = { me: userAdmin, settings: {}, bannerSettings: {}, entitySettings: {}, platformModuleHelpers: {}, schema: {} };
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const ZeroCapabilityContext: any = { me: userZeroCapability, settings: {}, bannerSettings: {}, entitySettings: {}, platformModuleHelpers: {}, schema: {} };
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const OneCapabilityContext: any = { me: userOneCapability, settings: {}, bannerSettings: {}, entitySettings: {}, platformModuleHelpers: {}, schema: {} };
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const TwoCapabilityContext: any = { me: userTwoCapability, settings: {}, bannerSettings: {}, entitySettings: {}, platformModuleHelpers: {}, schema: {} };

let container: HTMLDivElement | null;
describe('Security validations', () => {
  it('admin with BYPASS should be allowed whatever the required permission is.', async () => {
    act(() => {
      const createComponent = (divElement: HTMLDivElement, environment: RelayMockEnvironment) => {
        ReactDOM.createRoot(divElement).render(
          <RelayEnvironmentProvider environment={environment}>
            <AppIntlProvider settings={{ platform_language: 'auto' }}>
              <ThemeProvider theme={createTheme()}>
                <UserContext.Provider value={AdminContext}>
                  <Security needs={[KNOWLEDGE_KNUPDATE, EXPLORE_EXUPDATE]}>
                    <Alert
                      severity="info"
                      variant="outlined"
                    >The security allows to see this data.</Alert>
                  </Security>
                </UserContext.Provider>
              </ThemeProvider>
            </AppIntlProvider>
          </RelayEnvironmentProvider>,
        );
      };
      container = document.createElement('div');
      const environment = createMockEnvironment();
      createComponent(container, environment);
    });

    const alertContent = container?.querySelectorAll('[role="alert"]')[0];
    expect(alertContent?.innerHTML).contains('The security allows to see this data');
  });

  it('user with zero capability should not be allowed whatever the required permission is.', async () => {
    act(() => {
      const createComponent = (divElement: HTMLDivElement, environment: RelayMockEnvironment) => {
        ReactDOM.createRoot(divElement).render(
          <RelayEnvironmentProvider environment={environment}>
            <AppIntlProvider settings={{ platform_language: 'auto' }}>
              <ThemeProvider theme={createTheme()}>
                <UserContext.Provider value={ZeroCapabilityContext}>
                  <Security
                    needs={[KNOWLEDGE_KNUPDATE, EXPLORE_EXUPDATE]}
                    placeholder={<span>NOT ALLOWED</span>}
                  >
                    <Alert
                      severity="info"
                      variant="outlined"
                    >The security allows to see this data.</Alert>
                  </Security>
                </UserContext.Provider>
              </ThemeProvider>
            </AppIntlProvider>
          </RelayEnvironmentProvider>,
        );
      };

      container = document.createElement('div');
      const environment = createMockEnvironment();
      createComponent(container, environment);
    });

    const alertContent = container?.querySelectorAll('[role="alert"]')[0];
    expect(alertContent).toBeUndefined();
    expect(container?.innerHTML).contains('NOT ALLOWED');
  });

  it('user with one capability should not be allowed when all are required.', async () => {
    act(() => {
      const createComponent = (divElement: HTMLDivElement, environment: RelayMockEnvironment) => {
        ReactDOM.createRoot(divElement).render(
          <RelayEnvironmentProvider environment={environment}>
            <AppIntlProvider settings={{ platform_language: 'auto' }}>
              <ThemeProvider theme={createTheme()}>
                <UserContext.Provider value={OneCapabilityContext}>
                  <Security
                    needs={[KNOWLEDGE_KNUPDATE, EXPLORE_EXUPDATE]}
                    matchAll={true}
                    placeholder={<span>NOT ALLOWED</span>}
                  >
                    <Alert
                      severity="info"
                      variant="outlined"
                    >The security allows to see this data.</Alert>
                  </Security>
                </UserContext.Provider>
              </ThemeProvider>
            </AppIntlProvider>
          </RelayEnvironmentProvider>,
        );
      };

      container = document.createElement('div');
      const environment = createMockEnvironment();
      createComponent(container, environment);
    });

    const alertContent = container?.querySelectorAll('[role="alert"]')[0];
    expect(alertContent).toBeUndefined();
    expect(container?.innerHTML).contains('NOT ALLOWED');
  });

  it('user with one capability should be allowed when only one is required.', async () => {
    act(() => {
      const createComponent = (divElement: HTMLDivElement, environment: RelayMockEnvironment) => {
        ReactDOM.createRoot(divElement).render(
          <RelayEnvironmentProvider environment={environment}>
            <AppIntlProvider settings={{ platform_language: 'auto' }}>
              <ThemeProvider theme={createTheme()}>
                <UserContext.Provider value={OneCapabilityContext}>
                  <Security
                    needs={[KNOWLEDGE_KNUPDATE, EXPLORE_EXUPDATE]}
                    matchAll={false}
                    placeholder={<span>NOT ALLOWED</span>}
                  >
                    <Alert
                      severity="info"
                      variant="outlined"
                    >The security allows to see this data.</Alert>
                  </Security>
                </UserContext.Provider>
              </ThemeProvider>
            </AppIntlProvider>
          </RelayEnvironmentProvider>,
        );
      };

      container = document.createElement('div');
      const environment = createMockEnvironment();
      createComponent(container, environment);
    });

    const alertContent = container?.querySelectorAll('[role="alert"]')[0];
    expect(alertContent?.innerHTML).contains('The security allows to see this data');
  });

  it('user with 2 capability should be allowed when 2 are required.', async () => {
    act(() => {
      const createComponent = (divElement: HTMLDivElement, environment: RelayMockEnvironment) => {
        ReactDOM.createRoot(divElement).render(
          <RelayEnvironmentProvider environment={environment}>
            <AppIntlProvider settings={{ platform_language: 'auto' }}>
              <ThemeProvider theme={createTheme()}>
                <UserContext.Provider value={TwoCapabilityContext}>
                  <Security
                    needs={[KNOWLEDGE_KNUPDATE, EXPLORE_EXUPDATE]}
                    matchAll={true}
                    placeholder={<span>NOT ALLOWED</span>}
                  >
                    <Alert
                      severity="info"
                      variant="outlined"
                    >The security allows to see this data.</Alert>
                  </Security>
                </UserContext.Provider>
              </ThemeProvider>
            </AppIntlProvider>
          </RelayEnvironmentProvider>,
        );
      };

      container = document.createElement('div');
      const environment = createMockEnvironment();
      createComponent(container, environment);
    });

    const alertContent = container?.querySelectorAll('[role="alert"]')[0];
    expect(alertContent?.innerHTML).contains('The security allows to see this data');
  });
});
