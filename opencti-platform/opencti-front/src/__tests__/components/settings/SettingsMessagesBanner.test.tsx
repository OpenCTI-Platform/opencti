import React from 'react';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { act } from '@testing-library/react';
import ReactDOM from 'react-dom/client';
import { RelayEnvironmentProvider } from 'react-relay/hooks';
import { createMockEnvironment, MockPayloadGenerator } from 'relay-test-utils';
import { createTheme, ThemeProvider } from '@mui/material/styles';
import { RelayMockEnvironment } from 'relay-test-utils/lib/RelayModernMockEnvironment';
import SettingsMessagesBanner, { settingsMessagesQuery } from '../../../private/components/settings/settings_messages/SettingsMessagesBanner';
import AppIntlProvider from '../../../components/AppIntlProvider';

let container: HTMLDivElement | null;

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
});

afterEach(() => {
  if (container !== null) {
    document.body.removeChild(container);
  }
  container = null;
});

describe('Settings Messages', () => {
  // Render a react element in HTML objects
  const createComponent = (divElement: HTMLDivElement, environment: RelayMockEnvironment) => {
    ReactDOM.createRoot(divElement).render(
      <RelayEnvironmentProvider environment={environment}>
        <AppIntlProvider settings={{ platform_language: 'auto' }}>
          <ThemeProvider theme={createTheme()}>
            <SettingsMessagesBanner />
          </ThemeProvider>
        </AppIntlProvider>
      </RelayEnvironmentProvider>,
    );
  };
  it('Renders component in loading mode', async () => {
    act(() => {
      if (container !== null) {
        const environment = createMockEnvironment();
        createComponent(container, environment);
      }
    });
    const loader = container?.querySelectorAll('[role="progressbar"]')[0];
    expect(loader).not.toBeNull();
  });
  it('Renders component with datas - activated message and not dismiss', async () => {
    const message = {
      id: '01',
      message: 'This is a default broadcast message.',
      activated: true,
      dismissible: false,
      updated_at: new Date().toString(),
    };
    const environment = createMockEnvironment();
    environment.mock.queueOperationResolver((operation) => {
      return MockPayloadGenerator.generate(operation, {
        Settings() {
          return {
            messages: [message],
          };
        },
      });
    });
    localStorage.setItem('banner', JSON.stringify({ messages: [{ ...message, dismiss: false }] })); // Mocking local storage
    environment.mock.queuePendingOperation(settingsMessagesQuery, {});
    act(() => {
      if (container !== null) {
        createComponent(container, environment);
      }
    });
    const loader = container?.querySelector('#banner_div');
    expect(loader).not.toBeNull();
  });
  it('Renders component with datas - activated message and dismiss', async () => {
    const message = {
      id: '01',
      message: 'This is a default broadcast message.',
      activated: true,
      dismissible: false,
      updated_at: new Date().toString(),
      dismiss: true,
    };
    const environment = createMockEnvironment();
    environment.mock.queueOperationResolver((operation) => {
      return MockPayloadGenerator.generate(operation, {
        Settings() {
          return {
            platform_messages: [message],
          };
        },
      });
    });
    localStorage.setItem('banner', JSON.stringify({ messages: [{ ...message, dismiss: true }] })); // Mocking local storage
    environment.mock.queuePendingOperation(settingsMessagesQuery, {});
    act(() => {
      if (container !== null) {
        createComponent(container, environment);
      }
    });
    const loader = container?.querySelector('#banner_div');
    expect(loader).toBeNull();
  });
  it('Renders component with datas - not activated message', async () => {
    const message = {
      id: '01',
      message: 'This is a default broadcast message.',
      activated: false,
      dismissible: false,
      updated_at: new Date().toString(),
    };
    const environment = createMockEnvironment();
    environment.mock.queueOperationResolver((operation) => {
      return MockPayloadGenerator.generate(operation, {
        Settings() {
          return {
            platform_messages: [message],
          };
        },
      });
    });
    localStorage.setItem('banner', JSON.stringify({ messages: [{ ...message, dismiss: false }] })); // Mocking local storage
    environment.mock.queuePendingOperation(settingsMessagesQuery, {});
    act(() => {
      if (container !== null) {
        createComponent(container, environment);
      }
    });
    const loader = container?.querySelector('#banner_div');
    expect(loader).toBeNull();
  });
});
