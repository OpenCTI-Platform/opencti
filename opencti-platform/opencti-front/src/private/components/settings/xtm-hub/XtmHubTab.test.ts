import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen, waitFor, within } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import XtmHubTab from './XtmHubTab';
import { XTM_HUB_AUTO_REGISTER_QUERY_PARAM } from '../../RedirectByPath';

const mockOpenTab = vi.fn();
const mockCloseTab = vi.fn();
const mockFocusTab = vi.fn();
const mockUseExternalTab = vi.fn((_args: { url: string }) => ({
  isTabOpen: false,
  openTab: mockOpenTab,
  closeTab: mockCloseTab,
  focusTab: mockFocusTab,
}));

vi.mock('./useExternalTab', () => ({
  default: (args: { url: string }) => mockUseExternalTab(args),
}));

const getLastRegistrationUrl = () => {
  const calls = mockUseExternalTab.mock.calls;
  if (calls.length === 0) {
    return '';
  }
  return (calls[calls.length - 1]?.[0] as { url?: string } | undefined)?.url ?? '';
};

// The hub tab posts its outcome back through the onMessage given to useExternalTab.
const sendHubMessage = (data: Record<string, unknown>) => {
  const calls = mockUseExternalTab.mock.calls;
  const { onMessage } = calls[calls.length - 1]?.[0] as unknown as { onMessage: (event: MessageEvent) => void };
  onMessage({ data } as MessageEvent);
};

interface XtmHubTabTestProps {
  registrationStatus?: string;
  renderTrigger?: (openDialog: () => void) => React.ReactNode;
  onRegistered?: () => void;
}

const renderXtmHubTab = (
  route: string,
  platformTitle = 'OpenCTI Platform',
  props: XtmHubTabTestProps = {},
) => {
  return testRender(
    React.createElement(XtmHubTab, { registrationStatus: 'unregistered', ...props }),
    {
      route,
      userContext: createMockUserContext({
        settings: {
          id: 'settings-id',
          platform_demo: false,
          platform_title: platformTitle,
          platform_xtmhub_url: 'https://hub.filigran.io/app',
          platform_enterprise_edition: {
            license_validated: false,
          },
        },
      }),
    },
  );
};

describe('XtmHubTab', () => {
  describe('XtmHubTab auto-registration flow', () => {
    beforeEach(() => {
      vi.clearAllMocks();
    });

    it('perform auto connection when using the auto connection query param', async () => {
      const route = `/dashboard/settings/experience?${XTM_HUB_AUTO_REGISTER_QUERY_PARAM}=true`;
      const { user } = renderXtmHubTab(route, 'Fallback Platform');

      const authorizeDialog = await screen.findByRole('dialog', { name: 'Authorize connection' });
      await user.click(within(authorizeDialog).getByRole('button', { name: 'Continue' }));

      await waitFor(() => {
        expect(mockOpenTab).toHaveBeenCalledTimes(1);
      });
      expect(getLastRegistrationUrl()).toContain('platform_title=Fallback+Platform');
      expect(getLastRegistrationUrl()).toContain('platform_id=settings-id');
    });
  });

  describe('XtmHubTab trigger rendering', () => {
    beforeEach(() => {
      vi.clearAllMocks();
    });

    const route = '/dashboard/settings/experience';

    it('renders the default floated button when no renderTrigger is provided', () => {
      renderXtmHubTab(route);

      expect(screen.getByRole('button', { name: 'Connect to XTM Hub' })).toBeInTheDocument();
    });

    it('renders the caller trigger instead of the default button when renderTrigger is provided', () => {
      renderXtmHubTab(route, 'OpenCTI Platform', {
        renderTrigger: (openDialog) => React.createElement(
          'button',
          { type: 'button', onClick: openDialog },
          'Custom trigger',
        ),
      });

      expect(screen.getByRole('button', { name: 'Custom trigger' })).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Connect to XTM Hub' })).not.toBeInTheDocument();
    });

    it('opens the connection dialog through the openDialog callback given to renderTrigger', async () => {
      const { user } = renderXtmHubTab(route, 'OpenCTI Platform', {
        renderTrigger: (openDialog) => React.createElement(
          'button',
          { type: 'button', onClick: openDialog },
          'Custom trigger',
        ),
      });

      await user.click(screen.getByRole('button', { name: 'Custom trigger' }));

      expect(await screen.findByRole('dialog', { name: 'Connect your product to XTM Hub' })).toBeInTheDocument();
    });
  });

  describe('XtmHubTab registration completion', () => {
    beforeEach(() => {
      vi.clearAllMocks();
    });

    const route = '/dashboard/settings/experience';

    it('notifies the caller once the token sent by the hub is saved', async () => {
      const onRegistered = vi.fn();
      const { relayEnv } = renderXtmHubTab(route, 'OpenCTI Platform', { onRegistered });

      act(() => sendHubMessage({ action: 'register', token: 'platform-token' }));
      expect(relayEnv.mock.getMostRecentOperation().fragment.node.name).toBe('XtmHubTabSettingsFieldPatchMutation');
      expect(onRegistered).not.toHaveBeenCalled();
      await act(async () => {
        relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation));
      });

      expect(onRegistered).toHaveBeenCalledTimes(1);
    });

    it('does not notify the caller when saving the token fails', async () => {
      const onRegistered = vi.fn();
      const { relayEnv } = renderXtmHubTab(route, 'OpenCTI Platform', { onRegistered });

      act(() => sendHubMessage({ action: 'register', token: 'platform-token' }));
      await act(async () => {
        // Same shape as a Relay network error: useApiMutation reads its GraphQL errors to notify the user.
        relayEnv.mock.rejectMostRecentOperation(Object.assign(new Error('Unable to save the token'), {
          res: { errors: [{ message: 'Unable to save the token' }] },
        }));
      });

      expect(onRegistered).not.toHaveBeenCalled();
    });
  });
});
