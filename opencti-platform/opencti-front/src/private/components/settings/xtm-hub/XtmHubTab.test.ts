import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
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

const renderXtmHubTab = (route: string, platformTitle = 'OpenCTI Platform') => {
  return testRender(
    React.createElement(XtmHubTab, { registrationStatus: 'unregistered' }),
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
});
