import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import XtmHubTab, { getRegistrationPlatformTitle, getXtmHubProductName } from './XtmHubTab';
import { XTM_HUB_AUTO_REGISTER_QUERY_PARAM, XTM_HUB_PRODUCT_NAME_QUERY_PARAM } from '../../RedirectByPath';

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
  describe('getXtmHubProductName', () => {
    it('returns product name from search params', () => {
      expect(getXtmHubProductName('?productName=OpenCTI')).toEqual('OpenCTI');
    });

    it('returns null when product name is absent', () => {
      expect(getXtmHubProductName('?foo=bar')).toBeNull();
    });

    it('returns null when product name is blank', () => {
      expect(getXtmHubProductName('?productName=%20%20')).toBeNull();
    });
  });

  describe('getRegistrationPlatformTitle', () => {
    it('uses auto registration product name when available', () => {
      expect(
        getRegistrationPlatformTitle({
          autoRegistrationProductName: 'OpenCTI',
          fallbackPlatformTitle: 'OpenCTI Platform',
        }),
      ).toEqual('OpenCTI');
    });

    it('falls back to platform title when auto registration product name is missing', () => {
      expect(
        getRegistrationPlatformTitle({
          autoRegistrationProductName: null,
          fallbackPlatformTitle: 'OpenCTI Platform',
        }),
      ).toEqual('OpenCTI Platform');
    });
  });

  describe('XtmHubTab auto-registration flow', () => {
    beforeEach(() => {
      vi.clearAllMocks();
    });

    it('uses the auto-registration product name in the registration URL after confirmation', async () => {
      const route = `/dashboard/settings/experience?${XTM_HUB_AUTO_REGISTER_QUERY_PARAM}=true&${XTM_HUB_PRODUCT_NAME_QUERY_PARAM}=OpenCTI%20XTM`;
      const { user } = renderXtmHubTab(route, 'Fallback Platform');

      const authorizeDialog = await screen.findByRole('dialog', { name: 'Authorize connection' });
      await user.click(within(authorizeDialog).getByRole('button', { name: 'Continue' }));

      await waitFor(() => {
        expect(mockOpenTab).toHaveBeenCalledTimes(1);
      });
      expect(getLastRegistrationUrl()).toContain('platform_title=OpenCTI+XTM');
      expect(getLastRegistrationUrl()).toContain('platform_id=settings-id');
    });

    it('falls back to platform title after canceling auto-registration and starting registration manually', async () => {
      const route = `/dashboard/settings/experience?${XTM_HUB_AUTO_REGISTER_QUERY_PARAM}=true&${XTM_HUB_PRODUCT_NAME_QUERY_PARAM}=OpenCTI%20From%20Hub`;
      const { user } = renderXtmHubTab(route, 'Fallback Platform');

      const authorizeDialog = await screen.findByRole('dialog', { name: 'Authorize connection' });
      await user.click(within(authorizeDialog).getByRole('button', { name: 'Cancel' }));

      await waitFor(() => {
        expect(screen.queryByRole('dialog', { name: 'Authorize connection' })).not.toBeInTheDocument();
      });

      await user.click(screen.getByRole('button', { name: 'Connect to XTM Hub' }));
      const processDialog = await screen.findByRole('dialog', { name: 'Connect your product to XTM Hub' });
      await user.click(within(processDialog).getByRole('button', { name: 'Continue' }));

      await waitFor(() => {
        expect(mockOpenTab).toHaveBeenCalledTimes(1);
      });
      expect(getLastRegistrationUrl()).toContain('platform_title=Fallback+Platform');
    });
  });
});
