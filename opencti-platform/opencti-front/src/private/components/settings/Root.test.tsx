import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { waitFor } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import testRender from '../../../utils/tests/test-render';
import { SETTINGS_SETMANAGEXTMHUB, SETTINGS_SUPPORT } from '../../../utils/hooks/useGranted';
import Root from './Root';
import { XTM_HUB_AUTO_REGISTER_QUERY_PARAM, XTM_HUB_PERMISSION_REQUIRED_DIALOG_SESSION_STORAGE_KEY } from '../RedirectByPath';

vi.mock('../../../utils/hooks/useSettingsFallbackUrl', () => ({
  default: () => '/dashboard/settings',
}));

vi.mock('../../../utils/Security', () => ({
  default: ({
    needs,
    children,
    placeholder,
  }: {
    needs?: string[];
    children?: React.ReactNode;
    placeholder?: React.ReactNode;
  }) => {
    const isExperienceSecurity = needs?.includes(SETTINGS_SUPPORT)
      && needs?.includes(SETTINGS_SETMANAGEXTMHUB);
    return <>{isExperienceSecurity ? placeholder : children}</>;
  },
}));

describe('Settings Root permission redirect', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.clear();
  });

  it('initializes permission dialog marker when experience is denied and auto-register is present', async () => {
    testRender(
      <Routes>
        <Route path="/dashboard/settings/*" element={<Root />} />
      </Routes>,
      { route: `/dashboard/settings/experience?${XTM_HUB_AUTO_REGISTER_QUERY_PARAM}=true` },
    );

    await waitFor(() => {
      expect(window.location.pathname).toBe('/dashboard');
    });
    expect(sessionStorage.getItem(XTM_HUB_PERMISSION_REQUIRED_DIALOG_SESSION_STORAGE_KEY)).toBe('true');
  });

  it('does not initialize permission dialog marker when auto-register is absent', async () => {
    testRender(
      <Routes>
        <Route path="/dashboard/settings/*" element={<Root />} />
      </Routes>,
      { route: '/dashboard/settings/experience' },
    );

    await waitFor(() => {
      expect(window.location.pathname).toBe('/dashboard/settings');
    });
    expect(sessionStorage.getItem(XTM_HUB_PERMISSION_REQUIRED_DIALOG_SESSION_STORAGE_KEY)).toBeNull();
  });
});
