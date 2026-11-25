import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { Route, Routes } from 'react-router';
import testRender from '../../../utils/tests/test-render';
import { SETTINGS_SETMANAGEXTMHUB, SETTINGS_SUPPORT } from '../../../utils/hooks/useGranted';
import Root from './Root';
import { XTM_HUB_AUTO_REGISTER_QUERY_PARAM, XTM_HUB_PERMISSION_REQUIRED_DIALOG_SESSION_STORAGE_KEY } from '../RedirectByPath';

// Root lazily imports its pages. A real page pulls in a large module graph
// that would keep loading, and logging, after the test ends in the shared
// worker (isolate: false). Stub the one these tests render (Settings) so every
// import settles inside the test; the mocked Security below never renders Experience.
vi.mock('./Settings', () => ({ default: () => <div>Settings page</div> }));
vi.mock('./Experience', () => ({ default: () => <div>Experience page</div> }));

vi.mock('./useSettingsFallbackUrl', () => ({
  default: () => '/dashboard/settings',
}));

// The page rules are covered by EntryGuard's own test: here a page is open unless listed in `deniedPaths` (as the
// Experience entry is in a draft).
let deniedPaths: string[] = [];
vi.mock('../nav/EntryGuard', () => ({
  default: ({ path, children, placeholder }: { path: string; children?: React.ReactNode; placeholder?: React.ReactNode }) => (
    <>{deniedPaths.includes(path) ? placeholder : children}</>
  ),
}));

// Lets the Experience page through the mocked Security below, to tell it apart from the guard's redirect.
let experienceGranted = false;

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
    return <>{isExperienceSecurity && !experienceGranted ? placeholder : children}</>;
  },
}));

describe('Settings Root permission redirect', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.clear();
    deniedPaths = [];
    experienceGranted = false;
  });

  it('redirects a user with the Experience capabilities away from the page when its entry denies it (draft)', async () => {
    experienceGranted = true;
    deniedPaths = ['/dashboard/settings/experience'];
    testRender(
      <Routes>
        <Route path="/dashboard/settings/*" element={<Root />} />
      </Routes>,
      { route: '/dashboard/settings/experience' },
    );

    await waitFor(() => {
      expect(window.location.pathname).toBe('/dashboard/settings');
    });
    expect(await screen.findByText('Settings page')).toBeInTheDocument();
  });

  it('does not show the permission dialog to a user with the Experience capabilities when its entry denies it (draft)', async () => {
    experienceGranted = true;
    deniedPaths = ['/dashboard/settings/experience'];
    testRender(
      <Routes>
        <Route path="/dashboard/settings/*" element={<Root />} />
      </Routes>,
      { route: `/dashboard/settings/experience?${XTM_HUB_AUTO_REGISTER_QUERY_PARAM}=true` },
    );

    await waitFor(() => {
      expect(window.location.pathname).toBe('/dashboard/settings');
    });
    expect(sessionStorage.getItem(XTM_HUB_PERMISSION_REQUIRED_DIALOG_SESSION_STORAGE_KEY)).toBeNull();
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
    expect(await screen.findByText('Settings page')).toBeInTheDocument();
    expect(sessionStorage.getItem(XTM_HUB_PERMISSION_REQUIRED_DIALOG_SESSION_STORAGE_KEY)).toBeNull();
  });
});
