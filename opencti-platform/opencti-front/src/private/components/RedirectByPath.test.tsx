import React from 'react';
import { describe, expect, it } from 'vitest';
import { Route, Routes, useLocation } from 'react-router-dom';
import { screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../utils/tests/test-render';
import { SETTINGS_SETMANAGEXTMHUB } from '../../utils/hooks/useGranted';
import RedirectByPath, { XTM_HUB_AUTO_REGISTER_QUERY_PARAM, XTM_HUB_PERMISSION_REQUIRED_QUERY_PARAM, XTM_HUB_PRODUCT_NAME_QUERY_PARAM } from './RedirectByPath';

const LocationProbe = () => {
  const location = useLocation();
  return <div data-testid="location">{`${location.pathname}${location.search}`}</div>;
};

describe('RedirectByPath', () => {
  const authorizedUserContext = createMockUserContext({
    me: {
      ...createMockUserContext().me,
      capabilities: [{ name: SETTINGS_SETMANAGEXTMHUB }],
      capabilitiesInDraft: [],
    },
  });

  it('preserves query params for mapped redirects', async () => {
    testRender(
      <Routes>
        <Route path="/dashboard/redirect/*" element={<RedirectByPath />} />
        <Route path="/dashboard/settings/experience" element={<LocationProbe />} />
      </Routes>,
      {
        route: '/dashboard/redirect/connect-xtm-hub?productName=toto',
        userContext: authorizedUserContext,
      },
    );

    expect(await screen.findByTestId('location')).toHaveTextContent(
      `/dashboard/settings/experience?${XTM_HUB_PRODUCT_NAME_QUERY_PARAM}=toto&${XTM_HUB_AUTO_REGISTER_QUERY_PARAM}=true`,
    );
  });

  it('adds xtm hub auto register query param for connect redirect', async () => {
    testRender(
      <Routes>
        <Route path="/dashboard/redirect/*" element={<RedirectByPath />} />
        <Route path="/dashboard/settings/experience" element={<LocationProbe />} />
      </Routes>,
      {
        route: '/dashboard/redirect/connect-xtm-hub',
        userContext: authorizedUserContext,
      },
    );

    expect(await screen.findByTestId('location')).toHaveTextContent(`/dashboard/settings/experience?${XTM_HUB_AUTO_REGISTER_QUERY_PARAM}=true`);
  });

  it('redirects to dashboard with permission modal query for unauthorized connect redirect', async () => {
    testRender(
      <Routes>
        <Route path="/dashboard/redirect/*" element={<RedirectByPath />} />
        <Route path="/dashboard" element={<LocationProbe />} />
      </Routes>,
      { route: '/dashboard/redirect/connect-xtm-hub?productName=toto' },
    );

    expect(await screen.findByTestId('location')).toHaveTextContent(
      `/dashboard?${XTM_HUB_PRODUCT_NAME_QUERY_PARAM}=toto&${XTM_HUB_PERMISSION_REQUIRED_QUERY_PARAM}=true`,
    );
  });

  it('renders not found for unknown mapping key', () => {
    testRender(
      <Routes>
        <Route path="/dashboard/redirect/*" element={<RedirectByPath />} />
      </Routes>,
      { route: '/dashboard/redirect/unknown' },
    );

    expect(screen.getByText('This page is not found on this OpenCTI application.')).toBeInTheDocument();
  });
});
