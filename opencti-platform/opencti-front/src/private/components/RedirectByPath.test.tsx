import React, { Suspense } from 'react';
import { describe, expect, it } from 'vitest';
import { Route, Routes, useLocation } from 'react-router-dom';
import { screen } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender from '../../utils/tests/test-render';
import { SETTINGS_SETMANAGEXTMHUB } from '../../utils/hooks/useGranted';
import RedirectByPath, { XTM_HUB_AUTO_REGISTER_QUERY_PARAM, XTM_HUB_PERMISSION_REQUIRED_QUERY_PARAM } from './RedirectByPath';

const LocationProbe = () => {
  const location = useLocation();
  return <div data-testid="location">{`${location.pathname}${location.search}`}</div>;
};

const withSuspense = (element: React.ReactElement) => <Suspense fallback={<div>Loading...</div>}>{element}</Suspense>;

describe('RedirectByPath', () => {
  const mockAuthorizedCapabilities = (relayEnv: ReturnType<typeof testRender>['relayEnv']) => {
    relayEnv.mock.resolveMostRecentOperation((operation) =>
      MockPayloadGenerator.generate(operation, {
        MeUser() {
          return { capabilities: [{ name: SETTINGS_SETMANAGEXTMHUB }] };
        },
      }),
    );
  };

  const mockUnauthorizedCapabilities = (relayEnv: ReturnType<typeof testRender>['relayEnv']) => {
    relayEnv.mock.resolveMostRecentOperation((operation) =>
      MockPayloadGenerator.generate(operation, {
        MeUser() {
          return { capabilities: [] };
        },
      }),
    );
  };

  it('preserves query params for mapped redirects', async () => {
    const { relayEnv } = testRender(
      <Routes>
        <Route path="/redirect/*" element={withSuspense(<RedirectByPath />)} />
        <Route path="/dashboard/settings/experience" element={<LocationProbe />} />
      </Routes>,
      { route: '/redirect/connect-xtm-hub?foo=bar' },
    );
    mockAuthorizedCapabilities(relayEnv);

    expect(await screen.findByTestId('location')).toHaveTextContent(
      `/dashboard/settings/experience?foo=bar&${XTM_HUB_AUTO_REGISTER_QUERY_PARAM}=true`,
    );
  });

  it('adds xtm hub auto register query param for connect redirect', async () => {
    const { relayEnv } = testRender(
      <Routes>
        <Route path="/redirect/*" element={withSuspense(<RedirectByPath />)} />
        <Route path="/dashboard/settings/experience" element={<LocationProbe />} />
      </Routes>,
      { route: '/redirect/connect-xtm-hub' },
    );
    mockAuthorizedCapabilities(relayEnv);

    expect(await screen.findByTestId('location')).toHaveTextContent(`/dashboard/settings/experience?${XTM_HUB_AUTO_REGISTER_QUERY_PARAM}=true`);
  });

  it('redirects to dashboard with permission modal query for unauthorized connect redirect', async () => {
    const { relayEnv } = testRender(
      <Routes>
        <Route path="/redirect/*" element={withSuspense(<RedirectByPath />)} />
        <Route path="/dashboard" element={<LocationProbe />} />
      </Routes>,
      { route: '/redirect/connect-xtm-hub?foo=bar' },
    );
    mockUnauthorizedCapabilities(relayEnv);

    expect(await screen.findByTestId('location')).toHaveTextContent(
      `/dashboard?foo=bar&${XTM_HUB_PERMISSION_REQUIRED_QUERY_PARAM}=true`,
    );
  });

  it('renders not found for unknown mapping key', async () => {
    const { relayEnv } = testRender(
      <Routes>
        <Route path="/redirect/*" element={withSuspense(<RedirectByPath />)} />
      </Routes>,
      { route: '/redirect/unknown' },
    );
    mockUnauthorizedCapabilities(relayEnv);

    expect(await screen.findByText('This page is not found on this OpenCTI application.')).toBeInTheDocument();
  });
});
