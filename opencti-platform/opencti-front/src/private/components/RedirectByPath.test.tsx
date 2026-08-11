import React, { Suspense } from 'react';
import { describe, expect, it } from 'vitest';
import { Route, Routes, useLocation } from 'react-router-dom';
import { screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import RedirectByPath, { XTM_HUB_AUTO_REGISTER_QUERY_PARAM } from './RedirectByPath';

const LocationProbe = () => {
  const location = useLocation();
  return <div data-testid="location">{`${location.pathname}${location.search}`}</div>;
};

const withSuspense = (element: React.ReactElement) => <Suspense fallback={<div>Loading...</div>}>{element}</Suspense>;

describe('RedirectByPath', () => {
  it('preserves query params for mapped redirects', async () => {
    testRender(
      <Routes>
        <Route path="/redirect/*" element={withSuspense(<RedirectByPath />)} />
        <Route path="/dashboard/settings/experience" element={<LocationProbe />} />
      </Routes>,
      { route: '/redirect/connect-xtm-hub?foo=bar' },
    );

    expect(await screen.findByTestId('location')).toHaveTextContent(
      `/dashboard/settings/experience?foo=bar&${XTM_HUB_AUTO_REGISTER_QUERY_PARAM}=true`,
    );
  });

  it('adds xtm hub auto register query param for connect redirect', async () => {
    testRender(
      <Routes>
        <Route path="/redirect/*" element={withSuspense(<RedirectByPath />)} />
        <Route path="/dashboard/settings/experience" element={<LocationProbe />} />
      </Routes>,
      { route: '/redirect/connect-xtm-hub' },
    );

    expect(await screen.findByTestId('location')).toHaveTextContent(`/dashboard/settings/experience?${XTM_HUB_AUTO_REGISTER_QUERY_PARAM}=true`);
  });

  it('renders not found for unknown mapping key', async () => {
    testRender(
      <Routes>
        <Route path="/redirect/*" element={withSuspense(<RedirectByPath />)} />
      </Routes>,
      { route: '/redirect/unknown' },
    );

    expect(await screen.findByText('This page is not found on this OpenCTI application.')).toBeInTheDocument();
  });
});
