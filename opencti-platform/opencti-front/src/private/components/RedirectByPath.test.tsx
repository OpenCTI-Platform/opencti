import React from 'react';
import { describe, expect, it } from 'vitest';
import { Route, Routes, useLocation } from 'react-router-dom';
import { screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import RedirectByPath from './RedirectByPath';

const LocationProbe = () => {
  const location = useLocation();
  return <div data-testid="location">{`${location.pathname}${location.search}`}</div>;
};

describe('RedirectByPath', () => {
  it('preserves query params for mapped redirects', async () => {
    testRender(
      <Routes>
        <Route path="/dashboard/redirect/*" element={<RedirectByPath />} />
        <Route path="/dashboard/settings/experience" element={<LocationProbe />} />
      </Routes>,
      { route: '/dashboard/redirect/connect-xtm-hub?name=toto' },
    );

    expect(await screen.findByTestId('location')).toHaveTextContent('/dashboard/settings/experience?name=toto');
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
