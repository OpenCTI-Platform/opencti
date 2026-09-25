import { screen } from '@testing-library/react';
import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import testRender from '../../../utils/tests/test-render';
import Notifications from './Notifications';

vi.mock('./Alerts', () => ({
  default: () => <div>Alerts tab content</div>,
}));

vi.mock('./Triggers', () => ({
  default: () => <div>Triggers tab content</div>,
}));

describe('Notifications', () => {
  it('renders the alerts tab by default', () => {
    testRender(<Notifications />, { route: '/dashboard/profile/notifications' });

    expect(screen.getByText('Alerts tab content')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Alerts' })).toHaveAttribute('href', '/dashboard/profile/notifications');
    expect(screen.getByRole('tab', { name: 'Triggers' })).toHaveAttribute('href', '/dashboard/profile/notifications/triggers');
  });

  it('renders the triggers tab when the URL points to it', () => {
    testRender(<Notifications />, { route: '/dashboard/profile/notifications/triggers' });

    expect(screen.getByText('Triggers tab content')).toBeInTheDocument();
    expect(screen.queryByText('Alerts tab content')).not.toBeInTheDocument();
  });

  it('redirects legacy alert paths to the canonical alerts URL', () => {
    testRender(<Notifications />, { route: '/dashboard/profile/notifications/alerts' });

    expect(window.location.pathname).toBe('/dashboard/profile/notifications');
  });
});
