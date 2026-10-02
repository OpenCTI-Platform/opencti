import { screen } from '@testing-library/react';
import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../utils/tests/test-render';
import IntegrationsNavBadge from './IntegrationsNavBadge';
import { NavBarView } from './NavBar';

const mocks = vi.hoisted(() => ({
  useIntegrationsNavBadge: vi.fn(),
}));

vi.mock('./useIntegrationsNavBadge', () => ({
  default: mocks.useIntegrationsNavBadge,
}));

const renderNavWithIntegrationsBadge = () => testRender(
  <NavBarView
    groups={[{
      id: 'main',
      items: [
        { id: 'home', label: 'Home', icon: null, link: '/dashboard', exact: true },
        {
          id: 'integrations',
          label: 'Integrations',
          icon: null,
          link: '/dashboard/integrations',
          badge: <IntegrationsNavBadge queryRef={{} as never} compact={false} />,
        },
      ],
    }]}
    pathname="/dashboard"
    collapsed={false}
    onCollapsedChange={vi.fn()}
    openSubmenus={[]}
    onSubmenuOpenChange={vi.fn()}
    submenuShowIcons={false}
    topOffset="0px"
    bottomOffset="0px"
    flowOffset="0px"
    header={null}
    footer={null}
    navLabel="Main navigation"
  />,
  { route: '/dashboard' },
);

describe('IntegrationsNavBadge', () => {
  afterEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it('should show the count once the connector statuses are loaded', () => {
    mocks.useIntegrationsNavBadge.mockReturnValue({ content: 3, accessibleText: '3 connector update available' });

    renderNavWithIntegrationsBadge();

    expect(screen.getByText('3')).toBeInTheDocument();
  });

  it('should render the navigation while the connector statuses are still loading', () => {
    mocks.useIntegrationsNavBadge.mockImplementation(() => {
      throw new Promise(() => {});
    });

    renderNavWithIntegrationsBadge();

    expect(screen.getByRole('link', { name: 'Home' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Integrations' })).toBeInTheDocument();
  });

  it('should only hide the badge when the connector statuses cannot be loaded', () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    mocks.useIntegrationsNavBadge.mockImplementation(() => {
      throw new Error('catalog unavailable');
    });

    renderNavWithIntegrationsBadge();

    expect(screen.getByRole('link', { name: 'Home' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Integrations' })).toBeInTheDocument();
  });
});
