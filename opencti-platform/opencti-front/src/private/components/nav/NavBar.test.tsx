import { screen, within } from '@testing-library/react';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import testRender from '../../../utils/tests/test-render';
import { isRouteSelected, NavBarView, NavBarViewProps } from './NavBar';
import { NavGroup } from './useNavMenu';

const groups: NavGroup[] = [
  {
    id: 'main',
    items: [{ id: 'home', label: 'Home', icon: null, link: '/dashboard', exact: true }],
  },
  {
    id: 'knowledge',
    items: [
      {
        id: 'threats',
        label: 'Threats',
        icon: null,
        link: '/dashboard/threats',
        subItems: [
          { type: 'Threat-Actor-Group', link: '/dashboard/threats/threat_actors_group', label: 'Threat actors (group)' },
          { type: 'Campaign', link: '/dashboard/threats/campaigns', label: 'Campaigns' },
        ],
      },
    ],
  },
];

const renderNav = (overrides: Partial<NavBarViewProps> = {}, route = '/dashboard') => testRender(
  <NavBarView
    groups={groups}
    pathname={overrides.pathname ?? route}
    collapsed={false}
    onCollapsedChange={vi.fn()}
    openSubmenus={[]}
    onSubmenuOpenChange={vi.fn()}
    submenuShowIcons={false}
    header={null}
    footer={null}
    navLabel="Main navigation"
    {...overrides}
  />,
  { route },
);

describe('NavBarView', () => {
  it('names the rail so the e2e page object and screen readers can find it', () => {
    renderNav();
    expect(screen.getByLabelText('Main navigation')).toBeInTheDocument();
  });

  it('renders leaf entries as real links, which is what makes Ctrl-click work', () => {
    renderNav();
    const home = screen.getByRole('link', { name: 'Home' });
    // A button with an onClick handler would look identical but could not be
    // opened in a new tab, which is the regression this asserts against.
    expect(home).toHaveAttribute('href', '/dashboard');
  });

  it('marks the active entry with aria-current, which the library styles from', () => {
    renderNav({ pathname: '/dashboard' }, '/dashboard');
    expect(screen.getByRole('link', { name: 'Home' })).toHaveAttribute('aria-current', 'page');
  });

  it('does not mark Data as active while a draft is open', () => {
    // Reproduces the exception the previous rail carried: drafts live under
    // the /dashboard/data prefix but must not light the Data entry up.
    expect(isRouteSelected('/dashboard/data/import/draft/abc', '/dashboard/data')).toBe(false);
    expect(isRouteSelected('/dashboard/data/entities', '/dashboard/data')).toBe(true);
    expect(isRouteSelected('/dashboard/workspaces/dashboards_public', '/dashboard/workspaces/dashboards', true)).toBe(false);
  });

  it('renders submenu entries as real links too', () => {
    renderNav({ openSubmenus: ['threats'] });
    expect(screen.getByRole('link', { name: 'Campaigns' })).toHaveAttribute(
      'href',
      '/dashboard/threats/campaigns',
    );
  });

  it('leaves a submenu parent non-navigable while the rail is expanded', () => {
    // Iso-functional with the previous rail: expanded, clicking a parent only
    // toggled its submenu; it never navigated.
    renderNav({ collapsed: false });
    const parent = screen.getByRole('button', { name: /Threats/ });
    expect(parent).not.toHaveAttribute('href');
  });

  it('makes a submenu parent navigable while the rail is collapsed', () => {
    // ...and collapsed, clicking the parent DID navigate to its own route.
    renderNav({ collapsed: true });
    const parent = screen.getByRole('link', { name: /Threats/ });
    expect(parent.tagName).toBe('A');
    expect(parent).toHaveAttribute('href', '/dashboard/threats');
    // Recorded, not asserted as desirable: the library renders a bare anchor
    // here, not a router Link, so this one navigation is a full page reload
    // where the previous rail did a client-side navigate(). Same destination,
    // different mechanism. Filed as library feedback.
  });

  it('hides submenu icons when the user preference is off', () => {
    const withIcons: NavGroup[] = [{
      id: 'g',
      items: [{
        id: 'threats',
        label: 'Threats',
        icon: null,
        link: '/dashboard/threats',
        subItems: [{ link: '/a', label: 'A', icon: <svg data-testid="sub-icon" /> }],
      }],
    }];
    const { unmount } = renderNav({ groups: withIcons, openSubmenus: ['threats'], submenuShowIcons: false });
    expect(screen.queryByTestId('sub-icon')).not.toBeInTheDocument();
    unmount();
    renderNav({ groups: withIcons, openSubmenus: ['threats'], submenuShowIcons: true });
    expect(screen.getByTestId('sub-icon')).toBeInTheDocument();
  });

  it('separates groups so no separator is rendered against nothing', () => {
    const { container } = renderNav();
    // Two groups, therefore exactly one separator between them.
    expect(container.querySelectorAll('hr')).toHaveLength(1);
  });
});

describe('NavBarView accent compensation', () => {
  it('overrides the library brand token on the rail', () => {
    const { container } = renderNav({ accentColor: '#ff9800' });
    const nav = container.querySelector('nav');
    expect(nav?.style.getPropertyValue('--color-filigran-brand-primary')).toBe('#ff9800');
  });

  it('leaves the token alone when no accent is supplied', () => {
    const { container } = renderNav();
    expect(container.querySelector('nav')?.style.getPropertyValue('--color-filigran-brand-primary')).toBe('');
  });

  /**
   * NON-REGRESSION GUARD. The compensation above works only because the
   * library still paints the selected row from this exact custom property. If
   * a future pin renames it, nothing would fail at build or runtime — the
   * accent would just silently fall back to Filigran blue and the customised
   * `theme_primary` would be lost without a single red test. This reads the
   * installed stylesheet and fails loudly instead.
   */
  it('still finds the brand token driving the selected-row styling in the installed library', () => {
    const require = createRequire(import.meta.url);
    const cssPath = require.resolve('@filigran/design-system/dist/index.css');
    const css = readFileSync(cssPath, 'utf8');
    const currentPageRules = css
      .split('}')
      .filter((rule) => rule.includes('aria-current=page') || rule.includes('aria-current="page"'));
    expect(currentPageRules.length).toBeGreaterThan(0);
    expect(
      currentPageRules.some((rule) => rule.includes('--color-filigran-brand-primary')),
    ).toBe(true);
  });
});

describe('NavBarView rail width', () => {
  it('collapses to the width the floating toolbars offset themselves by', () => {
    // The library sizes the rail with a utility class, not an inline width, so
    // this asserts the class the constants were derived from. `w-12` is 48px
    // and `w-45` is 180px, which is what SMALL_BAR_WIDTH / OPEN_BAR_WIDTH say.
    const { container, unmount } = renderNav({ collapsed: true });
    expect(container.querySelector('nav')?.className).toContain('w-12');
    unmount();
    const { container: expanded } = renderNav({ collapsed: false });
    expect(expanded.querySelector('nav')?.className).toContain('w-45');
  });
});

describe('NavBarView collapse toggle', () => {
  it('reports the new collapsed state to the persistence layer', async () => {
    const onCollapsedChange = vi.fn();
    const { user } = renderNav({ onCollapsedChange });
    const nav = screen.getByLabelText('Main navigation');
    await user.click(within(nav).getByRole('button', { name: 'Collapse' }));
    expect(onCollapsedChange).toHaveBeenCalledWith(true);
  });
});
