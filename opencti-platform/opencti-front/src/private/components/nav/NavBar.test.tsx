import { screen, within } from '@testing-library/react';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import testRender from '../../../utils/tests/test-render';
import MadeByFiligran from './MadeByFiligran';
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
    topOffset="0px"
    bottomOffset="0px"
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
    // Recorded, not asserted as desirable: the library renders a bare anchor here, not a router
    // Link, so this one navigation is a full page reload where the previous rail did a client-
    // side navigate().
  });

  it('renders a parent whose submenu was emptied by permissions as a plain link', () => {
    // Iso-functionality: `LeftBarItem`'s "No Subitems" branch rendered such a parent as a
    // navigable row.
    const gutted: NavGroup[] = [{
      id: 'data',
      items: [{
        id: 'data', label: 'Data', icon: null, link: '/dashboard/data', subItems: [],
      }],
    }];
    renderNav({ groups: gutted });
    expect(screen.getByRole('link', { name: 'Data' })).toHaveAttribute('href', '/dashboard/data');
    expect(screen.queryByRole('button', { name: /Data/ })).not.toBeInTheDocument();
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

  it('pins the rail to the viewport, full height, below the banners', () => {
    // The library lays its <nav> out in flow and sizes it with a percentage height; the fixed-
    // position drawer it replaces was full height and did not scroll away with the page.
    const { container } = renderNav({ topOffset: '50px', bottomOffset: '20px' });
    const nav = container.querySelector('nav') as HTMLElement;
    expect(nav.style.position).toBe('sticky');
    expect(nav.style.top).toBe('50px');
    // jsdom reorders the terms of a calc(), so assert on its parts: the rail
    // is one viewport tall minus the space the banners take.
    expect(nav.style.height).toContain('100dvh');
    expect(nav.style.height).toContain('50px');
    expect(nav.style.height).toContain('20px');
    expect(nav.style.alignSelf).toBe('flex-start');
  });

  it('does not drive the hover flyout from the persisted submenu state', () => {
    // Collapsed, `open`/`onOpenChange` drive the hover flyout, not an accordion.
    const onSubmenuOpenChange = vi.fn();
    renderNav({ collapsed: true, openSubmenus: ['threats'], onSubmenuOpenChange });
    expect(screen.queryByRole('link', { name: 'Campaigns' })).not.toBeInTheDocument();
    expect(onSubmenuOpenChange).not.toHaveBeenCalled();
  });
});

describe('MadeByFiligran', () => {
  it('keeps one accessible name in both rail states', () => {
    const { unmount } = testRender(<MadeByFiligran collapsed={false} />, { route: '/dashboard' });
    expect(screen.getByAltText('Filigran')).toBeInTheDocument();
    expect(screen.getByText('Made by')).toBeInTheDocument();
    unmount();
    testRender(<MadeByFiligran collapsed />, { route: '/dashboard' });
    expect(screen.getByAltText('Filigran')).toBeInTheDocument();
    // Collapsed, the label goes: the rail is 48px wide and the emblem alone
    // stands for the signature, as in the OpenAEV pilot.
    expect(screen.queryByText('Made by')).not.toBeInTheDocument();
  });

  it('shows the emblem alone when collapsed, by cropping the wordmark', () => {
    testRender(<MadeByFiligran collapsed />, { route: '/dashboard' });
    const logo = screen.getByAltText('Filigran');
    // A square box cropped from the left edge of the wordmark asset: the emblem survives, the
    // lettering is cut.
    expect(logo.style.width).toBe('12px');
    expect(logo.style.height).toBe('12px');
    expect(logo.style.objectFit).toBe('cover');
    expect(logo.style.objectPosition).toBe('left center');
  });
});

describe('NavBarView accent compensation', () => {
  it('overrides every brand token the selected row is painted from', () => {
    const { container } = renderNav({ accentColor: '#ff9800' });
    const nav = container.querySelector('nav');
    expect(nav?.style.getPropertyValue('--color-filigran-brand-primary')).toBe('#ff9800');
    // The tint is a derived token declared on `:root`; overriding only the
    // base token left the row tinted Filigran blue under a custom theme.
    expect(nav?.style.getPropertyValue('--color-filigran-brand-primary-transparency-10'))
      .toBe('color-mix(in srgb, #ff9800 10%, transparent)');
  });

  it('leaves the token alone when no accent is supplied', () => {
    const { container } = renderNav();
    expect(container.querySelector('nav')?.style.getPropertyValue('--color-filigran-brand-primary')).toBe('');
  });

  /**
   * NON-REGRESSION GUARD. The compensation above works only because the library still paints
   * the selected row from these exact custom properties.
   */
  const NOT_ACCENT_DERIVED: Record<string, string> = {
    // lib pin a22b188 (#123): a selected row's GLYPH takes the ordinary primary text tone, not
    // the accent — `group-[[aria-current=page]]:text-default-primary` on NavbarItem's icon
    // span.
    '--text-default-primary': 'selected-row glyph colour, neutral by design',
  };

  it('overrides every custom property the installed library resolves for the selected row', () => {
    const require = createRequire(import.meta.url);
    const cssPath = require.resolve('@filigran/design-system/dist/index.css');
    const css = readFileSync(cssPath, 'utf8');
    const currentPageRules = css
      .split('}')
      .filter((rule) => rule.includes('aria-current=page') || rule.includes('aria-current="page"'));
    expect(currentPageRules.length).toBeGreaterThan(0);

    const referenced = new Set<string>();
    currentPageRules.forEach((rule) => {
      [...rule.matchAll(/var\((--[a-z0-9-]+)\)/g)].forEach((match) => referenced.add(match[1]));
    });
    expect(referenced.size).toBeGreaterThan(0);

    const { container } = renderNav({ accentColor: '#ff9800' });
    const nav = container.querySelector('nav');
    referenced.forEach((property) => {
      const exempt = NOT_ACCENT_DERIVED[property];
      if (exempt) {
        // Still assert the opposite direction, so the exemption cannot rot into
        // a blanket ignore: an exempt property must NOT be overridden either.
        expect(
          nav?.style.getPropertyValue(property),
          `${property} is exempt (${exempt}) and must be left alone by the rail`,
        ).toBe('');
        return;
      }
      expect(
        nav?.style.getPropertyValue(property),
        `the rail must override ${property}, which the library resolves for aria-current rows`,
      ).not.toBe('');
    });
  });

  /**
   * The tint set itself, in both directions.
   */
  it('re-derives exactly the brand tints the installed library consumes', () => {
    const require = createRequire(import.meta.url);
    const css = readFileSync(require.resolve('@filigran/design-system/dist/index.css'), 'utf8');
    const tint = /--color-filigran-brand-primary-transparency-\d+/g;
    const consumed = new Set(
      [...css.matchAll(new RegExp(`var\\((${tint.source})\\)`, 'g'))].map((m) => m[1]),
    );
    // A stylesheet that resolves no tint at all would make the comparison
    // below pass against an empty rail.
    expect(consumed.size).toBeGreaterThan(0);

    const { container } = renderNav({ accentColor: '#ff9800' });
    const nav = container.querySelector('nav');
    const reDerived = new Set(
      [...(nav?.getAttribute('style') ?? '').matchAll(tint)].map((m) => m[0]),
    );
    expect([...reDerived].sort()).toEqual([...consumed].sort());
  });
});

describe('NavBarView rail width', () => {
  it('collapses to the width the floating toolbars offset themselves by', () => {
    // The library sizes the rail with a utility class, not an inline width, so this asserts the
    // class the constants were derived from.
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
